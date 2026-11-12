"""OpenQASM (2.0 / common 3.0 subset) parser producing :class:`CircuitIR`.

Supported:

* ``OPENQASM 2.0;`` / ``OPENQASM 3;`` version lines
* ``include`` statements (recorded, contents not inlined)
* ``qreg`` / ``creg`` declarations
* gate definitions ``gate name(params) qubits { ... }`` (recursively expanded)
* gate applications with numeric parameter expressions
* ``measure q[i] -> c[j];`` and whole-register ``measure q -> c;``
* ``barrier`` (recorded, not modelled as unitary)
* ``reset`` (recorded; circuit is flagged non-unitary)
* conditional gates ``if (creg == n) ...`` are parsed, flagged in metadata and
  excluded from the unitary (they are classical feedback, not unitaries)

The parser annotates every gate with its unitary matrix when the gate is
known to the built-in gate database.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass, field

from qshield.core.circuit_ir import CircuitIR, GateNode, GateType
from qshield.core.gate_database import GATE_DB
from qshield.core.parsers.expressions import ExpressionError, evaluate_expression

_COMMENT_RE = re.compile(r"//[^\n]*")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_GATE_DEF_RE = re.compile(
    r"\bgate\s+(?P<name>[A-Za-z_][\w]*)\s*"
    r"(?:\((?P<params>[^()]*)\))?\s*"
    r"(?P<qubits>[A-Za-z_][\w\[\]\s,]*)\s*\{",
    re.MULTILINE,
)


class QASMParseError(ValueError):
    """Raised when an OpenQASM source cannot be parsed."""


@dataclass
class _GateDefinition:
    name: str
    params: list[str]
    qubits: list[str]
    body: str  # raw statement block, without the outer braces


@dataclass
class _Register:
    name: str
    size: int
    offset: int


@dataclass
class _ParserState:
    qregs: dict[str, _Register] = field(default_factory=dict)
    cregs: dict[str, _Register] = field(default_factory=dict)
    definitions: dict[str, _GateDefinition] = field(default_factory=dict)


# ----------------------------------------------------------------------
# Low-level helpers
# ----------------------------------------------------------------------

def _strip_comments(source: str) -> str:
    source = _BLOCK_COMMENT_RE.sub(lambda m: "\n" * m.group(0).count("\n"), source)
    return _COMMENT_RE.sub("", source)


def _line_of(source: str, index: int) -> int:
    return source.count("\n", 0, index) + 1


def _remove_gate_blocks(source: str) -> tuple[str, list[tuple[_GateDefinition, int]]]:
    """Extract ``gate ... { ... }`` blocks by brace matching."""
    definitions: list[tuple[_GateDefinition, int]] = []
    spans: list[tuple[int, int]] = []
    for match in _GATE_DEF_RE.finditer(source):
        brace_start = source.index("{", match.start(), match.end())
        depth = 0
        end = None
        for i in range(brace_start, len(source)):
            ch = source[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i
                    break
        if end is None:
            raise QASMParseError(f"Unterminated gate definition starting at line {_line_of(source, match.start())}")
        params_raw = (match.group("params") or "").strip()
        params = [p.strip() for p in params_raw.split(",") if p.strip()]
        qubits = [q.strip() for q in match.group("qubits").split(",") if q.strip()]
        if not qubits:
            raise QASMParseError(f"Gate {match.group('name')!r} declares no qubit arguments")
        for q in qubits:
            if not re.fullmatch(r"[A-Za-z_]\w*", q):
                raise QASMParseError(f"Invalid formal qubit argument {q!r} in gate {match.group('name')!r}")
        body = source[brace_start + 1 : end]
        definitions.append((_GateDefinition(match.group("name"), params, qubits, body), match.start()))
        spans.append((match.start(), end + 1))
    if not spans:
        return source, definitions
    cleaned = []
    cursor = 0
    for start, end in spans:
        cleaned.append(source[cursor:start])
        cleaned.append("\n" * source.count("\n", start, end))  # preserve line numbers
        cursor = end
    cleaned.append(source[cursor:])
    return "".join(cleaned), definitions


_QREG_RE = re.compile(r"^(?P<kind>qreg|creg)\s+(?P<name>[A-Za-z_]\w*)\s*\[\s*(?P<size>\d+)\s*\]$")


def _split_args(arg_string: str) -> list[str]:
    """Split a comma-separated argument list at top level (paren-aware)."""
    args: list[str] = []
    depth = 0
    current: list[str] = []
    for ch in arg_string:
        if ch == "(":
            depth += 1
            current.append(ch)
        elif ch == ")":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        args.append("".join(current).strip())
    return [a for a in args if a]


_QUBIT_REF_RE = re.compile(r"^(?P<reg>[A-Za-z_]\w*)(?:\s*\[\s*(?P<idx>\d+)\s*\])?$")


def _resolve_qubit_ref(ref: str, state: _ParserState, env: dict[str, int]) -> list[int]:
    ref = ref.strip()
    m = _QUBIT_REF_RE.match(ref)
    if not m:
        raise QASMParseError(f"Invalid qubit reference: {ref!r}")
    reg_name = m.group("reg")
    idx = m.group("idx")
    if reg_name in state.qregs:
        reg = state.qregs[reg_name]
        if idx is None:
            return list(range(reg.offset, reg.offset + reg.size))
        i = int(idx)
        if i >= reg.size:
            raise QASMParseError(f"Qubit index {reg_name}[{i}] out of bounds (size {reg.size})")
        return [reg.offset + i]
    if reg_name in env:  # formal parameter inside a gate body
        if idx is not None:
            raise QASMParseError(f"Formal qubit {reg_name!r} cannot be indexed")
        return [env[reg_name]]
    raise QASMParseError(f"Unknown register or formal argument: {reg_name!r}")


_GATE_CALL_RE = re.compile(
    r"^(?P<name>[A-Za-z_]\w*)\s*(?:\((?P<params>.*)\))?\s+(?P<args>.*)$",
    re.DOTALL,
)


def _parse_gate_call(stmt: str):
    m = _GATE_CALL_RE.match(stmt.strip())
    if not m:
        return None
    name = m.group("name")
    reserved = {"qreg", "creg", "measure", "barrier", "OPENQASM", "include", "gate", "if", "reset", "opaque", "let", "int", "float"}
    if name in reserved or name.upper() == "OPENQASM":
        return None
    params_raw = m.group("params")
    params = _split_args(params_raw) if params_raw is not None else []
    args = _split_args(m.group("args"))
    if not args:
        raise QASMParseError(f"Gate call {stmt!r} has no arguments")
    return name, params, args


# ----------------------------------------------------------------------
# Main parser
# ----------------------------------------------------------------------

def parse_qasm(source: str, name: str = "circuit") -> CircuitIR:
    """Parse an OpenQASM source string into a :class:`CircuitIR`."""
    source_hash = hashlib.sha256(source.encode("utf-8")).hexdigest()
    try:
        cleaned = _strip_comments(source)
        cleaned, defs = _remove_gate_blocks(cleaned)
    except QASMParseError as exc:
        raise QASMParseError(str(exc)) from exc

    state = _ParserState()
    for definition, _pos in defs:
        state.definitions[definition.name] = definition

    gates: list[GateNode] = []
    measurements: list[tuple[int, int]] = []
    metadata: dict = {"includes": [], "barriers": 0, "resets": 0, "conditional_ops": 0, "warnings": []}
    gate_counter = 0
    q_offset = 0
    c_offset = 0
    version = "2.0"

    def new_gate_id() -> str:
        nonlocal gate_counter
        gate_counter += 1
        return f"g{gate_counter:05d}"

    def add_gate(gate_name: str, params: list[float], qubits: list[int], index: int):
        nonlocal gate_counter
        canonical = GATE_DB.canon(gate_name)
        spec = GATE_DB.get_spec(canonical)
        unitary = GATE_DB.matrix(canonical, params)
        if spec is not None:
            gtype = GateType.PARAMETERIZED if spec.is_parameterized else GateType.STANDARD
        else:
            gtype = GateType.CUSTOM
        node = GateNode(
            gate_id=new_gate_id(),
            gate_name=canonical,
            gate_type=gtype,
            qubits=list(qubits),
            parameters=list(params),
            unitary=unitary,
            source_location=f"{name}:{index}",
        )
        gates.append(node)

    statements = list(_iter_statements(cleaned))
    for stmt_text, stmt_index in statements:
        stmt = stmt_text.strip()
        if not stmt:
            continue
        lineno = _line_of(cleaned, stmt_index)

        m = re.match(r"^OPENQASM\s+([\d.]+)", stmt, re.IGNORECASE)
        if m:
            version = m.group(1)
            continue
        m = re.match(r"^include\s+\"([^\"]+)\"", stmt)
        if m:
            metadata["includes"].append(m.group(1))
            continue

        m = _QREG_RE.match(stmt)
        if m:
            reg = _Register(m.group("name"), int(m.group("size")), 0)
            if m.group("kind") == "qreg":
                if reg.name in state.qregs:
                    raise QASMParseError(f"Duplicate qreg {reg.name!r}")
                reg.offset = sum(r.size for r in state.qregs.values())
                state.qregs[reg.name] = reg
                q_offset += reg.size
            else:
                if reg.name in state.cregs:
                    raise QASMParseError(f"Duplicate creg {reg.name!r}")
                reg.offset = sum(r.size for r in state.cregs.values())
                state.cregs[reg.name] = reg
                c_offset += reg.size
            continue

        upper = stmt.upper()
        if upper.startswith("BARRIER"):
            metadata["barriers"] += 1
            continue
        if upper.startswith("RESET"):
            metadata["resets"] += 1
            metadata["warnings"].append("reset encountered: circuit is not unitary")
            continue
        if upper.startswith("IF") or re.match(r"^if\s*\(", stmt):
            metadata["conditional_ops"] += 1
            metadata["warnings"].append(
                "conditional operation encountered: excluded from unitary computation"
            )
            continue

        m = re.match(r"^measure\s+(.+)$", stmt, re.IGNORECASE | re.DOTALL)
        if m:
            body = m.group(1)
            if "->" not in body:
                raise QASMParseError(f"Malformed measure statement: {stmt!r}")
            src, dst = body.split("->", 1)
            src_refs = [s.strip() for s in _split_args(src)]
            dst_refs = [d.strip() for d in _split_args(dst)]
            src_qubits = _flatten_refs(src_refs, state, env={})
            dst_bits = _flatten_creg_refs(dst_refs, state)
            if len(src_qubits) != len(dst_bits):
                raise QASMParseError(
                    f"measure size mismatch: {len(src_qubits)} qubits vs {len(dst_bits)} bits"
                )
            measurements.extend(zip(src_qubits, dst_bits, strict=True))
            continue

        parsed = _parse_gate_call(stmt)
        if parsed is None:
            metadata["warnings"].append(f"Unrecognised statement skipped: {stmt[:80]!r}")
            continue
        name_tok, param_exprs, args = parsed
        _expand_call(
            name_tok, param_exprs, args,
            env={}, qubit_env={}, state=state,
            emit=lambda gname, ps, qs, _ln=lineno: add_gate(gname, ps, qs, _ln),
            depth=0,
        )

    num_qubits = q_offset
    dag: dict[str, list[str]] = {}
    last_on_qubit: dict[int, str] = {}
    for g in gates:
        preds = {last_on_qubit[q] for q in g.qubits if q in last_on_qubit}
        for p in preds:
            dag.setdefault(p, []).append(g.gate_id)
        for q in g.qubits:
            last_on_qubit[q] = g.gate_id

    return CircuitIR(
        circuit_id=f"circ-{uuid.uuid4().hex[:12]}",
        name=name,
        num_qubits=num_qubits,
        num_classical_bits=c_offset,
        gates=gates,
        dag=dag,
        measurements=measurements,
        source_framework=f"qasm{version}",
        source_hash=source_hash,
        metadata=metadata,
    )


def _iter_statements(cleaned: str):
    """Yield (statement_text, char_offset) pairs split on top-level ';'."""
    depth = 0
    start = 0
    for i, ch in enumerate(cleaned):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif ch == ";" and depth == 0:
            yield cleaned[start:i], start
            start = i + 1
    tail = cleaned[start:]
    if tail.strip():
        yield tail, start


def _flatten_refs(refs: list[str], state: _ParserState, env: dict[str, int]) -> list[int]:
    out: list[int] = []
    for ref in refs:
        out.extend(_resolve_qubit_ref(ref, state, env))
    return out


def _flatten_creg_refs(refs: list[str], state: _ParserState) -> list[int]:
    out: list[int] = []
    for ref in refs:
        m = _QUBIT_REF_RE.match(ref.strip())
        if not m:
            raise QASMParseError(f"Invalid classical register reference: {ref!r}")
        reg_name = m.group("reg")
        reg = state.cregs.get(reg_name)
        if reg is None:
            raise QASMParseError(f"Unknown classical register: {reg_name!r}")
        idx = m.group("idx")
        if idx is None:
            out.extend(range(reg.offset, reg.offset + reg.size))
        else:
            i = int(idx)
            if i >= reg.size:
                raise QASMParseError(f"Classical bit {reg_name}[{i}] out of bounds")
            out.append(reg.offset + i)
    return out


def _expand_call(
    name: str,
    param_exprs: list[str],
    args: list[str],
    env: dict[str, float],
    qubit_env: dict[str, int],
    state: _ParserState,
    emit,
    depth: int,
    max_depth: int = 16,
):
    """Resolve a gate call and emit unitary nodes (recursively for custom gates)."""
    if depth > max_depth:
        raise QASMParseError(f"Gate expansion too deep for {name!r} (recursive definition?)")

    try:
        params = [evaluate_expression(p, env) for p in param_exprs]
    except ExpressionError as exc:
        raise QASMParseError(f"In call to {name!r}: {exc}") from exc

    canonical = GATE_DB.canon(name)
    spec = GATE_DB.get_spec(canonical)
    definition = state.definitions.get(name)

    # Resolve every argument to a list of qubit indices.
    arg_lists = [_resolve_qubit_ref(a, state, qubit_env) for a in args]

    # Whole-register semantics:
    #  * single whole-register arg + arity-1 gate  -> one gate per qubit
    #  * all args are equally sized whole registers and count == arity
    #    -> dot-product broadcast, one gate per slice
    if (
        len(arg_lists) == 1
        and len(arg_lists[0]) > 1
        and spec is not None
        and spec.arity == 1
    ):
        for q in arg_lists[0]:
            emit(name, params, [q])
        return
    if (
        len(arg_lists) > 1
        and all(len(lst) == len(arg_lists[0]) for lst in arg_lists)
        and all(len(lst) > 1 for lst in arg_lists)
        and spec is not None
        and len(arg_lists) == spec.arity
    ):
        for i in range(len(arg_lists[0])):
            emit(name, params, [lst[i] for lst in arg_lists])
        return

    expanded_qubits = [q for lst in arg_lists for q in lst]

    if spec is not None:
        if len(expanded_qubits) != spec.arity:
            raise QASMParseError(
                f"Gate {name!r} expects {spec.arity} qubit(s), got {len(expanded_qubits)}"
            )
        if spec.num_params >= 0 and len(params) != spec.num_params:
            raise QASMParseError(
                f"Gate {name!r} expects {spec.num_params} parameter(s), got {len(params)}"
            )
        emit(name, params, expanded_qubits)
        return

    if definition is not None:
        if len(params) != len(definition.params):
            raise QASMParseError(
                f"Custom gate {name!r} expects {len(definition.params)} parameter(s), got {len(params)}"
            )
        if len(expanded_qubits) != len(definition.qubits):
            raise QASMParseError(
                f"Custom gate {name!r} expects {len(definition.qubits)} qubit(s), got {len(expanded_qubits)}"
            )
        child_env = dict(zip(definition.params, params, strict=True))
        child_qubit_env = dict(zip(definition.qubits, expanded_qubits, strict=True))
        for stmt_text, _stmt_index in _iter_statements(_strip_comments(definition.body)):
            stmt = stmt_text.strip()
            if not stmt:
                continue
            parsed = _parse_gate_call(stmt)
            if parsed is None:
                raise QASMParseError(
                    f"Unsupported statement in gate {name!r} body: {stmt[:80]!r}"
                )
            child_name, child_params, child_args = parsed
            _expand_call(
                child_name, child_params, child_args,
                env=child_env, qubit_env=child_qubit_env, state=state,
                emit=emit, depth=depth + 1, max_depth=max_depth,
            )
        return

    # Unknown gate: keep it (custom/foreign) but with no unitary.
    emit(name, params, expanded_qubits)
