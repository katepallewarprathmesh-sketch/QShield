"""Emit a :class:`CircuitIR` back to OpenQASM 2.0 source.

Scope and honesty notes:

* Only the **unitary, gate-level** content is emitted. Ancilla metadata does
  not survive: circuits with ``reset`` or classical-feedback ``if`` operations
  are refused loudly (:class:`QASMEmitError`) — emitting them would silently
  change semantics.
* ``barrier`` statements are counted by the parser but carry no unitary
  semantics and their positions are not retained, so they are not emitted
  (this is deliberate; scheduling hints are lost).
* Custom OpenQASM 2.0 ``gate`` definitions are expanded inline by the parser
  and are emitted as their flattened call sequence — semantics are preserved,
  the original definition text is not.
* Gate names are emitted verbatim. Builtin (gate-database) names are valid
  OpenQASM identifiers. Names created by modifiers such as ``ctrl @ rz`` are
  emitted as flat identifiers (e.g. ``ctrl_rz``) which re-parse as opaque
  custom gates: the *structure* round-trips, the unitary annotation does not.
* Parameters are emitted via ``repr(float)`` which round-trips exactly through
  Python's ``ast.parse`` (both directions use the same parser family).
  Non-finite parameters are refused.
* This is an *interchange* emitter, not a proof of OpenQASM 2.0 validity for
  foreign tools. ``qelib1.inc`` gate names are emitted by canonical name;
  unknown/custom gate names are emitted verbatim and will only be understood
  by readers that know them.
"""

from __future__ import annotations

import math
import re

from qshield.core.circuit_ir import CircuitIR

_IDENT_RE = re.compile(r"[A-Za-z_]\w*")


class QASMEmitError(ValueError):
    """Raised when a circuit cannot be emitted as OpenQASM 2.0."""


def _fmt_param(value: float) -> str:
    if not math.isfinite(value):
        raise QASMEmitError(f"Non-finite parameter {value!r} cannot be emitted")
    return repr(float(value))


def emit_qasm(ir: CircuitIR, name: str | None = None) -> str:
    """Serialize ``ir`` to OpenQASM 2.0 source text.

    Raises :class:`QASMEmitError` for un-emittable content (never silently
    drops semantics).
    """
    metadata = ir.metadata or {}
    if metadata.get("resets"):
        raise QASMEmitError(
            f"Circuit contains {metadata['resets']} reset(s) — not unitary, cannot emit OpenQASM 2.0"
        )
    if metadata.get("conditional_ops"):
        raise QASMEmitError(
            f"Circuit contains {metadata['conditional_ops']} classical-feedback (if) operation(s) — "
            "cannot emit as pure OpenQASM 2.0"
        )

    lines = ["OPENQASM 2.0;", 'include "qelib1.inc";', f"qreg q[{ir.num_qubits}];"]
    if ir.num_classical_bits:
        lines.append(f"creg c[{ir.num_classical_bits}];")

    for gate in ir.gates:
        if not _IDENT_RE.fullmatch(gate.gate_name):
            raise QASMEmitError(f"Gate name {gate.gate_name!r} is not a valid OpenQASM identifier")
        params = ", ".join(_fmt_param(p) for p in gate.parameters)
        pstr = f"({params})" if params else ""
        for qubit in gate.qubits:
            if not 0 <= qubit < ir.num_qubits:
                raise QASMEmitError(f"Gate {gate.gate_id} references qubit {qubit} out of range")
        qubits = ", ".join(f"q[{q}]" for q in gate.qubits)
        lines.append(f"{gate.gate_name}{pstr} {qubits};")

    for src, dst in ir.measurements:
        if not 0 <= src < ir.num_qubits:
            raise QASMEmitError(f"Measurement source qubit {src} out of range")
        if ir.num_classical_bits and not 0 <= dst < ir.num_classical_bits:
            raise QASMEmitError(f"Measurement destination bit {dst} out of range")
        lines.append(f"measure q[{src}] -> c[{dst}];")

    return "\n".join(lines) + "\n"
