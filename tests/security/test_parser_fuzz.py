"""Parser fuzz targets — property-based (implementation plan Task 1.4).

Requires ``hypothesis`` (dev extra, installed in CI). Covers:

* arbitrary text and QASM-flavoured token soup never raise anything but
  :class:`QASMParseError`;
* grammar-generated circuits parse and satisfy CircuitIR invariants;
* parsing is deterministic; the expression evaluator never crashes;
* circuits serialized by Qiskit never crash the parser (optional qiskit leg).

Resource-bomb regressions that must always run live in
``test_parser_robustness.py``.
"""

import math
import random

import pytest

from qshield.core.circuit_ir import CircuitIR
from qshield.core.parsers.expressions import ExpressionError, evaluate_expression
from qshield.core.parsers.qasm_parser import MAX_GATES, QASMParseError, parse_qasm

hypothesis = pytest.importorskip("hypothesis", reason="hypothesis (dev extra) not installed")
from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402


@given(st.text(max_size=2048))
@settings(max_examples=100, deadline=5000)
def test_arbitrary_text_never_raises_unexpected(source: str):
    try:
        result = parse_qasm(source)
    except QASMParseError:
        return
    assert isinstance(result, CircuitIR)


_QASM_TOKENS = [
    "OPENQASM 2.0;",
    "OPENQASM 3.0;",
    "include \"qelib1.inc\";",
    "qreg q[2];",
    "qreg big[64];",
    "creg c[2];",
    "h q[0];",
    "x q[0];",
    "rz(0.5) q[0];",
    "rz(pi) q[1];",
    "rx(-0.25) q[0];",
    "cx q[0], q[1];",
    "cz q[0], q[1];",
    "ccx q[0], q[1], q[0];",
    "measure q[0] -> c[0];",
    "measure q -> c;",
    "reset q[0];",
    "barrier q;",
    "gate mygate(p0) a { rz(p0) a; }",
    "mygate(0.5) q[0];",
    "inv @ rz(0.5) q[0];",
    "ctrl @ x q[0], q[1];",
    "if (c == 1) x q[0];",
    "qubit[2] q;",
    "bit[2] c;",
    "$0 = measure q[0];",
    "opaque foo q[0];",
    "// comment\n",
    "/* block\ncomment */",
    "garbage token soup",
    "2**10**10",
    "gate recursive(q) { recursive q; }",
]


@given(st.lists(st.sampled_from(_QASM_TOKENS), max_size=40))
@settings(max_examples=150, deadline=5000)
def test_qasm_token_soup_never_raises_unexpected(tokens: list[str]):
    source = "\n".join(tokens)
    try:
        result = parse_qasm(source)
    except QASMParseError:
        return
    assert isinstance(result, CircuitIR)


_GATES_1Q = ["h", "x", "y", "z", "s", "t", "sdg", "tdg"]
_PARAM_GATES = ["rx", "ry", "rz"]
_GATES_2Q = ["cx", "cz"]


def _random_circuit_source(rng: random.Random, num_qubits: int, num_gates: int) -> str:
    lines = ["OPENQASM 2.0;", f"qreg q[{num_qubits}];"]
    if rng.random() < 0.7:
        lines.append(f"creg c[{num_qubits}];")
    for _ in range(num_gates):
        choice = rng.random()
        if choice < 0.35:
            g = rng.choice(_GATES_1Q)
            lines.append(f"{g} q[{rng.randrange(num_qubits)}];")
        elif choice < 0.60:
            g = rng.choice(_PARAM_GATES)
            lines.append(f"{g}({rng.uniform(-math.pi, math.pi):.6f}) q[{rng.randrange(num_qubits)}];")
        elif choice < 0.85 and num_qubits >= 2:
            g = rng.choice(_GATES_2Q)
            a, b = rng.sample(range(num_qubits), 2)
            lines.append(f"{g} q[{a}], q[{b}];")
        elif num_qubits >= 2:
            a, b = rng.sample(range(num_qubits), 2)
            lines.append(f"cx q[{a}], q[{b}];")
        else:
            lines.append("h q[0];")
    if rng.random() < 0.6 and f"creg c[{num_qubits}];" in lines:
        lines.append("measure q[0] -> c[0];")
    return "\n".join(lines) + "\n"


@given(st.randoms(use_true_random=False))
@settings(max_examples=60, deadline=10000)
def test_grammar_generated_circuits_parse_and_satisfy_invariants(rng: random.Random):
    num_qubits = rng.randint(1, 4)
    source = _random_circuit_source(rng, num_qubits, rng.randint(1, 30))
    ir = parse_qasm(source)  # grammar avoids unsupported constructs: must parse
    assert ir.num_qubits == num_qubits
    assert len(ir.gates) <= MAX_GATES
    for gate in ir.gates:
        assert all(0 <= q < num_qubits for q in gate.qubits)
    gate_ids = {g.gate_id for g in ir.gates}
    assert set(ir.dag) <= gate_ids
    for preds, succs in ir.dag.items():
        assert preds in gate_ids
        assert set(succs) <= gate_ids
    for src, dst in ir.measurements:
        assert 0 <= src < num_qubits
        assert 0 <= dst < num_qubits
    assert len(ir.source_hash) == 64


@given(st.randoms(use_true_random=False))
@settings(max_examples=20, deadline=10000)
def test_parse_is_deterministic(rng: random.Random):
    source = _random_circuit_source(rng, rng.randint(1, 3), rng.randint(1, 20))
    a = parse_qasm(source)
    b = parse_qasm(source)
    sig_a = [(g.gate_name, tuple(g.qubits), tuple(g.parameters)) for g in a.gates]
    sig_b = [(g.gate_name, tuple(g.qubits), tuple(g.parameters)) for g in b.gates]
    assert sig_a == sig_b
    assert a.num_qubits == b.num_qubits
    assert a.source_hash == b.source_hash


_EXPR_TOKENS = ["1", "2", "0", "3.5", "pi", "tau", "e", "+", "-", "*", "/", "%", "**", "(", ")", "sqrt(", ")", "sin(", "cos(", "abs("]


@given(st.lists(st.sampled_from(_EXPR_TOKENS), max_size=30))
@settings(max_examples=150, deadline=5000)
def test_expression_fuzz_never_crashes(tokens: list[str]):
    expr = "".join(tokens)
    try:
        value = evaluate_expression(expr)
    except ExpressionError:
        return
    assert math.isfinite(value)


@given(st.integers(min_value=1, max_value=3), st.integers(min_value=1, max_value=15), st.integers(min_value=0, max_value=10**9))
@settings(max_examples=15, deadline=30000)
def test_qiskit_serialized_circuits_never_crash(num_qubits: int, depth: int, seed: int):
    pytest.importorskip("qiskit", reason="qiskit ([qiskit] extra) not installed")
    from qiskit.circuit.random import random_circuit

    from qshield.core.parsers import parse_any

    circuit = random_circuit(num_qubits=num_qubits, depth=depth, seed=seed)
    try:
        from qiskit import qasm2
        source = qasm2.dumps(circuit)
    except Exception:
        return  # serialization path unavailable — nothing to fuzz
    try:
        ir = parse_any(source)
    except QASMParseError:
        return  # documented: unsupported constructs fail loudly
    assert isinstance(ir, CircuitIR)
