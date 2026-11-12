"""Phase-1 acceptance: parser and structural analyzer scale to 100 qubits.

Spec: "Parse Qiskit circuits up to 100 qubits; structural analysis <10% FP,
>80% detection; end-to-end `qshield scan circuit.qasm`."
"""

import time

import pytest

from qshield import Scanner
from qshield.core.parsers.qasm_parser import parse_qasm


def _chain_qasm(n: int, body_gates: list[str] | None = None) -> str:
    lines = ["OPENQASM 2.0;", f"qreg q[{n}];"]
    lines.append("".join(f"h q[{i}];\n" for i in range(n)))
    lines.append("".join(f"cx q[{i}], q[{i + 1}];\n" for i in range(0, n - 1, 2)))
    if body_gates:
        lines.extend(body_gates)
    return "\n".join(lines)


def test_parse_100_qubit_qasm():
    ir = parse_qasm(_chain_qasm(100))
    assert ir.num_qubits == 100
    assert len(ir.gates) == 100 + 50
    assert ir.get_depth() <= 5


def test_scan_100_qubit_qasm_fast_and_quiet(tmp_path):
    qasm = _chain_qasm(100) + "measure q -> c;\n"
    qasm = qasm.replace("qreg q[100];", "qreg q[100];\ncreg c[100];")
    circuit = tmp_path / "wide.qasm"
    circuit.write_text(qasm)
    start = time.time()
    scanner = Scanner(config="strict")
    scanner.add_circuit(str(circuit))
    results = scanner.run()
    elapsed = time.time() - start
    assert elapsed < 30, f"scan too slow: {elapsed:.1f}s"
    high = [f for f in results.findings if f.severity_rank >= 3]
    assert not high, [f.title for f in high]


def test_100_qubit_qiskit_object_parse(tmp_path):
    qiskit = pytest.importorskip("qiskit")
    qc = qiskit.QuantumCircuit(100)
    for i in range(100):
        qc.h(i)
    for i in range(0, 99, 2):
        qc.cx(i, i + 1)
    scanner = Scanner()
    scanner.add_circuit(qc, name="wide_100")
    results = scanner.run()
    assert results.circuits[0].num_qubits == 100


def test_unitary_path_refuses_100_qubits(tmp_path):
    """Exact dense unitary must NOT be attempted at 100 qubits."""
    from qshield.core.circuit_ir import MAX_EXACT_QUBITS

    ir = parse_qasm(_chain_qasm(20))
    assert ir.num_qubits > MAX_EXACT_QUBITS
    assert ir.to_unitary() is None
