"""Cross-framework parsing consistency: all frameworks must agree on unitaries."""

import numpy as np
import pytest

from qshield.core.parsers import parse_any, parse_qasm

qiskit = pytest.importorskip("qiskit")
cirq = pytest.importorskip("cirq")
pennylane = pytest.importorskip("pennylane")

QASM_BELL_RZ = """OPENQASM 2.0;
qreg q[2];
h q[0];
cx q[0], q[1];
rz(0.5) q[0];
"""


def _qiskit_circuit():
    qc = qiskit.QuantumCircuit(2)
    qc.h(0)
    qc.cx(0, 1)
    qc.rz(0.5, 0)
    return qc


def _cirq_circuit():
    q0, q1 = cirq.LineQubit.range(2)
    return cirq.Circuit(cirq.H(q0), cirq.CNOT(q0, q1), cirq.rz(0.5)(q0))


def _pennylane_tape():
    return pennylane.tape.QuantumScript([
        pennylane.Hadamard(wires=0),
        pennylane.CNOT(wires=[0, 1]),
        pennylane.RZ(0.5, wires=0),
    ])


def test_all_frameworks_produce_same_unitary():
    u_qasm = parse_qasm(QASM_BELL_RZ).to_unitary()
    u_qiskit = parse_any(_qiskit_circuit()).to_unitary()
    u_cirq = parse_any(_cirq_circuit()).to_unitary()
    u_pennylane = parse_any(_pennylane_tape()).to_unitary()
    assert u_qasm is not None and u_qiskit is not None
    assert u_cirq is not None and u_pennylane is not None
    assert np.allclose(u_qasm, u_qiskit, atol=1e-9)
    assert np.allclose(u_qasm, u_cirq, atol=1e-9)
    assert np.allclose(u_qasm, u_pennylane, atol=1e-9)


def test_framework_gate_names_canonical():
    for maker in (_qiskit_circuit,):
        ir = parse_any(maker())
        assert [g.gate_name for g in ir.gates] == ["h", "cx", "rz"]


def test_qiskit_scan_clean():
    import qshield
    scanner = qshield.Scanner(config="default")
    scanner.add_circuit(_qiskit_circuit(), name="bell_rz")
    results = scanner.run()
    high = [f for f in results.findings if f.severity_rank >= 3]
    assert not high
