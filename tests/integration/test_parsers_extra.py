"""Coverage-oriented tests for framework parsers and formal layer."""

import pytest

qiskit = pytest.importorskip("qiskit")
cirq = pytest.importorskip("cirq")
p = pytest.importorskip("pennylane")
pyzx = pytest.importorskip("pyzx")

from qshield.core.circuit_ir import CircuitIR, GateNode, GateType  # noqa: E402
from qshield.core.parsers.framework_parsers import (  # noqa: E402
    parse_cirq,
    parse_pennylane,
    parse_qiskit,
)
from qshield.formal import zx_equivalence_check  # noqa: E402


def _cirq_bell():
    q = cirq.LineQubit.range(2)
    return cirq.Circuit(cirq.H(q[0]), cirq.CNOT(q[0], q[1]), cirq.rz(0.5)(q[0]))


def test_parse_cirq_rotation_and_names():
    ir = parse_cirq(_cirq_bell())
    names = [g.gate_name for g in ir.gates]
    assert names[0] == "h"
    assert names[1] == "cx"
    # RotationGate convention: exponent = theta / pi with global_shift -0.5
    assert names[2] == "rz"
    assert ir.gates[2].parameters == pytest.approx([0.5])


def test_parse_cirq_measurement_ops():
    q = cirq.LineQubit.range(1)
    c = cirq.Circuit(cirq.H(q[0]), cirq.measure(q[0], key="m"))
    ir = parse_cirq(c)
    assert len(ir.measurements) == 1


def test_parse_cirq_xpowgate_powers():
    q = cirq.LineQubit.range(1)
    assert [g.gate_name for g in parse_cirq(cirq.Circuit(cirq.X(q[0]) ** 0.5)).gates] == ["sx"]
    assert [g.gate_name for g in parse_cirq(cirq.Circuit(cirq.X(q[0]) ** (1 / 3))).gates] == ["rx"]


def test_parse_cirq_pauli_gates():
    q = cirq.LineQubit.range(3)
    c = cirq.Circuit(cirq.X(q[0]), cirq.Y(q[1]), cirq.Z(q[2]))
    names = {g.gate_name for g in parse_cirq(c).gates}
    assert names == {"x", "y", "z"}


def test_parse_cirq_custom_gate_with_parameters_by_name():
    class MysteryGate(cirq.Gate):
        def __init__(self, theta):
            self.theta = theta

        def _num_qubits_(self):
            return 1

        @property
        def parameters_by_name(self):
            return {"theta": self.theta}

        def _decompose_(self, qubits):
            yield cirq.rz(self.theta).on(qubits[0])

    q = cirq.LineQubit.range(1)
    c = cirq.Circuit(MysteryGate(0.7).on(q[0]))
    ir = parse_cirq(c)
    # falls back to class-name-derived canonical name with parameters
    assert ir.gates[0].parameters == pytest.approx([0.7])


def test_parse_pennylane_tape():
    op_h = p.Hadamard(wires=0)
    op_rz = p.RZ(0.5, wires=0)
    op_cnot = p.CNOT(wires=[0, 1])
    tape = p.tape.QuantumScript([op_h, op_rz, op_cnot])
    ir = parse_pennylane(tape)
    names = [g.gate_name for g in ir.gates]
    assert names == ["h", "rz", "cx"]
    assert ir.gates[1].parameters == pytest.approx([0.5])


def test_parse_pennylane_rejects_non_tape():
    with pytest.raises(TypeError, match="QuantumScript"):
        parse_pennylane(object())


def test_parse_qiskit_with_barrier_and_reset():
    qc = qiskit.QuantumCircuit(2)
    qc.h(0)
    qc.barrier()
    qc.cx(0, 1)
    ir = parse_qiskit(qc)
    names = [g.gate_name for g in ir.gates]
    assert "h" in names and "cx" in names


def _gate(name, arity, params):
    return GateNode(gate_id=name, gate_name=name, gate_type=GateType.STANDARD,
                    qubits=list(range(arity)), parameters=params, unitary=None)


def _ir(gates, nq):
    return CircuitIR(circuit_id="t", name="t", num_qubits=nq, num_classical_bits=0,
                     gates=gates, dag={}, measurements=[], source_framework="test",
                     source_hash="x", metadata={})


def test_zx_verify_equality_notimplemented(monkeypatch):
    import qshield.formal.equivalence_checker as ec

    class _C:
        def verify_equality(self, other):
            raise NotImplementedError("nope")

    monkeypatch.setattr(ec, "circuit_to_pyzx", lambda ir: _C())
    monkeypatch.setattr("pyzx.compare_tensors", lambda a, b: True)
    ir = _ir([_gate("h", 1, [])], 1)
    r = zx_equivalence_check(ir, _ir([_gate("h", 1, [])], 1))
    assert r.equivalent is True
    assert r.method == "tensor_exact"


def test_zx_verify_equality_exception(monkeypatch):
    import qshield.formal.equivalence_checker as ec

    class _C:
        def verify_equality(self, other):
            raise RuntimeError("boom")

    monkeypatch.setattr(ec, "circuit_to_pyzx", lambda ir: _C())
    ir = _ir([_gate("h", 1, [])], 1)
    r = zx_equivalence_check(ir, _ir([_gate("h", 1, [])], 1))
    assert r.equivalent is None and "boom" in r.message


def test_zx_tensor_compare_exception(monkeypatch):
    import qshield.formal.equivalence_checker as ec

    class _C:
        def verify_equality(self, other):
            return False

    monkeypatch.setattr(ec, "circuit_to_pyzx", lambda ir: _C())

    def _boom(a, b):
        raise RuntimeError("tensor boom")

    monkeypatch.setattr("pyzx.compare_tensors", _boom)
    ir = _ir([_gate("h", 1, [])], 1)
    r = zx_equivalence_check(ir, _ir([_gate("h", 1, [])], 1))
    assert r.equivalent is None and "tensor boom" in r.message


def test_zx_tensor_exact_different(monkeypatch):
    import qshield.formal.equivalence_checker as ec

    class _C:
        def verify_equality(self, other):
            return False

    monkeypatch.setattr(ec, "circuit_to_pyzx", lambda ir: _C())
    monkeypatch.setattr("pyzx.compare_tensors", lambda a, b: False)
    ir = _ir([_gate("h", 1, [])], 1)
    r = zx_equivalence_check(ir, _ir([_gate("x", 1, [])], 1))
    assert r.equivalent is False
