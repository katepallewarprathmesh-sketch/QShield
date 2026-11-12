"""Round-trip acceptance: Qiskit -> CircuitIR -> Qiskit preserves semantics.

Spec (M1.1): "Round-trip: Qiskit → CircuitIR → Qiskit preserves semantics."
"""

import numpy as np
import pytest

qiskit = pytest.importorskip("qiskit")
from qiskit import QuantumCircuit  # noqa: E402
from qiskit.quantum_info import Operator  # noqa: E402

import qshield  # noqa: E402
from qshield.core.exporters import UnsupportedGateError, to_qiskit  # noqa: E402
from qshield.core.parsers.framework_parsers import parse_qiskit  # noqa: E402


def _assert_same_semantics(original: QuantumCircuit, exported: QuantumCircuit) -> None:
    u_orig = Operator(original).data
    u_exp = Operator(exported).data
    assert u_orig.shape == u_exp.shape
    assert np.allclose(u_orig, u_exp, atol=1e-12), "unitary differs after round-trip"


def _roundtrip(qc: QuantumCircuit) -> QuantumCircuit:
    ir = parse_qiskit(qc, name="roundtrip")
    return to_qiskit(ir)


@pytest.mark.parametrize("builder", [
    "bell", "parameterized", "toffoli", "standard_library", "new_gates", "measured",
])
def test_roundtrip_semantics(builder):
    if builder == "bell":
        qc = QuantumCircuit(2, 2)
        qc.h(0)
        qc.cx(0, 1)
        qc.measure([0, 1], [0, 1])
    elif builder == "parameterized":
        qc = QuantumCircuit(2)
        qc.rx(0.3, 0)
        qc.ry(1.1, 1)
        qc.rz(0.7, 0)
        qc.crx(0.5, 0, 1)
        qc.cp(1.2, 0, 1)
        qc.cu(0.4, 0.2, 1.1, 0.0, 0, 1)  # gamma=0
    elif builder == "toffoli":
        qc = QuantumCircuit(3)
        qc.h(0)
        qc.ccx(0, 1, 2)
        qc.ccz(0, 1, 2)
    elif builder == "standard_library":
        qc = QuantumCircuit(2, 2)
        for q in range(2):
            qc.h(q)
            qc.s(q)
            qc.sdg(q)
            qc.t(q)
            qc.tdg(q)
            qc.sx(q)
            qc.sxdg(q)
        qc.cy(0, 1)
        qc.swap(0, 1)
        qc.swap(0, 1)
        qc.ch(0, 1)
        qc.measure([0, 1], [0, 1])
    elif builder == "new_gates":
        qc = QuantumCircuit(3)
        qc.r(0.7, 1.1, 0)
        qc.iswap(0, 1)
        qc.cs(0, 1)
        qc.csdg(0, 1)
        qc.csx(0, 1)
        qc.rzx(0.9, 1, 2)
        qc.rzz(0.8, 0, 2)
    else:  # measured
        qc = QuantumCircuit(2, 2)
        qc.h(0)
        qc.cx(0, 1)
        qc.x(1)
        qc.measure([0, 1], [0, 1])

    exported = _roundtrip(qc)
    if "measured" in builder or getattr(qc, "cregs", []):
        # unitary comparison only up to measurement count; use the unitary fragment
        frag = QuantumCircuit(qc.num_qubits)
        for inst in qc.data:
            if inst.operation.name != "measure":
                frag.append(inst.operation, inst.qubits)
        exported_frag = QuantumCircuit(exported.num_qubits)
        for inst in exported.data:
            if inst.operation.name != "measure":
                exported_frag.append(inst.operation, inst.qubits)
        _assert_same_semantics(frag, exported_frag)
        assert qc.count_ops().get("measure", 0) == exported.count_ops().get("measure", 0)
    else:
        _assert_same_semantics(qc, exported)


def test_exported_circuit_reparses_with_unitaries():
    qc = QuantumCircuit(2, 2)
    qc.h(0)
    qc.cx(0, 1)
    qc.rz(0.4, 1)
    qc.measure([0, 1], [0, 1])
    ir1 = parse_qiskit(qc, name="a")
    exported = to_qiskit(ir1)
    ir2 = parse_qiskit(exported, name="b")
    u1, u2 = ir1.to_unitary(), ir2.to_unitary()
    assert u1 is not None and u2 is not None
    assert np.allclose(u1, u2, atol=1e-12)
    assert ir2.measurements == ir1.measurements


def test_unsupported_gate_raises():
    from qshield.core.circuit_ir import CircuitIR, GateNode, GateType

    ir = CircuitIR(
        circuit_id="t", name="t", num_qubits=1, num_classical_bits=0,
        gates=[GateNode(gate_id="g1", gate_name="mystery_gate", gate_type=GateType.CUSTOM,
                        qubits=[0], parameters=[], unitary=None)],
        dag={}, measurements=[], source_framework="test", source_hash="x", metadata={},
    )
    with pytest.raises(UnsupportedGateError, match="mystery_gate"):
        to_qiskit(ir)


def test_api_surface():
    assert callable(qshield.to_qiskit)
    assert issubclass(qshield.UnsupportedGateError, ValueError)
