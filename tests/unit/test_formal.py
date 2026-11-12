import math

import pytest

from qshield.core.parsers import parse_qasm
from qshield.formal import pyzx_available, zx_equivalence_check

pytestmark = pytest.mark.skipif(not pyzx_available(), reason="pyzx not installed")


def test_identical_circuits_equivalent():
    a = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n")
    b = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n")
    assert zx_equivalence_check(a, b).equivalent is True


def test_hh_identity_proven():
    a = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n")
    b = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\nh q[0];\nh q[0];\ncx q[0], q[1];\n")
    assert zx_equivalence_check(a, b).equivalent is True


def test_rz_pi_2_equals_s_up_to_global_phase():
    a = parse_qasm(f"OPENQASM 2.0;\nqreg q[1];\nrz({math.pi / 2}) q[0];\n")
    b = parse_qasm("OPENQASM 2.0;\nqreg q[1];\ns q[0];\n")
    assert zx_equivalence_check(a, b).equivalent is True


def test_perturbed_circuit_different():
    a = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n")
    b = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\nrz(0.001) q[0];\n")
    assert zx_equivalence_check(a, b).equivalent is False


def test_qubit_mismatch():
    a = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nh q[0];\n")
    b = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\n")
    result = zx_equivalence_check(a, b)
    assert result.equivalent is False
    assert result.method == "zx_calculus"


def test_measurement_circuit_compared_as_unitary_fragment():
    a = parse_qasm("OPENQASM 2.0;\nqreg q[1];\ncreg c[1];\nh q[0];\nmeasure q -> c;\n")
    b = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nh q[0];\n")
    result = zx_equivalence_check(a, b)
    assert result.equivalent is True  # measurements excluded from comparison


def test_circuit_to_pyzx_rejects_unknown_gate():
    pytest.importorskip("pyzx")
    from qshield.core.circuit_ir import CircuitIR, GateNode, GateType
    from qshield.formal import FormalVerificationError, circuit_to_pyzx

    ir = CircuitIR(
        circuit_id="t", name="t", num_qubits=1, num_classical_bits=0,
        gates=[GateNode(gate_id="g1", gate_name="mystery", gate_type=GateType.CUSTOM,
                        qubits=[0], parameters=[], unitary=None)],
        dag={}, measurements=[], source_framework="test", source_hash="x", metadata={},
    )
    with pytest.raises(FormalVerificationError, match="mystery"):
        circuit_to_pyzx(ir)


def test_circuit_to_pyzx_rejects_reset():
    pytest.importorskip("pyzx")
    from qshield.formal import FormalVerificationError, circuit_to_pyzx

    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nreset q[0];\n")
    with pytest.raises(FormalVerificationError, match="reset"):
        circuit_to_pyzx(ir)


def test_circuit_to_pyzx_maps_common_gates():
    pytest.importorskip("pyzx")
    from qshield.formal import circuit_to_pyzx

    qasm = """OPENQASM 2.0;
qreg q[3];
x q[0]; y q[1]; z q[2];
s q[0]; sdg q[1]; t q[2]; tdg q[0];
sx q[1]; sxdg q[2];
rx(0.5) q[0]; ry(0.25) q[1]; rz(0.75) q[2]; p(0.5) q[0]; u1(0.5) q[1];
u2(0.25, 0.5) q[2]; u3(0.25, 0.5, 0.75) q[0]; u(0.25, 0.5, 0.75) q[1];
cy q[0], q[1]; cz q[1], q[2]; swap q[0], q[2]; ch q[0], q[1];
crz(0.5) q[0], q[1]; cp(0.25) q[0], q[1]; cu1(0.25) q[0], q[2];
crx(0.5) q[0], q[1]; cry(0.5) q[1], q[2];
cu3(0.25, 0.5, 0.75) q[0], q[1]; cu(0.25, 0.5, 0.75) q[1], q[2];
rxx(0.5) q[0], q[1]; rzz(0.5) q[1], q[2];
ccx q[0], q[1], q[2]; ccz q[0], q[1], q[2];
"""
    ir = parse_qasm(qasm)
    c = circuit_to_pyzx(ir)
    assert c.qubits == 3


def test_circuit_to_pyzx_ryy_unmappable():
    pytest.importorskip("pyzx")
    from qshield.formal import FormalVerificationError, circuit_to_pyzx

    with pytest.raises(FormalVerificationError, match="ryy"):
        circuit_to_pyzx(parse_qasm("OPENQASM 2.0;\nqreg q[2];\nryy(0.5) q[0], q[1];\n"))


def test_phase_near_miss_snapping():
    pytest.importorskip("pyzx")
    from qshield.formal.zx_calculus import _phase

    frac = _phase(0.7853981633974483)  # pi/4 written as float
    assert float(frac) == pytest.approx(0.25, abs=1e-6)  # 1/4 of pi


def test_equivalence_rejects_qubit_mismatch():
    pytest.importorskip("pyzx")
    from qshield.formal import zx_equivalence_check

    a = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\n")
    b = parse_qasm("OPENQASM 2.0;\nqreg q[3];\nh q[0];\n")
    r = zx_equivalence_check(a, b)
    assert r.equivalent is False
    assert "qubit count mismatch" in r.message


def test_equivalence_unmappable_gate_returns_error():
    pytest.importorskip("pyzx")
    from qshield.formal import zx_equivalence_check

    a = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nryy(0.5) q[0], q[1];\n")
    b = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nryy(0.5) q[0], q[1];\n")
    r = zx_equivalence_check(a, b)
    assert r.equivalent is None
    assert r.method == "error"
