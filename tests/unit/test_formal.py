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
