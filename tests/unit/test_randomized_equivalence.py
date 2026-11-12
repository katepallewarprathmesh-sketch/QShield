"""Randomized (polynomial identity testing) unitary equivalence."""

import numpy as np
import pytest

from qshield.core.parsers.qasm_parser import parse_qasm
from qshield.static.randomized_equivalence import (
    RandomizedVerificationError,
    apply_gates_to_state,
    randomized_equivalence,
)

BELL = """OPENQASM 2.0;
qreg q[2];
h q[0];
cx q[0], q[1];
"""
BELL_WITH_IDENTITY = BELL + "s q[1];\nsdg q[1];\n"
BELL_PERTURBED = BELL + "rz(0.5) q[0];\n"


def _wide_qasm(n: int) -> str:
    gates = "".join(f"h q[{i}];\n" for i in range(n))
    gates += "".join(f"cx q[{i}], q[{i + 1}];\n" for i in range(0, n - 1, 2))
    return f"OPENQASM 2.0;\nqreg q[{n}];\n{gates}"


def test_identical_circuits_equivalent():
    a = parse_qasm(BELL)
    report = randomized_equivalence(a, a, num_samples=4, seed=1)
    assert report.equivalent
    assert report.min_fidelity == pytest.approx(1.0, abs=1e-12)


def test_embedded_identity_pair_equivalent():
    a, b = parse_qasm(BELL), parse_qasm(BELL_WITH_IDENTITY)
    report = randomized_equivalence(a, b, num_samples=4, seed=1)
    assert report.equivalent


def test_perturbed_circuit_different():
    a, b = parse_qasm(BELL), parse_qasm(BELL_PERTURBED)
    report = randomized_equivalence(a, b, num_samples=4, seed=1)
    assert not report.equivalent
    assert report.min_fidelity < 0.95  # rz(0.5) is easily distinguished


def test_qubit_count_mismatch_rejected():
    a = parse_qasm(BELL)
    b = parse_qasm("OPENQASM 2.0;\nqreg q[3];\nh q[0];\n")
    with pytest.raises(RandomizedVerificationError):
        randomized_equivalence(a, b)


def test_state_dimension_mismatch_rejected():
    a = parse_qasm(BELL)
    with pytest.raises(RandomizedVerificationError):
        apply_gates_to_state(np.ones(8, dtype=complex), a)


@pytest.mark.slow
def test_twenty_qubit_equivalence_smoke():
    wide = _wide_qasm(20)
    a = parse_qasm(wide)
    b = parse_qasm(wide + "rz(0.0) q[0];\n")  # identity rotation
    report = randomized_equivalence(a, b, num_samples=2, seed=7)
    assert report.equivalent
