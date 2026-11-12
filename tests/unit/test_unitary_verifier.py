import numpy as np
import pytest

from qshield.core.parsers import parse_qasm
from qshield.static.unitary_verifier import (
    UnitaryVerifier,
    VerificationResult,
    reduced_density_matrix,
    trace_distance,
)

BELL = """OPENQASM 2.0;
qreg q[2];
h q[0];
cx q[0], q[1];
"""

ANCILLA_LEAK = """OPENQASM 2.0;
qreg q[3];
cx q[0], q[2];
h q[0];
cx q[0], q[1];
"""


def test_equivalence_identical():
    circuit = parse_qasm(BELL)
    u = circuit.to_unitary()
    report = UnitaryVerifier().verify_equivalence(circuit, u, tolerance=1e-9)
    assert report.result == VerificationResult.EQUIVALENT
    assert report.distance == pytest.approx(0.0, abs=1e-12)


def test_equivalence_different():
    circuit = parse_qasm(BELL + "x q[0];\n")
    u = parse_qasm(BELL).to_unitary()
    report = UnitaryVerifier().verify_equivalence(circuit, u)
    assert report.result == VerificationResult.DIFFERENT
    assert report.distance > 1e-6


def test_ancilla_independence_bell_is_clean():
    circuit = parse_qasm(BELL)
    report = UnitaryVerifier().check_ancilla_independence(circuit, [1])
    assert not report.leaks


def test_ancilla_dependence_detected():
    circuit = parse_qasm(ANCILLA_LEAK)
    report = UnitaryVerifier(max_qubits=8).check_ancilla_independence(circuit, [2])
    assert report.leaks
    assert report.max_trace_distance > 0.5


def test_reduced_density_matrix_bell():
    circuit = parse_qasm(BELL)
    u = circuit.to_unitary()
    psi = u @ np.array([1, 0, 0, 0], dtype=complex)
    rho = reduced_density_matrix(psi, [0], 2)
    assert np.allclose(rho, np.eye(2) / 2, atol=1e-9)
    rho1 = reduced_density_matrix(psi, [1], 2)
    assert np.allclose(rho1, np.eye(2) / 2, atol=1e-9)


def test_schmidt_decomposition():
    circuit = parse_qasm(BELL)
    u = circuit.to_unitary()
    psi = u @ np.array([1, 0, 0, 0], dtype=complex)
    result = UnitaryVerifier().compute_schmidt_decomposition(psi, ([0], [1]), num_qubits=2)
    assert result.rank == 2
    assert result.entanglement_entropy == pytest.approx(1.0)  # maximally entangled
    assert result.coefficients == pytest.approx([1 / np.sqrt(2), 1 / np.sqrt(2)], abs=1e-9)


def test_schmidt_product_state():
    psi = np.array([1, 0, 0, 0], dtype=complex)  # |00>
    result = UnitaryVerifier().compute_schmidt_decomposition(psi, ([0], [1]), num_qubits=2)
    assert result.rank == 1
    assert result.entanglement_entropy == pytest.approx(0.0, abs=1e-9)


def test_trace_distance_identical():
    rho = np.eye(2) / 2
    assert trace_distance(rho, rho) == pytest.approx(0.0, abs=1e-9)


def test_verify_rejects_mismatched_dimensions():
    circuit = parse_qasm(BELL)
    report = UnitaryVerifier().verify_equivalence(circuit, np.eye(3))
    assert report.result == VerificationResult.DIFFERENT
