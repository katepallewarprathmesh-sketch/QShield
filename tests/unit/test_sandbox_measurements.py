"""M2.1: measurement interception, ancilla capture, wall-clock limits."""

import numpy as np
import pytest

from qshield.core.circuit_ir import CircuitIR
from qshield.core.parsers import parse_qasm
from qshield.dynamic import SandboxExecutor, SandboxViolation

BELL_M = """OPENQASM 2.0;
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
measure q[0] -> c[0];
measure q[1] -> c[1];
"""

X_M = """OPENQASM 2.0;
qreg q[1];
creg c[1];
x q[0];
measure q[0] -> c[0];
"""


def test_measurements_are_intercepted_and_correlated():
    circuit = parse_qasm(BELL_M)
    result = SandboxExecutor().run(circuit, rng=np.random.default_rng(42))
    assert len(result.measurement_log) == 2
    first, second = result.measurement_log
    assert first.qubit == 0 and first.clbit == 0
    assert first.outcome in (0, 1)
    # Bell pair: both measurements always agree
    assert result.classical_bits[0] == result.classical_bits[1]
    assert first.outcome == result.classical_bits[0]
    # second measurement is deterministic given the first collapse
    assert second.probability == pytest.approx(1.0)
    # final state is a single computational basis state
    assert pytest.approx(sum(result.probabilities.values()), rel=1e-9) == 1.0
    assert len(result.probabilities) == 1


def test_deterministic_measurement_probability_one():
    circuit = parse_qasm(X_M)
    result = SandboxExecutor().run(circuit, rng=np.random.default_rng(1))
    assert result.measurement_log[0].outcome == 1
    assert result.measurement_log[0].probability == pytest.approx(1.0)
    assert result.classical_bits == {0: 1}
    assert result.probabilities == {"1": pytest.approx(1.0)}


def test_wall_clock_limit_enforced():
    circuit = parse_qasm(BELL_M)
    with pytest.raises(SandboxViolation, match="time limit"):
        SandboxExecutor().run(circuit, time_limit=-1.0)
    # generous budget passes
    assert SandboxExecutor().run(circuit, time_limit=60.0).num_qubits == 2


def test_initial_state_validation():
    circuit = parse_qasm(BELL_M)
    with pytest.raises(SandboxViolation, match="shape"):
        SandboxExecutor().run(circuit, initial_state=np.zeros(3, dtype=complex))
    with pytest.raises(SandboxViolation, match="zero vector"):
        SandboxExecutor().run(circuit, initial_state=np.zeros(4, dtype=complex))


def test_ancilla_snapshot_capture_and_purity():
    measured = parse_qasm(BELL_M)
    circuit = CircuitIR(
        circuit_id=measured.circuit_id,
        name="bell-with-ancilla",
        num_qubits=2,
        num_classical_bits=2,
        gates=list(measured.gates),
        measurements=list(measured.measurements),
        ancilla_qubits=[1],
        source_framework="test",
        source_hash="x",
        metadata={},
    )
    result = SandboxExecutor().run(circuit, rng=np.random.default_rng(7))
    assert len(result.ancilla_snapshots) == 2  # one snapshot per measurement step
    snap = result.ancilla_snapshots[0]
    assert snap.ancilla_qubits == [1]
    assert snap.reduced_density_matrix.shape == (2, 2)
    # Bell-state ancilla: maximally mixed, purity 0.5
    assert snap.purity == pytest.approx(0.5, abs=1e-6)


def test_sample_distribution_still_works():
    circuit = parse_qasm(BELL_M)
    counts = SandboxExecutor().sample_distribution(circuit, shots=200, rng=np.random.default_rng(3))
    assert sum(counts.values()) == 200
    # Bell correlations dominate: only 00 and 11 should appear
    assert set(counts) <= {"00", "11"}
