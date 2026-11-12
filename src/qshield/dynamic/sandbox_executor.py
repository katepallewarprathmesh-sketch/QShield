"""Sandboxed execution of untrusted quantum circuits.

Executes a :class:`CircuitIR` on an internal NumPy statevector backend.
Enforces resource limits (qubits, gates, wall-clock time) and *intercepts
measurements*: each measurement collapses the state (projective, Born
rule) and is logged with its outcome and the probability that produced it.

Ancilla capture: circuits that declare ``ancilla_qubits`` get their
ancilla reduced density matrix snapshotted at *every* measurement step
(before the collapse is applied), together with the purity
``Tr(rho^2)`` — 1.0 means the ancilla is in a pure state (unentangled
with the data), < 1.0 means the measurement destroys information about an
entangled ancilla.  Snapshots are available on
:attr:`ExecutionResult.ancilla_snapshots`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import numpy as np

from qshield.core.circuit_ir import CircuitIR, embed_gate_matrix

DEFAULT_MAX_QUBITS = 12
DEFAULT_MAX_GATES = 1_000
MAX_ANCILLA_SNAPSHOT = 8  # cap on ancilla count for reduced-density snapshots


class SandboxViolation(RuntimeError):
    """Raised when a circuit exceeds the sandbox limits."""


@dataclass
class MeasurementRecord:
    """One intercepted measurement."""

    step: int            # index into circuit.measurements
    qubit: int
    clbit: int
    outcome: int         # 0 or 1 as sampled (or determined) at measurement time
    probability: float   # Born probability of the recorded outcome


@dataclass
class AncillaSnapshot:
    """Ancilla reduced density matrix captured before a measurement collapse."""

    at_measurement: int           # index of the triggering measurement record
    ancilla_qubits: list[int]
    reduced_density_matrix: np.ndarray
    purity: float                 # Tr(rho^2): 1.0 = pure, < 1.0 = entangled with data


@dataclass
class ExecutionResult:
    num_qubits: int
    final_state: np.ndarray
    measurement_log: list[MeasurementRecord] = field(default_factory=list)
    probabilities: dict[str, float] = field(default_factory=dict)
    classical_bits: dict[int, int] = field(default_factory=dict)  # clbit -> 0/1
    ancilla_snapshots: list[AncillaSnapshot] = field(default_factory=list)
    elapsed_seconds: float = 0.0


class SandboxExecutor:
    def __init__(self, max_qubits: int = DEFAULT_MAX_QUBITS, max_gates: int = DEFAULT_MAX_GATES):
        self.max_qubits = max_qubits
        self.max_gates = max_gates

    # ------------------------------------------------------------------
    def check_limits(self, circuit: CircuitIR) -> None:
        if circuit.num_qubits > self.max_qubits:
            raise SandboxViolation(
                f"Circuit has {circuit.num_qubits} qubits; sandbox limit is {self.max_qubits}"
            )
        if len(circuit.gates) > self.max_gates:
            raise SandboxViolation(
                f"Circuit has {len(circuit.gates)} gates; sandbox limit is {self.max_gates}"
            )

    # ------------------------------------------------------------------
    def run(
        self,
        circuit: CircuitIR,
        initial_state: np.ndarray | None = None,
        *,
        rng: np.random.Generator | None = None,
        time_limit: float | None = None,
        capture_ancillas: bool = True,
    ) -> ExecutionResult:
        """Execute ``circuit`` and intercept measurements.

        ``rng`` makes measurement sampling reproducible; ``time_limit`` is a
        wall-clock budget in seconds (checked after every gate/measurement,
        raising :class:`SandboxViolation` on expiry).
        """
        started = time.monotonic()
        self.check_limits(circuit)
        rng = rng or np.random.default_rng(20240611)
        n = circuit.num_qubits

        def _check_time() -> None:
            if time_limit is not None and time.monotonic() - started > time_limit:
                raise SandboxViolation(f"Wall-clock time limit ({time_limit}s) exceeded during execution")

        dim = 1 << n
        state: np.ndarray
        if initial_state is None:
            state = np.zeros(dim, dtype=complex)
            state[0] = 1.0  # |00...0>
        else:
            state = np.asarray(initial_state, dtype=complex)
            if state.shape != (dim,):
                raise SandboxViolation(f"Initial state shape {state.shape} does not match {n} qubits")
            norm = np.linalg.norm(state)
            if norm == 0:
                raise SandboxViolation("Initial state is the zero vector")
            state = state / norm

        for gate in circuit.gates:
            _check_time()
            if gate.unitary is None:
                # try to recover unknown-gate matrices from the gate DB
                from qshield.core.gate_database import GATE_DB

                mat = GATE_DB.matrix(gate.gate_name, gate.parameters)
                if mat is None:
                    raise SandboxViolation(f"Gate {gate.gate_name!r} has no known unitary; refusing to execute")
                gate.unitary = mat
            full = embed_gate_matrix(gate.unitary, gate.qubits, n)
            state = full @ state

        # ---- measurement interception -----------------------------------
        ancillas = sorted(circuit.ancilla_qubits or [])
        if len(ancillas) > MAX_ANCILLA_SNAPSHOT:
            ancillas = ancillas[:MAX_ANCILLA_SNAPSHOT]

        measurement_log: list[MeasurementRecord] = []
        ancilla_snapshots: list[AncillaSnapshot] = []
        classical_bits: dict[int, int] = {}

        for step, (qubit, clbit) in enumerate(circuit.measurements):
            _check_time()
            if ancillas and capture_ancillas:
                ancilla_snapshots.append(_snapshot_ancillas(state, ancillas, n, step))

            prob_one = _probability_of_one(state, qubit, n)
            if prob_one <= 0.0:
                outcome, collapsed = 0, _collapse(state, qubit, n, 0)
            elif prob_one >= 1.0:
                outcome, collapsed = 1, _collapse(state, qubit, n, 1)
            else:
                outcome = int(rng.random() < prob_one)
                collapsed = _collapse(state, qubit, n, outcome)
            p_outcome = prob_one if outcome == 1 else 1.0 - prob_one
            state = collapsed
            measurement_log.append(
                MeasurementRecord(step=step, qubit=qubit, clbit=clbit, outcome=outcome, probability=p_outcome)
            )
            classical_bits[clbit] = outcome
            _check_time()

        probabilities = {
            format(i, f"0{n}b"): float(abs(a) ** 2) for i, a in enumerate(state) if abs(a) ** 2 > 0
        }
        return ExecutionResult(
            num_qubits=n,
            final_state=state,
            measurement_log=measurement_log,
            probabilities=probabilities,
            classical_bits=classical_bits,
            ancilla_snapshots=ancilla_snapshots,
            elapsed_seconds=time.monotonic() - started,
        )

    # ------------------------------------------------------------------
    def sample_distribution(
        self,
        circuit: CircuitIR,
        shots: int = 10_000,
        rng: np.random.Generator | None = None,
    ) -> dict[str, int]:
        """Collapse-measure the final state ``shots`` times (simulated)."""
        result = self.run(circuit, rng=rng)
        rng = rng or np.random.default_rng(20240611)
        outcomes = sorted(result.probabilities)
        probs = np.array([result.probabilities[o] for o in outcomes], dtype=float)
        idx = rng.choice(len(outcomes), size=shots, p=probs / probs.sum())
        counts: dict[str, int] = {}
        for i in idx:
            counts[outcomes[i]] = counts.get(outcomes[i], 0) + 1
        return counts


def _probability_of_one(state: np.ndarray, qubit: int, num_qubits: int) -> float:
    """Born probability that ``qubit`` reads as |1> in ``state``.

    Qubit 0 is the most significant bit of the state index (MSB ordering).
    """
    bit = num_qubits - 1 - qubit
    mask = 1 << bit
    probs = np.abs(state) ** 2
    return float(sum(probs[i] for i in range(len(state)) if i & mask))


def _collapse(state: np.ndarray, qubit: int, num_qubits: int, outcome: int) -> np.ndarray:
    bit = num_qubits - 1 - qubit
    mask = 1 << bit
    collapsed = state.copy()
    for i in range(len(collapsed)):
        if bool(i & mask) != bool(outcome):
            collapsed[i] = 0.0
    norm = np.linalg.norm(collapsed)
    if norm == 0.0:
        # measurement of a zero-amplitude outcome: keep the state untouched
        return state
    return collapsed / norm


def _snapshot_ancillas(
    state: np.ndarray, ancillas: list[int], num_qubits: int, step: int
) -> AncillaSnapshot:
    rho = _partial_trace(state, ancillas, num_qubits)
    purity = float(np.real(np.trace(rho @ rho)))
    return AncillaSnapshot(
        at_measurement=step,
        ancilla_qubits=list(ancillas),
        reduced_density_matrix=rho,
        purity=purity,
    )


def _partial_trace(state: np.ndarray, keep: list[int], num_qubits: int) -> np.ndarray:
    """Reduced density matrix over ``keep`` qubits (trace out the rest)."""
    from qshield.static.unitary_verifier import reduced_density_matrix

    return reduced_density_matrix(state, keep, num_qubits)
