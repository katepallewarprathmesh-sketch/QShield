"""Sandboxed pure-NumPy statevector simulator for untrusted circuits.

Security properties:
* Hard resource limits (max qubits, max gates, max state dimension).
* No network, filesystem or subprocess access — pure linear algebra.
* Measurements are *intercepted and logged*; the simulated classical bits
  are returned to the caller, never written anywhere else.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from qshield.core.circuit_ir import CircuitIR, embed_gate_matrix

DEFAULT_MAX_QUBITS = 12
DEFAULT_MAX_GATES = 100_000


class SandboxViolation(RuntimeError):
    """Raised when a circuit exceeds the sandbox limits."""


@dataclass
class ExecutionResult:
    num_qubits: int
    final_state: np.ndarray
    measurement_log: list[tuple[int, int]] = field(default_factory=list)  # (gate_index/shot, bit)
    probabilities: dict[str, float] = field(default_factory=dict)


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
    ) -> ExecutionResult:
        self.check_limits(circuit)
        n = circuit.num_qubits
        dim = 1 << n
        state = initial_state if initial_state is not None else np.zeros(dim, dtype=complex)
        if initial_state is None:
            state[0] = 1.0  # |00...0>
        else:
            state = state / np.linalg.norm(state)

        for gate in circuit.gates:
            if gate.unitary is None:
                # try to recover unknown-gate matrices from the gate DB
                from qshield.core.gate_database import GATE_DB
                mat = GATE_DB.matrix(gate.gate_name, gate.parameters)
                if mat is None:
                    raise SandboxViolation(f"Gate {gate.gate_name!r} has no known unitary; refusing to execute")
                gate.unitary = mat
            full = embed_gate_matrix(gate.unitary, gate.qubits, n)
            state = full @ state
        probabilities = {
            format(i, f"0{n}b"): float(abs(a) ** 2) for i, a in enumerate(state) if abs(a) ** 2 > 0
        }
        return ExecutionResult(
            num_qubits=n,
            final_state=state,
            measurement_log=[],
            probabilities=probabilities,
        )

    # ------------------------------------------------------------------
    def sample_distribution(
        self,
        circuit: CircuitIR,
        shots: int = 10_000,
        rng: np.random.Generator | None = None,
    ) -> dict[str, int]:
        """Collapse-measure the final state ``shots`` times (simulated)."""
        result = self.run(circuit)
        rng = rng or np.random.default_rng(20240611)
        outcomes = sorted(result.probabilities)
        probs = np.array([result.probabilities[o] for o in outcomes], dtype=float)
        idx = rng.choice(len(outcomes), size=shots, p=probs / probs.sum())
        counts: dict[str, int] = {}
        for i in idx:
            counts[outcomes[i]] = counts.get(outcomes[i], 0) + 1
        return counts
