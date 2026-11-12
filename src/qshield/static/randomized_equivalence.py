"""Randomized (high-probability) unitary equivalence for large circuits.

Exact equivalence checking is exponential in the qubit count; the dense
path in :mod:`qshield.static.unitary_verifier` is practical up to ~12
qubits. This module implements the standard *polynomial identity testing*
argument instead: apply both circuits to a handful of random normalized
states and compare the outputs.

If ``|<psi_a|psi_b>|^2`` is below ``1 - tolerance`` for some random
``|psi>``, the circuits are certainly different.
If the fidelity is ``1`` on ``k`` independent random inputs, the circuits
are equivalent with probability exponentially close to 1 in ``k``
(quantified below) — this is evidence, not a proof. For a proof use
``qshield compare --formal`` (ZX calculus) or the dense verifier.

Probability bound: for unitaries whose action differs on a set of states
of measure ``mu``, k independent samples all landing in the agreeing set
happens with probability ``(1 - mu)^k``. For a relative Frobenius
departure ``||U - V||_F / ||U||_F`` the distinguishing measure is large;
in particular a single-gate deviation of angle ``theta`` is detected with
probability < 1 for ``theta << 1`` — see the note in ``README``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from qshield.core.circuit_ir import CircuitIR

DEFAULT_MAX_QUBITS = 22  # 2^22 complex128 amplitudes = 128 MiB per vector
DEFAULT_SAMPLES = 8


class RandomizedVerificationError(RuntimeError):
    """Raised when the randomized check cannot be run (non-unitary gate, limits)."""


def apply_gates_to_state(state: np.ndarray, circuit: CircuitIR) -> np.ndarray:
    """Apply a Unitary CircuitIR to a statevector without building 2^n x 2^n matrices.

    Cost is O(len(gates) x 2^n x 4) — practical to ~20+ qubits.
    Measurements/resets are skipped (they do not affect the unitary fragment).
    """
    n = circuit.num_qubits
    if state.shape != (1 << n,):
        raise RandomizedVerificationError(
            f"State dimension {state.shape} does not match {n} qubits"
        )
    out = state.astype(complex, copy=True)
    for gate in circuit.gates:
        mat = gate.unitary
        if mat is None:
            from qshield.core.gate_database import GATE_DB

            mat = GATE_DB.matrix(gate.gate_name, gate.parameters)
        if mat is None:
            raise RandomizedVerificationError(
                f"Gate {gate.gate_name!r} has no known unitary; cannot verify"
            )
        out = _apply_gate(out, np.asarray(mat, dtype=complex), gate.qubits, n)
    return out


def _apply_gate(state: np.ndarray, mat: np.ndarray, qubits: list[int], n: int) -> np.ndarray:
    k = len(qubits)
    targets = list(qubits)
    rest = [q for q in range(n) if q not in targets]
    perm = targets + rest
    tensor = np.transpose(state.reshape([2] * n), perm)
    flat = tensor.reshape(1 << k, -1)
    result = mat @ flat
    tensor = result.reshape([2] * k + [2] * len(rest))
    inverse = np.argsort(perm)
    return np.transpose(tensor, inverse).reshape(-1)


@dataclass
class RandomizedReport:
    num_qubits: int
    num_samples: int
    tolerance: float
    fidelities: list[float] = field(default_factory=list)

    @property
    def min_fidelity(self) -> float:
        return min(self.fidelities) if self.fidelities else 1.0

    @property
    def equivalent(self) -> bool:
        return all(f >= 1.0 - self.tolerance for f in self.fidelities)

    @property
    def verdict(self) -> str:
        """'equivalent' | 'different' | 'close' — never claims a proof."""
        if self.equivalent:
            return "equivalent"
        return "different"

    def summary(self) -> str:
        if self.equivalent:
            return (
                f"EQUIVALENT on {self.num_samples} random input(s) "
                f"(min fidelity {self.min_fidelity:.12f}) — high probability, not a proof"
            )
        return (
            f"DIFFERENT — a random distinguishing input was found "
            f"(min fidelity {self.min_fidelity:.12f} < {1.0 - self.tolerance:.12f})"
        )


def randomized_equivalence(
    circuit_a: CircuitIR,
    circuit_b: CircuitIR,
    num_samples: int = DEFAULT_SAMPLES,
    tolerance: float = 1e-9,
    seed: int | None = None,
    max_qubits: int = DEFAULT_MAX_QUBITS,
) -> RandomizedReport:
    """Compare two circuits on random normalized states.

    Returns a :class:`RandomizedReport`. Raises
    :class:`RandomizedVerificationError` when the circuits have different
    sizes, exceed the qubit limit, or contain non-unitary/unknown gates.
    """
    if circuit_a.num_qubits != circuit_b.num_qubits:
        raise RandomizedVerificationError(
            f"Circuits have different qubit counts: {circuit_a.num_qubits} vs {circuit_b.num_qubits}"
        )
    n = circuit_a.num_qubits
    if n > max_qubits:
        raise RandomizedVerificationError(
            f"{n} qubits exceeds the randomized-verification limit of {max_qubits} "
            "(statevector memory). Use structural comparison or the ZX-calculus engine."
        )
    rng = np.random.default_rng(seed)
    fidelities: list[float] = []
    dim = 1 << n
    for _ in range(num_samples):
        vec = rng.standard_normal(dim) + 1j * rng.standard_normal(dim)
        vec /= np.linalg.norm(vec)
        out_a = apply_gates_to_state(vec, circuit_a)
        out_b = apply_gates_to_state(vec, circuit_b)
        fidelities.append(float(abs(np.vdot(out_a, out_b)) ** 2))
    return RandomizedReport(num_qubits=n, num_samples=num_samples, tolerance=tolerance, fidelities=fidelities)
