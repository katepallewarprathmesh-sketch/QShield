"""Unitary equivalence verification (Algorithm 2 in the specification).

* :func:`UnitaryVerifier.to_circuit_unitary` — via CircuitIR.to_unitary
* :meth:`UnitaryVerifier.verify_equivalence` — circuit vs expected unitary
* :meth:`UnitaryVerifier.verify_partial_trace` — ancilla independence test
* :meth:`UnitaryVerifier.compute_schmidt_decomposition` — bipartite cut

Exact methods only; practical up to ``max_qubits`` (default 12, configurable).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import numpy as np

from qshield.core.circuit_ir import MAX_EXACT_QUBITS, CircuitIR


class VerificationResult(Enum):
    EQUIVALENT = "equivalent"
    CLOSE = "close"
    DIFFERENT = "different"
    UNCOMPUTABLE = "uncomputable"


@dataclass
class SchmidtResult:
    coefficients: list[float]
    rank: int
    entanglement_entropy: float  # von Neumann entropy in bits


@dataclass
class EquivalenceReport:
    result: VerificationResult
    distance: float | None
    tolerance: float
    message: str

    @property
    def ok(self) -> bool:
        return self.result in (VerificationResult.EQUIVALENT, VerificationResult.CLOSE)


@dataclass
class LeakageReport:
    leaks: bool
    max_trace_distance: float
    tested_inputs: int
    details: str


def reduced_density_matrix(state: np.ndarray, keep: list[int], num_qubits: int) -> np.ndarray:
    """Reduced density matrix over ``keep`` qubits (robust implementation)."""
    keep = list(keep)
    trace_axes = [q for q in range(num_qubits) if q not in keep]
    psi = state.reshape([2] * num_qubits)
    # density matrix as tensor with paired axes
    rho = np.tensordot(psi, psi.conj(), axes=0)  # axes: q0...qn-1, q0'...qn'-1
    # trace out each traced axis q: contract axis q with axis num_qubits + q
    # process in descending order, tracking axis shifts
    # work on the density matrix as a flat 2^n x 2^n object for simplicity
    flat = rho.reshape(2 ** num_qubits, 2 ** num_qubits)
    # indices: row = |a_0 ... a_{n-1}>, col = |b_0 ... b_{n-1}>
    # trace over traced qubits: sum a_q == b_q
    dim = 2 ** num_qubits
    idx_keep = _basis_indices(dim, keep, num_qubits)
    idx_trace = _basis_indices(dim, trace_axes, num_qubits)
    red = np.zeros((2 ** len(keep), 2 ** len(keep)), dtype=complex)
    for ki, a in enumerate(idx_keep):
        for kj, b in enumerate(idx_keep):
            total = 0.0 + 0.0j
            for t in idx_trace:
                # combine kept-row bits with trace bits into full row index
                row = _combine(a, t, keep, trace_axes, num_qubits)
                col = _combine(b, t, keep, trace_axes, num_qubits)
                total += flat[row, col]
            red[ki, kj] = total
    return red


def _basis_indices(dim: int, axes: list[int], num_qubits: int) -> list[int]:
    """All bit-value combinations for the given qubit axes, as row indices."""
    axes = sorted(axes)
    out: list[int] = []
    for combo in range(1 << len(axes)):
        idx = 0
        for j, q in enumerate(axes):
            bit = (combo >> (len(axes) - 1 - j)) & 1
            idx |= bit << (num_qubits - 1 - q)
        out.append(idx)
    return out


def _combine(kept: int, traced: int, keep: list[int], trace_axes: list[int], num_qubits: int) -> int:
    idx = 0
    keep_sorted = sorted(keep)
    trace_sorted = sorted(trace_axes)
    for q in keep_sorted:
        bit = (kept >> (num_qubits - 1 - q)) & 1
        idx |= bit << (num_qubits - 1 - q)
    for q in trace_sorted:
        bit = (traced >> (num_qubits - 1 - q)) & 1
        idx |= bit << (num_qubits - 1 - q)
    return idx


def trace_distance(rho_a: np.ndarray, rho_b: np.ndarray) -> float:
    """1/2 * ||rho_a - rho_b||_1 (trace norm)."""
    diff = rho_a - rho_b
    eig = np.linalg.eigvalsh(diff)
    return float(0.5 * np.sum(np.abs(eig)))


class UnitaryVerifier:
    """Exact unitary/density-matrix analyses for small circuits."""

    def __init__(self, max_qubits: int = MAX_EXACT_QUBITS):
        self.max_qubits = max_qubits

    # ------------------------------------------------------------------
    def verify_equivalence(
        self,
        circuit: CircuitIR,
        expected_unitary: np.ndarray,
        tolerance: float = 1e-6,
    ) -> EquivalenceReport:
        actual = circuit.to_unitary(max_qubits=self.max_qubits)
        if actual is None:
            return EquivalenceReport(
                result=VerificationResult.UNCOMPUTABLE,
                distance=None,
                tolerance=tolerance,
                message=(
                    f"Circuit has {circuit.num_qubits} qubits or non-unitary operations; "
                    f"exact verification limited to {self.max_qubits} qubits and unitary circuits."
                ),
            )
        expected = np.asarray(expected_unitary, dtype=complex)
        if expected.shape != actual.shape:
            return EquivalenceReport(
                result=VerificationResult.DIFFERENT,
                distance=None,
                tolerance=tolerance,
                message=f"Dimension mismatch: circuit {actual.shape} vs expected {expected.shape}",
            )
        distance = float(np.linalg.norm(actual - expected))
        if distance < tolerance:
            result = VerificationResult.EQUIVALENT
        elif distance < 10 * tolerance:
            result = VerificationResult.CLOSE
        else:
            result = VerificationResult.DIFFERENT
        return EquivalenceReport(
            result=result,
            distance=distance,
            tolerance=tolerance,
            message=f"||U_circuit - U_expected||_2 = {distance:.3e}",
        )

    # ------------------------------------------------------------------
    def check_ancilla_independence(
        self,
        circuit: CircuitIR,
        ancilla_qubits: list[int],
        num_probe_inputs: int = 8,
        tolerance: float = 1e-6,
    ) -> LeakageReport:
        """Test whether ancilla qubits are independent of the computation input.

        For each computational-basis product state |x> on the data qubits
        (ancillas start in |0>), compute the output state and the ancilla
        reduced density matrix.  If the ancilla state depends on x, the
        ancilla carries information about the computation -> leakage.
        """
        n = circuit.num_qubits
        if n > min(self.max_qubits, 10):
            return LeakageReport(False, float("nan"), 0, f"skipped: {n} qubits exceeds exact-analysis limit")
        unitary = circuit.to_unitary(max_qubits=self.max_qubits)
        if unitary is None:
            return LeakageReport(False, float("nan"), 0, "skipped: circuit is not exactly unitary-computable")
        ancillas = sorted(ancilla_qubits)
        data = [q for q in range(n) if q not in ancillas]
        if not ancillas or not data:
            return LeakageReport(False, 0.0, 0, "no ancilla/data split to test")

        probe_indices = _probe_inputs(len(data), num_probe_inputs)
        reductions = []
        for x in probe_indices:
            basis = _basis_state(n, {q: (x >> (len(data) - 1 - i)) & 1 for i, q in enumerate(data)})
            out = unitary @ basis
            rho_a = reduced_density_matrix(out, ancillas, n)
            reductions.append(rho_a)
        max_td = 0.0
        for i in range(len(reductions)):
            for j in range(i + 1, len(reductions)):
                max_td = max(max_td, trace_distance(reductions[i], reductions[j]))
        leaks = max_td > tolerance
        return LeakageReport(
            leaks=leaks,
            max_trace_distance=max_td,
            tested_inputs=len(probe_indices),
            details=(
                f"ancilla reduced states differ by up to {max_td:.2e} (trace distance) across {len(probe_indices)} probe inputs"
            ),
        )

    # ------------------------------------------------------------------
    def compute_schmidt_decomposition(
        self,
        state: np.ndarray,
        partition: tuple[list[int], list[int]],
        num_qubits: int | None = None,
    ) -> SchmidtResult:
        """Schmidt decomposition across a bipartition of a pure state."""
        n = num_qubits
        if n is None:
            n = int(np.log2(state.size).round())
        a_qubits, b_qubits = partition
        dim_a = 2 ** len(a_qubits)
        dim_b = 2 ** len(b_qubits)
        if dim_a * dim_b != state.size:
            raise ValueError("Partition sizes do not match state dimension")
        # reshape with MSB ordering: axis order = qubit index order 0..n-1
        tensor = state.reshape([2] * n)
        tensor = np.transpose(tensor, a_qubits + b_qubits)
        matrix = tensor.reshape(dim_a, dim_b)
        s = np.linalg.svd(matrix, compute_uv=False)
        coeffs = [float(v) for v in s if v > 1e-12]
        ent = 0.0
        for v in coeffs:
            p = v * v
            if p > 0:
                ent -= p * np.log2(p)
        return SchmidtResult(coefficients=coeffs, rank=len(coeffs), entanglement_entropy=float(ent))


def _basis_state(n: int, assignment: dict[int, int]) -> np.ndarray:
    idx = 0
    for q, bit in assignment.items():
        idx |= bit << (n - 1 - q)
    vec = np.zeros(2 ** n, dtype=complex)
    vec[idx] = 1.0
    return vec


def _probe_inputs(num_data_qubits: int, limit: int) -> list[int]:
    total = 1 << num_data_qubits
    if total <= limit:
        return list(range(total))
    step = total / limit
    return [int(i * step) for i in range(limit)]
