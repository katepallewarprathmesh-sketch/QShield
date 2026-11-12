"""Circuit equivalence checking via ZX-calculus (PyZX).

Two strategies, applied in order:

1. ``zx_full_reduce``: compose ``A`` with ``adjoint(B)`` and reduce the
   diagram to the identity.  A successful reduction is a *proof* of
   equivalence (sound, incomplete).
2. ``tensor_exact``: build the full tensors and compare.  Exact (up to
   numerical precision), exponential in circuit size — practical to ~12
   qubits.
"""

from __future__ import annotations

from dataclasses import dataclass

from qshield.core.circuit_ir import CircuitIR
from qshield.formal.zx_calculus import FormalVerificationError, circuit_to_pyzx, pyzx_available


@dataclass
class EquivalenceResult:
    equivalent: bool | None  # None when undecidable in available backends
    method: str                 # "zx_calculus" | "tensor_exact" | "unavailable" | "error"
    message: str

    def __bool__(self) -> bool:
        return bool(self.equivalent)


def zx_equivalence_check(circuit_a: CircuitIR, circuit_b: CircuitIR,
                         tensor_max_qubits: int = 10) -> EquivalenceResult:
    if not pyzx_available():
        return EquivalenceResult(
            None, "unavailable",
            "pyzx is not installed; pip install 'qshield[formal]' to enable ZX-calculus verification",
        )
    if circuit_a.num_qubits != circuit_b.num_qubits:
        return EquivalenceResult(
            False, "zx_calculus",
            f"qubit count mismatch: {circuit_a.num_qubits} vs {circuit_b.num_qubits}",
        )
    try:
        ca = circuit_to_pyzx(circuit_a)
        cb = circuit_to_pyzx(circuit_b)
    except FormalVerificationError as exc:
        return EquivalenceResult(None, "error", str(exc))

    try:
        verdict = ca.verify_equality(cb)
    except NotImplementedError:
        verdict = None
    except Exception as exc:  # pyzx internal failure must not crash scans
        return EquivalenceResult(None, "error", f"pyzx verification failed: {exc}")

    if verdict:
        return EquivalenceResult(True, "zx_calculus",
                                 "circuits reduce to the same ZX diagram (proven equivalent)")

    # ZX simplification is incomplete. The exact tensor fallback is
    # exponential (pyzx.compare_tensors materialises ~2^n x 2^n tensors):
    # at 16+ qubits that is >10^9 complex entries and will OOM the process,
    # so it only runs within a small qubit budget — above that we report
    # "undecidable" instead of dying.
    n = circuit_a.num_qubits
    if n > tensor_max_qubits:
        return EquivalenceResult(
            None, "undecidable",
            f"ZX simplification inconclusive and exact tensor comparison is limited to "
            f"{tensor_max_qubits} qubits (got {n}); cannot decide — do not read this as "
            "equivalence",
        )
    try:
        import pyzx
        same = pyzx.compare_tensors(ca, cb)
        if same:
            return EquivalenceResult(
                True, "tensor_exact",
                "ZX reduction inconclusive but exact tensor comparison shows equality "
                "(ZX-calculus simplification is incomplete)",
            )
        return EquivalenceResult(False, "tensor_exact",
                                 "circuits differ (exact tensor comparison)")
    except Exception as exc:
        return EquivalenceResult(None, "error", f"tensor comparison failed: {exc}")
