"""Formal verification (ZX-calculus via PyZX, optional dependency)."""

from qshield.formal.equivalence_checker import EquivalenceResult, zx_equivalence_check
from qshield.formal.property_verifier import verify_ancillas_independent
from qshield.formal.zx_calculus import FormalVerificationError, circuit_to_pyzx, pyzx_available

__all__ = [
    "EquivalenceResult",
    "FormalVerificationError",
    "circuit_to_pyzx",
    "pyzx_available",
    "verify_ancillas_independent",
    "zx_equivalence_check",
]
