"""Static analysis: runs without executing the circuit."""

from qshield.static.dependency_scanner import DependencyReport, DependencyScanner, audit_package
from qshield.static.randomized_equivalence import (
    RandomizedReport,
    RandomizedVerificationError,
    randomized_equivalence,
)
from qshield.static.structural_analyzer import StructuralAnalyzer
from qshield.static.unitary_verifier import SchmidtResult, UnitaryVerifier, VerificationResult

__all__ = [
    "DependencyReport",
    "DependencyScanner",
    "RandomizedReport",
    "RandomizedVerificationError",
    "SchmidtResult",
    "StructuralAnalyzer",
    "UnitaryVerifier",
    "VerificationResult",
    "audit_package",
    "randomized_equivalence",
]
