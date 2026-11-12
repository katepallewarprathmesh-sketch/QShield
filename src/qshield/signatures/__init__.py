"""YAML-based threat signatures: loader + matching engine."""

from qshield.signatures.loader import (
    Signature,
    SignatureError,
    builtin_signatures,
    load_directory,
    load_signature,
    validate_signature,
)
from qshield.signatures.matcher import SignatureMatcher

__all__ = [
    "Signature", "SignatureError", "SignatureMatcher",
    "builtin_signatures", "load_directory", "load_signature", "validate_signature",
]
