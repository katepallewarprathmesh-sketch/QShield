"""YAML-based threat signatures: loader + matching engine."""

from qshield.signatures.community import (
    community_signatures,
    installed_community_signatures,
    preferred_community_signatures,
    verify_pack,
)
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
    "Signature",
    "SignatureError",
    "SignatureMatcher",
    "builtin_signatures",
    "community_signatures",
    "installed_community_signatures",
    "load_directory",
    "load_signature",
    "preferred_community_signatures",
    "validate_signature",
    "verify_pack",
]
