"""Offline provenance manifest creation and Ed25519 signing.

Provenance v1 records source and versioned canonical circuit digests without
including circuit source or local filesystem paths. Signatures cover the
canonical JSON encoding of every manifest field except ``signature``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import platform
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from qshield import __version__
from qshield.core.canonicalization import CANONICALIZATION_SPEC, canonical_circuit_hash_v1
from qshield.core.parsers.qasm_parser import parse_qasm

PROVENANCE_SPEC = "qshield-provenance-v1"
_SIGNATURE_DOMAIN = (PROVENANCE_SPEC + "\0").encode("ascii")
_HEX_256 = re.compile(r"^[0-9a-f]{64}$")


class ProvenanceError(ValueError):
    """Invalid manifest, key, source, or signature."""


class PrivateKeyPassphraseRequired(ProvenanceError):
    """Raised when an encrypted private key needs its passphrase."""


@dataclass(frozen=True)
class VerificationResult:
    key_id: str
    circuit_sha256: str
    source_verified: bool


def _load_crypto():
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - exercised in minimal installs
        raise ProvenanceError("install offline provenance support with: pip install 'qshield[provenance]'") from exc
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    if os.name != "nt":
        os.chmod(path, mode)


def generate_keypair(
    private_key_path: str | Path,
    public_key_path: str | Path,
    *,
    passphrase: bytes | None = None,
) -> str:
    """Generate an Ed25519 keypair; never overwrite existing key files.

    Returns the key ID (SHA-256 of the raw public key). On POSIX, the private
    key is created with mode 0600. The caller is responsible for secure backup.
    """
    private_path, public_path = Path(private_key_path), Path(public_key_path)
    if passphrase == b"":
        raise ProvenanceError("passphrase must not be empty; pass None only for explicit unencrypted keys")
    if private_path.resolve() == public_path.resolve():
        raise ProvenanceError("private and public key paths must be different")
    serialization, private_type, _ = _load_crypto()
    private_key = private_type.generate()
    encryption = (
        serialization.BestAvailableEncryption(passphrase)
        if passphrase
        else serialization.NoEncryption()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "sha256:" + hashlib.sha256(raw_public).hexdigest()

    wrote_private = False
    try:
        _write_exclusive(private_path, private_pem, 0o600)
        wrote_private = True
        _write_exclusive(public_path, public_pem, 0o644)
    except OSError as exc:
        if wrote_private:
            private_path.unlink(missing_ok=True)
        raise ProvenanceError(f"could not create key files: {exc}") from exc
    return key_id


def _source_format(raw: bytes, source_path: Path) -> str:
    match = re.search(rb"\bOPENQASM\s+([0-9]+(?:\.[0-9]+)?)\s*;", raw, re.IGNORECASE)
    if match:
        return "openqasm-" + match.group(1).decode("ascii")
    suffix = source_path.suffix.lower().lstrip(".")
    return "openqasm-" + ("3" if suffix == "qasm3" else "2")


def create_manifest(circuit_path: str | Path) -> dict[str, Any]:
    """Create an unsigned v1 manifest for an OpenQASM source file."""
    path = Path(circuit_path)
    if not path.is_file():
        raise ProvenanceError(f"circuit source is not a file: {path}")
    if path.suffix.lower() not in {".qasm", ".qasm2", ".qasm3", ".q"}:
        raise ProvenanceError("provenance v1 accepts OpenQASM files (.qasm, .qasm2, .qasm3, .q)")
    try:
        raw = path.read_bytes()
        source = raw.decode("utf-8")
        circuit = parse_qasm(source, name=path.stem)
        circuit_digest = canonical_circuit_hash_v1(circuit)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ProvenanceError(f"could not parse circuit source: {exc}") from exc

    return {
        "spec_version": PROVENANCE_SPEC,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "subject": {
            "format": _source_format(raw, path),
            "source_sha256": hashlib.sha256(raw).hexdigest(),
            "canonicalization_spec": CANONICALIZATION_SPEC,
            "circuit_sha256": circuit_digest,
        },
        "toolchain": [
            {"name": "qshield", "version": __version__},
            {"name": "python", "version": platform.python_version()},
        ],
    }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProvenanceError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def load_manifest(path: str | Path) -> dict[str, Any]:
    """Load a JSON manifest and reject ambiguous duplicate object keys."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProvenanceError(f"could not read manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise ProvenanceError("manifest root must be a JSON object")
    _validate_manifest(value, signature_optional=True)
    return value


def _validate_manifest(manifest: dict[str, Any], *, signature_optional: bool) -> None:
    if manifest.get("spec_version") != PROVENANCE_SPEC:
        raise ProvenanceError(f"unsupported provenance spec: {manifest.get('spec_version')!r}")
    created = manifest.get("created_utc")
    if not isinstance(created, str) or not created.endswith("Z"):
        raise ProvenanceError("created_utc must be a UTC timestamp ending in 'Z'")
    try:
        datetime.fromisoformat(created[:-1] + "+00:00")
    except ValueError as exc:
        raise ProvenanceError("created_utc is not a valid ISO 8601 timestamp") from exc

    subject = manifest.get("subject")
    if not isinstance(subject, dict):
        raise ProvenanceError("subject must be an object")
    subject_fields = {"format", "source_sha256", "canonicalization_spec", "circuit_sha256"}
    if set(subject) != subject_fields:
        raise ProvenanceError("subject must contain exactly format, source_sha256, canonicalization_spec, and circuit_sha256")
    if subject.get("canonicalization_spec") != CANONICALIZATION_SPEC:
        raise ProvenanceError("unsupported canonicalization spec")
    if not isinstance(subject.get("format"), str) or not subject["format"].startswith("openqasm-"):
        raise ProvenanceError("subject.format must identify an OpenQASM version")
    for field in ("source_sha256", "circuit_sha256"):
        if not isinstance(subject.get(field), str) or not _HEX_256.fullmatch(subject[field]):
            raise ProvenanceError(f"subject.{field} must be a lowercase SHA-256 hex digest")

    toolchain = manifest.get("toolchain")
    if not isinstance(toolchain, list) or not toolchain:
        raise ProvenanceError("toolchain must be a non-empty array")
    for item in toolchain:
        if not isinstance(item, dict) or set(item) != {"name", "version"}:
            raise ProvenanceError("each toolchain item must contain exactly name and version")
        if not all(isinstance(item.get(k), str) and item[k] for k in ("name", "version")):
            raise ProvenanceError("each toolchain item must contain non-empty name and version strings")

    allowed = {"spec_version", "created_utc", "subject", "toolchain", "signature"}
    unknown = set(manifest) - allowed
    if unknown:
        raise ProvenanceError(f"unknown manifest field(s): {', '.join(sorted(unknown))}")
    if "signature" not in manifest:
        if not signature_optional:
            raise ProvenanceError("manifest has no signature")
        return
    signature = manifest["signature"]
    if not isinstance(signature, dict) or set(signature) != {"algorithm", "key_id", "value"}:
        raise ProvenanceError("signature must contain exactly algorithm, key_id, and value")
    if signature.get("algorithm") != "Ed25519":
        raise ProvenanceError("signature must use Ed25519")
    key_id = signature.get("key_id")
    if not isinstance(key_id, str) or not key_id.startswith("sha256:") or not _HEX_256.fullmatch(key_id[len("sha256:"):]):
        raise ProvenanceError("signature.key_id must be sha256:<64 lowercase hex characters>")
    if not isinstance(signature.get("value"), str):
        raise ProvenanceError("signature.value must be base64 text")


def _canonical_json(value: dict[str, Any]) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProvenanceError(f"manifest cannot be canonically encoded: {exc}") from exc


def _signature_message(manifest: dict[str, Any]) -> bytes:
    body = {key: value for key, value in manifest.items() if key != "signature"}
    return _SIGNATURE_DOMAIN + _canonical_json(body)


def _load_private_key(pem: bytes, passphrase: bytes | None):
    serialization, private_type, _ = _load_crypto()
    try:
        private_key = serialization.load_pem_private_key(pem, password=passphrase)
    except TypeError as exc:
        if passphrase is None:
            raise PrivateKeyPassphraseRequired("private key is encrypted; enter its passphrase") from exc
        raise ProvenanceError("could not decrypt private key; check the passphrase") from exc
    except (ValueError, binascii.Error) as exc:
        raise ProvenanceError(f"could not load private key: {exc}") from exc
    if not isinstance(private_key, private_type):
        raise ProvenanceError("private key must be Ed25519")
    return private_key


def sign_manifest(
    manifest: dict[str, Any],
    private_key_pem: bytes,
    *,
    passphrase: bytes | None = None,
) -> dict[str, Any]:
    """Return a signed copy of an unsigned manifest."""
    _validate_manifest(manifest, signature_optional=True)
    if "signature" in manifest:
        raise ProvenanceError("manifest is already signed; remove its signature before re-signing")
    serialization, _, _ = _load_crypto()
    private_key = _load_private_key(private_key_pem, passphrase)
    raw_public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "sha256:" + hashlib.sha256(raw_public).hexdigest()
    signed = dict(manifest)
    signature = private_key.sign(_signature_message(manifest))
    signed["signature"] = {
        "algorithm": "Ed25519",
        "key_id": key_id,
        "value": base64.b64encode(signature).decode("ascii"),
    }
    _validate_manifest(signed, signature_optional=False)
    return signed


def verify_manifest(
    manifest: dict[str, Any],
    public_key_pem: bytes,
    *,
    circuit_path: str | Path | None = None,
) -> VerificationResult:
    """Verify the Ed25519 signature and, optionally, a local circuit source."""
    _validate_manifest(manifest, signature_optional=False)
    serialization, _, public_type = _load_crypto()
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError) as exc:
        raise ProvenanceError(f"could not load public key: {exc}") from exc
    if not isinstance(public_key, public_type):
        raise ProvenanceError("public key must be Ed25519")
    raw_public = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "sha256:" + hashlib.sha256(raw_public).hexdigest()
    signature = manifest["signature"]
    if signature["key_id"] != key_id:
        raise ProvenanceError("public key does not match the manifest signer key_id")
    try:
        signature_bytes = base64.b64decode(signature["value"], validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProvenanceError("signature.value is invalid base64") from exc
    try:
        public_key.verify(signature_bytes, _signature_message(manifest))
    except Exception as exc:
        # cryptography's InvalidSignature is intentionally converted into a
        # library-level error without exposing backend-specific exception text.
        raise ProvenanceError("manifest signature is invalid") from exc

    source_verified = False
    if circuit_path is not None:
        actual = create_manifest(circuit_path)
        if actual["subject"] != manifest["subject"]:
            raise ProvenanceError("circuit source does not match the signed manifest subject")
        source_verified = True
    return VerificationResult(
        key_id=key_id,
        circuit_sha256=manifest["subject"]["circuit_sha256"],
        source_verified=source_verified,
    )


def write_manifest(path: str | Path, manifest: dict[str, Any], *, overwrite: bool = False) -> None:
    """Write a manifest atomically as human-readable JSON."""
    _validate_manifest(manifest, signature_optional=True)
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not overwrite:
        raise ProvenanceError(f"refusing to overwrite existing file: {target}")
    data = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
    temp = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if not overwrite and target.exists():
            raise ProvenanceError(f"refusing to overwrite existing file: {target}")
        os.replace(temp, target)
    finally:
        temp.unlink(missing_ok=True)
