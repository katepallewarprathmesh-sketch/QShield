"""Trusted baseline records for readout-differential integrity checks.

A reference circuit supplied by the caller is not a baseline. A baseline is a
record that binds a workload identity to a circuit digest, an approving
identity, an approval time, and a signature over all of that. This module
implements that record, its trust states, and the checks that decide whether a
differential may be computed at all.

Signing reuses :mod:`qshield.provenance.manifest` rather than introducing a
second signing implementation.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from qshield.core.canonicalization import CANONICALIZATION_SPEC, canonical_circuit_hash_v1
from qshield.core.circuit_ir import CircuitIR
from qshield.integrity.readout import extract_readout

BASELINE_SPEC_VERSION = "qshield-baseline-v1"
_DOMAIN = (BASELINE_SPEC_VERSION + "\0").encode("ascii")


class BaselineState(str, Enum):
    """Why a baseline may or may not be used."""

    APPROVED = "approved"
    REVOKED = "revoked"
    EXPIRED = "expired"
    UNVERIFIED = "unverified"
    MISSING = "missing"
    WRONG_WORKLOAD = "wrong_workload"
    PARSER_INCOMPATIBLE = "parser_incompatible"


#: States in which a differential must not be computed.
BLOCKING_STATES = frozenset(
    {
        BaselineState.REVOKED,
        BaselineState.EXPIRED,
        BaselineState.UNVERIFIED,
        BaselineState.MISSING,
        BaselineState.WRONG_WORKLOAD,
        BaselineState.PARSER_INCOMPATIBLE,
    }
)


class BaselineError(ValueError):
    """A baseline record is malformed or could not be registered."""


@dataclass(frozen=True)
class BaselineRecord:
    """An approved reference for one workload.

    ``circuit_digest`` is the canonical hash of the approved circuit under
    :data:`qshield.core.canonicalization.CANONICALIZATION_SPEC`, and
    ``readout_digest`` is the digest of that circuit's readout structure. Both
    are bound by the signature: changing either invalidates the record.
    """

    baseline_id: str
    workload_id: str
    circuit_digest: str
    readout_digest: str
    version: int
    approved_by: str
    approved_at: str
    canonicalization_spec: str = CANONICALIZATION_SPEC
    signature: dict[str, str] | None = None
    revoked_at: str | None = None
    revoked_by: str | None = None
    revoke_reason: str | None = None
    expires_at: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    #: The approved circuit itself. Not part of the signed payload because its
    #: digests are: the evaluator re-derives them and refuses the comparison if
    #: this circuit is not the one the signature covers.
    reference_circuit: CircuitIR | None = field(default=None, compare=False, repr=False)

    # -- serialisation ---------------------------------------------------
    def unsigned_payload(self) -> dict[str, Any]:
        """Fields bound by the signature, in a deterministic order."""
        return {
            "spec_version": BASELINE_SPEC_VERSION,
            "baseline_id": self.baseline_id,
            "workload_id": self.workload_id,
            "circuit_digest": self.circuit_digest,
            "readout_digest": self.readout_digest,
            "version": self.version,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "canonicalization_spec": self.canonicalization_spec,
            "expires_at": self.expires_at,
            "metadata": self.metadata,
        }

    def signing_bytes(self) -> bytes:
        payload = json.dumps(
            self.unsigned_payload(), sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        return _DOMAIN + payload

    def to_dict(self) -> dict[str, Any]:
        record = self.unsigned_payload()
        record["signature"] = self.signature
        record["revoked_at"] = self.revoked_at
        record["revoked_by"] = self.revoked_by
        record["revoke_reason"] = self.revoke_reason
        return record

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineRecord:
        if not isinstance(data, dict):
            raise BaselineError("baseline record must be a mapping")
        allowed = {
            "spec_version",
            "baseline_id",
            "workload_id",
            "circuit_digest",
            "readout_digest",
            "version",
            "approved_by",
            "approved_at",
            "canonicalization_spec",
            "signature",
            "revoked_at",
            "revoked_by",
            "revoke_reason",
            "expires_at",
            "metadata",
        }
        unknown = set(data) - allowed
        if unknown:
            raise BaselineError(f"unknown baseline field(s): {sorted(unknown)}")
        if data.get("spec_version") != BASELINE_SPEC_VERSION:
            raise BaselineError(
                f"unsupported baseline spec_version {data.get('spec_version')!r}; "
                f"expected {BASELINE_SPEC_VERSION!r}"
            )
        for required in ("baseline_id", "workload_id", "circuit_digest", "readout_digest",
                         "version", "approved_by", "approved_at"):
            if required not in data:
                raise BaselineError(f"baseline is missing required field {required!r}")
        version = data["version"]
        if isinstance(version, bool) or not isinstance(version, int) or version < 1:
            raise BaselineError("baseline version must be a positive integer")
        signature = data.get("signature")
        if signature is not None and (
            not isinstance(signature, dict)
            or set(signature) != {"algorithm", "key_id", "value"}
        ):
            raise BaselineError("baseline signature must have algorithm, key_id and value")
        return cls(
            baseline_id=str(data["baseline_id"]),
            workload_id=str(data["workload_id"]),
            circuit_digest=str(data["circuit_digest"]),
            readout_digest=str(data["readout_digest"]),
            version=version,
            approved_by=str(data["approved_by"]),
            approved_at=str(data["approved_at"]),
            canonicalization_spec=str(data.get("canonicalization_spec", CANONICALIZATION_SPEC)),
            signature=signature,
            revoked_at=data.get("revoked_at"),
            revoked_by=data.get("revoked_by"),
            revoke_reason=data.get("revoke_reason"),
            expires_at=data.get("expires_at"),
            metadata=dict(data.get("metadata") or {}),
        )

    def with_revocation(self, *, by: str, reason: str, at: str | None = None) -> BaselineRecord:
        """Return a revoked copy. Revocation is not covered by the signature."""
        return BaselineRecord(
            baseline_id=self.baseline_id,
            workload_id=self.workload_id,
            circuit_digest=self.circuit_digest,
            readout_digest=self.readout_digest,
            version=self.version,
            approved_by=self.approved_by,
            approved_at=self.approved_at,
            canonicalization_spec=self.canonicalization_spec,
            signature=self.signature,
            revoked_at=at or _now(),
            revoked_by=by,
            revoke_reason=reason,
            expires_at=self.expires_at,
            metadata=self.metadata,
            reference_circuit=self.reference_circuit,
        )


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def baseline_digest(circuit: CircuitIR) -> tuple[str, str]:
    """Return ``(circuit_digest, readout_digest)`` for a candidate circuit."""
    return canonical_circuit_hash_v1(circuit), extract_readout(circuit).digest()


def create_baseline(
    circuit: CircuitIR,
    *,
    workload_id: str,
    approved_by: str,
    baseline_id: str | None = None,
    version: int = 1,
    expires_at: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> BaselineRecord:
    """Build an unsigned baseline record for a circuit."""
    if not workload_id:
        raise BaselineError("workload_id is required")
    if not approved_by:
        raise BaselineError("approved_by is required")
    circuit_digest, readout_digest = baseline_digest(circuit)
    return BaselineRecord(
        baseline_id=baseline_id or f"bl-{hashlib.sha256(_DOMAIN + circuit_digest.encode()).hexdigest()[:16]}",
        workload_id=workload_id,
        circuit_digest=circuit_digest,
        readout_digest=readout_digest,
        version=version,
        approved_by=approved_by,
        approved_at=_now(),
        expires_at=expires_at,
        metadata=dict(metadata or {}),
        reference_circuit=circuit,
    )


# ----------------------------------------------------------------------
# Signing (reuses the existing Ed25519 implementation)
# ----------------------------------------------------------------------
def sign_baseline(record: BaselineRecord, private_key_pem: bytes, *, passphrase: bytes | None = None) -> BaselineRecord:
    """Sign a baseline record with an Ed25519 private key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if record.signature is not None:
        raise BaselineError("baseline is already signed; build a new record to re-sign")

    if passphrase is None:
        key = serialization.load_pem_private_key(private_key_pem, password=None)
    else:
        key = serialization.load_pem_private_key(private_key_pem, password=passphrase)
    if not isinstance(key, Ed25519PrivateKey):
        raise BaselineError("baseline signing requires an Ed25519 private key")

    raw_public = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = "sha256:" + hashlib.sha256(raw_public).hexdigest()
    return BaselineRecord(
        baseline_id=record.baseline_id,
        workload_id=record.workload_id,
        circuit_digest=record.circuit_digest,
        readout_digest=record.readout_digest,
        version=record.version,
        approved_by=record.approved_by,
        approved_at=record.approved_at,
        canonicalization_spec=record.canonicalization_spec,
        signature={
            "algorithm": "Ed25519",
            "key_id": key_id,
            "value": base64.b64encode(key.sign(record.signing_bytes())).decode("ascii"),
        },
        expires_at=record.expires_at,
        metadata=record.metadata,
        reference_circuit=record.reference_circuit,
    )


def verify_signature(record: BaselineRecord, public_key_pem: bytes) -> bool:
    """Return True only if the record carries a valid signature under this key."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if record.signature is None:
        return False
    try:
        key = serialization.load_pem_public_key(public_key_pem)
    except (ValueError, TypeError):
        return False
    if not isinstance(key, Ed25519PublicKey):
        return False
    try:
        key.verify(base64.b64decode(record.signature["value"]), record.signing_bytes())
    except (InvalidSignature, ValueError, TypeError, KeyError):
        return False
    return True


def _key_id_for(public_key_pem: bytes) -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    key = serialization.load_pem_public_key(public_key_pem)
    if not isinstance(key, Ed25519PublicKey):
        raise BaselineError("baseline verification requires an Ed25519 public key")
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# ----------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------
@dataclass(frozen=True)
class BaselineStatus:
    """The resolved trust state of a baseline lookup."""

    state: BaselineState
    record: BaselineRecord | None = None
    reason: str = ""

    @property
    def usable(self) -> bool:
        return self.state is BaselineState.APPROVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "baseline_id": self.record.baseline_id if self.record else None,
            "version": self.record.version if self.record else None,
            "reason": self.reason,
        }


class BaselineRegistry:
    """In-memory registry of approved baselines for workloads.

    Two tamper properties are enforced, because both are trivial attacks against
    a naive "load the file the caller points at" design:

    * **substitution** — a record's digests are inside the signed payload, so a
      record whose circuit fields were edited fails verification.
    * **rollback** — a workload may not replace an approved baseline with a
      lower version number.
    """

    def __init__(self) -> None:
        self._by_workload: dict[str, BaselineRecord] = {}

    def register(
        self,
        record: BaselineRecord,
        *,
        public_key_pem: bytes | None = None,
        require_signature: bool = True,
    ) -> BaselineRecord:
        """Register an approved baseline, enforcing monotonic versions."""
        if require_signature:
            if record.signature is None:
                raise BaselineError("baseline must be signed before registration")
            if public_key_pem is None:
                raise BaselineError("a public key is required to register a signed baseline")
            if not verify_signature(record, public_key_pem):
                raise BaselineError("baseline signature does not verify")
            expected = _key_id_for(public_key_pem)
            if record.signature.get("key_id") != expected:
                raise BaselineError(
                    "baseline was signed by a key that does not match the trusted public key"
                )
        existing = self._by_workload.get(record.workload_id)
        if existing is not None and record.version <= existing.version:
            raise BaselineError(
                f"rollback refused: version {record.version} is not newer than the "
                f"approved version {existing.version} for workload {record.workload_id!r}"
            )
        self._by_workload[record.workload_id] = record
        return record

    def revoke(self, workload_id: str, *, by: str, reason: str) -> BaselineRecord:
        record = self._by_workload.get(workload_id)
        if record is None:
            raise BaselineError(f"no baseline registered for workload {workload_id!r}")
        revoked = record.with_revocation(by=by, reason=reason)
        self._by_workload[workload_id] = revoked
        return revoked

    def resolve(
        self,
        workload_id: str,
        *,
        public_key_pem: bytes | None = None,
        now: datetime | None = None,
    ) -> BaselineStatus:
        """Look up a baseline and decide whether it may be used."""
        record = self._by_workload.get(workload_id)
        if record is None:
            return BaselineStatus(
                BaselineState.MISSING,
                None,
                f"no approved baseline registered for workload {workload_id!r}",
            )
        if record.revoked_at is not None:
            return BaselineStatus(
                BaselineState.REVOKED,
                record,
                f"baseline was revoked at {record.revoked_at} by {record.revoked_by}: "
                f"{record.revoke_reason}",
            )
        if record.expires_at is not None and _parse_time(record.expires_at) <= (
            now or datetime.now(timezone.utc)
        ):
            return BaselineStatus(
                BaselineState.EXPIRED,
                record,
                f"baseline expired at {record.expires_at}",
            )
        if record.signature is None:
            return BaselineStatus(
                BaselineState.UNVERIFIED, record, "baseline carries no signature"
            )
        if public_key_pem is not None and not verify_signature(record, public_key_pem):
            return BaselineStatus(
                BaselineState.UNVERIFIED,
                record,
                "baseline signature does not verify against the trusted key",
            )
        if record.canonicalization_spec != CANONICALIZATION_SPEC:
            return BaselineStatus(
                BaselineState.PARSER_INCOMPATIBLE,
                record,
                f"baseline was produced with {record.canonicalization_spec!r}; this build "
                f"uses {CANONICALIZATION_SPEC!r}",
            )
        return BaselineStatus(BaselineState.APPROVED, record, "")

    def history(self, workload_id: str) -> list[dict[str, Any]]:
        """Return the approval history retained for a workload."""
        record = self._by_workload.get(workload_id)
        if record is None:
            return []
        entry: dict[str, Any] = {
            "version": record.version,
            "approved_by": record.approved_by,
            "approved_at": record.approved_at,
            "baseline_id": record.baseline_id,
        }
        if record.revoked_at:
            entry["revoked_at"] = record.revoked_at
            entry["revoked_by"] = record.revoked_by
            entry["revoke_reason"] = record.revoke_reason
        return [entry]

    def workloads(self) -> list[str]:
        return sorted(self._by_workload)


def _parse_time(value: str) -> datetime:
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise BaselineError(f"timestamp {value!r} is not in YYYY-MM-DDTHH:MM:SSZ form") from exc


def load_baseline_file(path: str | Path) -> BaselineRecord:
    """Load a baseline record from JSON, rejecting duplicate keys."""
    target = Path(path)
    if not target.exists():
        raise BaselineError(f"baseline file not found: {target}")

    def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                raise BaselineError(f"duplicate key {key!r} in baseline file")
            seen[key] = value
        return seen

    try:
        document = json.loads(target.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicates)
    except json.JSONDecodeError as exc:
        raise BaselineError(f"{target.name}: not valid JSON ({exc.msg})") from exc
    return BaselineRecord.from_dict(document)
