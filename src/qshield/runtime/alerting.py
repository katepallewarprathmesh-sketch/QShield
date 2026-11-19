"""Real-time anomaly alerting for the runtime interceptor.

Sinks are fanned out with best-effort delivery: a failing sink never breaks
the proxy or the request path. Severity ordering follows the rest of
QSHIELD: info < low < medium < high < critical.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sys
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Alert:
    severity: str                      # info|low|medium|high|critical
    category: str                      # e.g. "circuit.integrity", "result.mismatch", "static.finding"
    message: str
    job_id: str | None = None
    circuit_hash: str | None = None
    details: dict = field(default_factory=dict)

    def to_json(self) -> dict:
        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "job_id": self.job_id,
            "circuit_hash": self.circuit_hash,
            "details": self.details,
        }


class AlertSink:
    """Base sink. Override :meth:`emit`."""

    def emit(self, alert: Alert) -> None:  # pragma: no cover - interface
        raise NotImplementedError


class StderrSink(AlertSink):
    def emit(self, alert: Alert) -> None:
        sys.stderr.write(json.dumps(alert.to_json(), sort_keys=True) + "\n")
        sys.stderr.flush()


class JsonLinesSink(AlertSink):
    """Append one JSON object per line to ``path`` (created lazily)."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def emit(self, alert: Alert) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(alert.to_json(), sort_keys=True) + "\n")


_ZERO_HASH = "0" * 64
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


class AuditChainState(TypedDict):
    entries: int
    head_hash: str


class AuditChainError(ValueError):
    """An audit-chain file is malformed, altered, or fails its optional anchor check."""


def _canonical_json(value: dict) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False,
    ).encode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditChainError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def verify_audit_chain(path: str | Path, *, expected_head: str | None = None) -> AuditChainState:
    """Verify a local JSONL hash chain and optionally compare its head to an external anchor.

    Hash chaining detects edits, reordering, and interior deletion. Without an
    externally retained ``expected_head``, truncation of the final records
    cannot be distinguished from a shorter valid log.
    """
    audit_path = Path(path)
    if expected_head is not None and (
        not isinstance(expected_head, str) or not _HASH_RE.fullmatch(expected_head)
    ):
        raise AuditChainError("expected_head must be a lowercase SHA-256 digest")
    try:
        raw = audit_path.read_bytes()
    except OSError as exc:
        raise AuditChainError(f"could not read audit chain: {exc}") from exc

    previous = _ZERO_HASH
    count = 0
    for line_number, line in enumerate(raw.splitlines(keepends=True), 1):
        if not line.endswith(b"\n"):
            raise AuditChainError(f"line {line_number}: incomplete final record")
        try:
            record = json.loads(line[:-1].decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise AuditChainError(f"line {line_number}: invalid JSON: {exc}") from exc
        if not isinstance(record, dict) or set(record) != {"seq", "prev_hash", "event", "hash"}:
            raise AuditChainError(f"line {line_number}: unexpected record fields")
        count += 1
        if type(record["seq"]) is not int or record["seq"] != count:
            raise AuditChainError(f"line {line_number}: sequence number mismatch")
        if record["prev_hash"] != previous:
            raise AuditChainError(f"line {line_number}: previous-hash link mismatch")
        if not isinstance(record["event"], dict):
            raise AuditChainError(f"line {line_number}: event must be a JSON object")
        digest = record["hash"]
        if not isinstance(digest, str) or not _HASH_RE.fullmatch(digest):
            raise AuditChainError(f"line {line_number}: invalid record hash")
        payload = {"seq": count, "prev_hash": previous, "event": record["event"]}
        calculated = hashlib.sha256(_canonical_json(payload)).hexdigest()
        if not hmac.compare_digest(digest, calculated):
            raise AuditChainError(f"line {line_number}: record hash mismatch")
        previous = digest

    if expected_head is not None and not hmac.compare_digest(previous, expected_head):
        raise AuditChainError("audit-chain head does not match expected_head anchor")
    return {"entries": count, "head_hash": previous}


class HashChainJsonLinesSink(AlertSink):
    """Append events to a single-writer, tamper-evident JSONL chain.

    The log contains event metadata, not circuit source. Keep a copy of the
    reported head hash somewhere independent to detect tail truncation.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._sequence = 0
        self._head = _ZERO_HASH
        if self.path.exists():
            state = verify_audit_chain(self.path)
            self._sequence = int(state["entries"])
            self._head = str(state["head_hash"])

    def emit(self, alert: Alert) -> None:
        with self._lock:
            sequence = self._sequence + 1
            payload = {"seq": sequence, "prev_hash": self._head, "event": alert.to_json()}
            digest = hashlib.sha256(_canonical_json(payload)).hexdigest()
            record = {**payload, "hash": digest}
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            if os.name != "nt":
                os.fchmod(fd, 0o600)
            with os.fdopen(fd, "ab") as stream:
                stream.write(_canonical_json(record) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            self._sequence = sequence
            self._head = digest


class WebhookSink(AlertSink):
    """POST the alert as JSON to ``url`` (urllib; no extra deps)."""

    def __init__(self, url: str, timeout: float = 2.0):
        self.url = url
        self.timeout = timeout

    def emit(self, alert: Alert) -> None:
        import urllib.request

        data = json.dumps(alert.to_json()).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310 - operator-configured webhook URL
            self.url, data=data, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout):  # noqa: S310 - operator-configured URL
            pass


class AlertRouter:
    """Fan out alerts at or above ``min_severity`` to every configured sink."""

    def __init__(self, sinks: list[AlertSink] | None = None, min_severity: str = "info"):
        self.sinks: list[AlertSink] = list(sinks or [])
        if min_severity not in SEVERITY_RANK:
            raise ValueError(f"unknown severity {min_severity!r}; expected one of {sorted(SEVERITY_RANK)}")
        self.min_severity = min_severity

    @property
    def min_rank(self) -> int:
        return SEVERITY_RANK[self.min_severity]

    def emit(self, alert: Alert) -> list[str]:
        """Deliver ``alert``; returns per-sink error messages ([] on full success)."""
        if SEVERITY_RANK.get(alert.severity, 0) < self.min_rank:
            return []
        errors: list[str] = []
        for sink in self.sinks:
            try:
                sink.emit(alert)
            except Exception as exc:  # sinks must never break the proxy
                errors.append(f"{type(sink).__name__}: {exc}")
        return errors

    def emit_audit(self, event: Alert) -> list[str]:
        """Deliver to configured local audit sinks, regardless of alert threshold."""
        errors: list[str] = []
        for sink in self.sinks:
            # Decision audits are per-request and must not synchronously turn
            # an optional network webhook into the proxy's critical path.
            if isinstance(sink, WebhookSink):
                continue
            try:
                sink.emit(event)
            except Exception as exc:  # audit sinks must never break the request path
                errors.append(f"{type(sink).__name__}: {exc}")
        return errors

    def emit_all(self, alerts: list[Alert]) -> list[str]:
        errors: list[str] = []
        for alert in alerts:
            errors.extend(self.emit(alert))
        return errors
