"""Real-time anomaly alerting for the runtime interceptor.

Sinks are fanned out with best-effort delivery: a failing sink never breaks
the proxy or the request path. Severity ordering follows the rest of
QSHIELD: info < low < medium < high < critical.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

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

    def emit_all(self, alerts: list[Alert]) -> list[str]:
        errors: list[str] = []
        for alert in alerts:
            errors.extend(self.emit(alert))
        return errors
