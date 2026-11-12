"""Runtime cloud-API monitoring (Phase 4, M4.1).

Public surface:

- :class:`QShieldProxy` / :class:`ProxyConfig` — the interceptor proxy
- :func:`inspect_circuit`, :func:`canonical_circuit_hash` — integrity verification
- :func:`validate_counts` — result validation against ideal predictions
- :class:`Alert`, :class:`AlertRouter`, sinks — real-time anomaly alerting
- :func:`extract_circuits`, :func:`extract_result` — wire-shape adapters
"""

from qshield.runtime.adapters import (
    TransportCircuit,
    TransportResult,
    extract_circuits,
    extract_result,
    looks_like_qasm,
)
from qshield.runtime.alerting import (
    SEVERITY_RANK,
    Alert,
    AlertRouter,
    AlertSink,
    JsonLinesSink,
    StderrSink,
    WebhookSink,
)
from qshield.runtime.integrity import (
    HASH_HEADER,
    CommitmentResult,
    IntegrityReport,
    canonical_circuit_hash,
    inspect_circuit,
    verify_commitment,
)
from qshield.runtime.proxy import ProxyConfig, ProxyState, ProxyStats, QShieldProxy, build_alert_router
from qshield.runtime.validation import ResultVerdict, ideal_probabilities, validate_counts

__all__ = [
    "HASH_HEADER",
    "SEVERITY_RANK",
    "Alert",
    "AlertRouter",
    "AlertSink",
    "CommitmentResult",
    "IntegrityReport",
    "JsonLinesSink",
    "ProxyConfig",
    "ProxyState",
    "ProxyStats",
    "QShieldProxy",
    "ResultVerdict",
    "StderrSink",
    "TransportCircuit",
    "TransportResult",
    "WebhookSink",
    "build_alert_router",
    "canonical_circuit_hash",
    "extract_circuits",
    "extract_result",
    "ideal_probabilities",
    "inspect_circuit",
    "looks_like_qasm",
    "validate_counts",
    "verify_commitment",
]
