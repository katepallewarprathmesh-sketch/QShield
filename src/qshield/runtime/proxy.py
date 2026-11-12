"""QSHIELD runtime interceptor proxy.

A transparent HTTP(S) *reverse* proxy that sits between a quantum-cloud
client and the cloud endpoint. Plain HTTP proxying is intentional: TLS is
terminated at the load balancer / service mesh in real deployments, so the
proxy inspects plaintext with operator consent (never on-path of traffic it
does not own).

What it does on every request:

1. reads the body (hard cap ``max_body_bytes`` → 413),
2. extracts circuits from known submission shapes (``runtime.adapters``),
3. per circuit: canonical hash, optional commitment check against the
   ``X-QShield-Expected-Hash`` header, static structural scan,
4. policy decision — ``observe`` (forward + alert) or ``enforce``
   (403 on commitment mismatch / high+ findings / unparseable circuit),
5. forwards upstream and streams the response back,
6. on count-bearing responses whose job id matches a pending submission:
   validates the counts against the ideal Born distribution
   (``runtime.validation``) and alerts on mismatch.

Overhead target (spec M4.1): < 100 ms per API call. The interceptor work is
microseconds-to-milliseconds for typical payloads; the benchmark
(``benchmarks/runtime_latency.py``) enforces this in CI.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from qshield.core.parsers.qasm_parser import parse_qasm
from qshield.runtime import adapters
from qshield.runtime.alerting import Alert, AlertRouter, JsonLinesSink, StderrSink
from qshield.runtime.integrity import HASH_HEADER, SEVERITY_RANK, inspect_circuit
from qshield.runtime.validation import validate_counts

HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade", "host",
})


@dataclass
class ProxyConfig:
    upstream: str = "http://localhost:9999"
    policy: str = "observe"                # "observe" | "enforce"
    min_severity: str = "high"             # enforce-mode block threshold
    alert_min_severity: str = "medium"     # router threshold for circuit events
    block_on_commitment_mismatch: bool = True
    max_body_bytes: int = adapters.MAX_BODY_BYTES
    upstream_timeout: float = 30.0
    validate_results: bool = True
    run_static: bool = True
    prediction_ttl_seconds: float = 900.0
    prediction_max_qubits: int = 12
    extra_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.policy not in ("observe", "enforce"):
            raise ValueError("policy must be 'observe' or 'enforce'")
        if self.min_severity not in SEVERITY_RANK:
            raise ValueError(f"min_severity must be one of {sorted(SEVERITY_RANK)}")


@dataclass
class PendingPrediction:
    circuit_hash: str
    ir: Any                     # CircuitIR
    shots: int | None
    created: float = field(default_factory=time.monotonic)


@dataclass
class ProxyStats:
    requests: int = 0
    intercepted_submissions: int = 0
    circuits_seen: int = 0
    blocked: int = 0
    alerts: int = 0
    results_validated: int = 0
    result_mismatches: int = 0
    overhead_ms_total: float = 0.0
    overhead_ms_max: float = 0.0

    def snapshot(self) -> dict:
        avg = self.overhead_ms_total / self.intercepted_submissions if self.intercepted_submissions else 0.0
        return {
            "requests": self.requests,
            "intercepted_submissions": self.intercepted_submissions,
            "circuits_seen": self.circuits_seen,
            "blocked": self.blocked,
            "alerts": self.alerts,
            "results_validated": self.results_validated,
            "result_mismatches": self.result_mismatches,
            "overhead_ms_avg": round(avg, 3),
            "overhead_ms_max": round(self.overhead_ms_max, 3),
        }


class ProxyState:
    def __init__(self) -> None:
        self.pending: dict[str, PendingPrediction] = {}   # key: job_id (or temp)
        self.lock = threading.Lock()
        self.stats = ProxyStats()

    def add_pending(self, key: str, pred: PendingPrediction) -> None:
        with self.lock:
            self._purge_locked()
            self.pending[key] = pred

    def pop_pending(self, key: str) -> PendingPrediction | None:
        with self.lock:
            self._purge_locked()
            return self.pending.pop(key, None)

    def _purge_locked(self, ttl: float = 900.0) -> None:
        now = time.monotonic()
        stale = [k for k, v in self.pending.items() if now - v.created > ttl]
        for k in stale:
            del self.pending[k]


def build_alert_router(alert_file: Path | None, webhook: str | None,
                       min_severity: str) -> AlertRouter:
    sinks: list = []
    if alert_file is not None:
        sinks.append(JsonLinesSink(alert_file))
    else:
        sinks.append(StderrSink())
    if webhook:
        from qshield.runtime.alerting import WebhookSink

        sinks.append(WebhookSink(webhook))
    return AlertRouter(sinks=sinks, min_severity=min_severity)


def make_handler(config: ProxyConfig, router: AlertRouter, state: ProxyState) -> type[BaseHTTPRequestHandler]:
    class QShieldHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "qshield-runtime/0.1"

        # ------------------------------------------------------------------
        def log_message(self, fmt: str, *args) -> None:  # quiet by default
            return

        def _send_json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _forward(self, method: str) -> None:
            t0 = time.monotonic()
            with state.lock:
                state.stats.requests += 1
            length = int(self.headers.get("Content-Length") or 0)
            if length > config.max_body_bytes:
                self._send_json(413, {"error": {"code": "qshield_body_too_large",
                                                "max_body_bytes": config.max_body_bytes}})
                return
            body = self.rfile.read(length) if length else b""

            expected_hash = self.headers.get(HASH_HEADER)
            overhead_ms = 0.0

            stored_tmp_keys: list[str] = []
            if method in ("POST", "PUT", "PATCH") and body:
                overhead_ms, blocked, stored_tmp_keys = self._inspect_submission(body, expected_hash, t0)
                if blocked is not None:
                    status, payload = blocked
                    self._send_json(status, payload)
                    return

            upstream_url = config.upstream.rstrip("/") + self.path
            fwd_headers = {
                k: v for k, v in self.headers.items()
                if k.lower() not in HOP_BY_HOP and k.lower() != "content-length"
            }
            fwd_headers["Content-Length"] = str(len(body))
            fwd_headers["X-QShield-Intercepted"] = "1"
            fwd_headers.update(config.extra_headers)
            try:
                req = urllib.request.Request(upstream_url, data=body if body else None,  # noqa: S310 - operator-configured upstream
                                             method=method, headers=fwd_headers)
                with urllib.request.urlopen(req, timeout=config.upstream_timeout) as resp:  # noqa: S310 - operator-configured upstream
                    status_code = resp.status
                    resp_headers = dict(resp.headers.items())
                    resp_body = resp.read()
            except urllib.error.HTTPError as exc:
                # upstream answered with an error status — that is a valid response
                status_code = exc.code
                resp_headers = dict(exc.headers.items()) if exc.headers else {}
                resp_body = exc.read()
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                self._send_json(502, {"error": {"code": "qshield_upstream_unavailable",
                                                "detail": str(exc)}})
                return

            if stored_tmp_keys:
                job_id = adapters.extract_job_id(resp_body)
                if job_id:
                    with state.lock:
                        for key in stored_tmp_keys:
                            pred = state.pending.pop(key, None)
                            if pred is not None:
                                state.pending[job_id] = pred
            result_hdr = self._maybe_validate_result(resp_body, self.path)
            self._relay_response(status_code, resp_headers, resp_body, result_hdr, overhead_ms)

        # ------------------------------------------------------------------
        def _inspect_submission(self, body: bytes, expected_hash: str | None, t0: float):
            """Returns (overhead_ms, blocked|None, stored_tmp_keys)."""
            inspect_start = time.monotonic()
            stored_tmp_keys: list[str] = []
            try:
                circuits = adapters.extract_circuits(body, self.headers.get("Content-Type", ""))
            except ValueError as exc:
                router.emit(Alert(severity="high", category="body.oversize", message=str(exc)))
                return 0.0, (413, {"error": {"code": "qshield_body_too_large", "detail": str(exc)}}), stored_tmp_keys

            if not circuits:
                return 0.0, None, stored_tmp_keys

            with state.lock:
                state.stats.intercepted_submissions += 1
                state.stats.circuits_seen += len(circuits)

            blocked: tuple[int, dict] | None = None
            alerts: list[Alert] = []
            for idx, tc in enumerate(circuits):
                circuit_hash = None
                try:
                    ir = parse_qasm(tc.qasm, name=f"wire{idx}")
                except Exception as exc:  # parser must not 500 the proxy
                    alerts.append(Alert(severity="medium", category="circuit.parse_failure",
                                        message=f"could not parse intercepted circuit #{idx}: {exc}"))
                    if config.policy == "enforce":
                        blocked = (400, {"error": {"code": "qshield_unverifiable",
                                                   "detail": f"circuit #{idx} failed to parse: {exc}"}})
                        break
                    continue

                report = inspect_circuit(ir, expected_hash=expected_hash if len(circuits) == 1 else None,
                                         run_static=config.run_static)
                circuit_hash = report.circuit_hash

                if report.commitment.ok is False:
                    alerts.append(Alert(
                        severity="high", category="circuit.integrity",
                        message="intercepted circuit does not match the declared commitment hash",
                        circuit_hash=circuit_hash,
                        details={"expected": report.commitment.expected, "actual": circuit_hash,
                                 "backend": tc.backend, "shape": tc.shape, "idx": idx},
                    ))
                    if config.policy == "enforce" and config.block_on_commitment_mismatch:
                        blocked = (403, {"error": {
                            "code": "qshield_commitment_mismatch",
                            "expected": report.commitment.expected,
                            "actual": circuit_hash,
                        }})
                        break

                for finding in report.findings_at_least(config.min_severity):
                    alerts.append(Alert(
                        severity=finding.severity, category="static.finding",
                        message=f"{finding.threat_type}: {finding.title}",
                        circuit_hash=circuit_hash,
                        details={"threat_type": finding.threat_type,
                                 "confidence": finding.confidence,
                                 "analysis_type": finding.analysis_type},
                    ))
                if (config.policy == "enforce"
                        and report.findings_at_least(config.min_severity)):
                    worst = report.max_severity or config.min_severity
                    blocked = (403, {"error": {
                        "code": "qshield_static_threshold",
                        "min_severity": config.min_severity,
                        "max_observed": worst,
                        "findings": len(report.findings),
                    }})
                    break

                if config.validate_results and tc.shots:
                    key = tc.job_id or f"tmp-{id(tc):x}"
                    if not tc.job_id:
                        stored_tmp_keys.append(key)
                    state.add_pending(key, PendingPrediction(circuit_hash=circuit_hash, ir=ir,
                                                             shots=tc.shots))

            overhead_ms = (time.monotonic() - inspect_start) * 1000.0
            with state.lock:
                state.stats.overhead_ms_total += overhead_ms
                state.stats.overhead_ms_max = max(state.stats.overhead_ms_max, overhead_ms)

            if alerts:
                with state.lock:
                    state.stats.alerts += len(alerts)
                router.emit_all(alerts)
            if blocked is not None:
                with state.lock:
                    state.stats.blocked += 1
            return overhead_ms, blocked, stored_tmp_keys

        # ------------------------------------------------------------------
        def _maybe_validate_result(self, resp_body: bytes, path: str) -> str | None:
            """Validate a counts-bearing response; returns the X-QShield-Result value."""
            if not config.validate_results:
                return None
            result = adapters.extract_result(resp_body)
            if result is None:
                return None
            job_id = result.job_id
            if not job_id:
                tail = path.rstrip("/").rsplit("/", 1)[-1]
                job_id = tail if tail else None
            pred = state.pop_pending(job_id) if job_id else None
            if pred is None:
                return "unvalidated"
            verdict = validate_counts(pred.ir, result.counts,
                                      max_qubits=config.prediction_max_qubits)
            with state.lock:
                state.stats.results_validated += 1
                if verdict.status == "mismatch":
                    state.stats.result_mismatches += 1
                    state.stats.alerts += 1
            if verdict.status == "mismatch":
                router.emit(Alert(
                    severity="high", category="result.mismatch",
                    message=verdict.reason,
                    job_id=job_id, circuit_hash=pred.circuit_hash,
                    details={"chi2": verdict.chi2, "p_value": verdict.p_value,
                             "bit_order": verdict.bit_order, "shots": verdict.shots},
                ))
            return verdict.status

        # ------------------------------------------------------------------
        def _relay_response(self, status_code: int, resp_headers: dict, resp_body: bytes,
                            result_hdr: str | None, overhead_ms: float) -> None:
            self.send_response(status_code)
            for k, v in resp_headers.items():
                lk = k.lower()
                if lk in HOP_BY_HOP or lk in ("content-length",):
                    continue
                try:
                    self.send_header(k, v)
                except Exception:  # noqa: S112 - header relay is best-effort; body still forwarded
                    continue
            self.send_header("Content-Length", str(len(resp_body)))
            self.send_header("Connection", "close")
            self.send_header("X-QShield-Intercepted", "1")
            self.send_header("X-QShield-Overhead-Ms", f"{overhead_ms:.3f}")
            if result_hdr:
                self.send_header("X-QShield-Result", result_hdr)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(resp_body)

        # HTTP verbs ---------------------------------------------------------
        def do_GET(self) -> None:
            self._forward("GET")

        def do_HEAD(self) -> None:
            self._forward("HEAD")

        def do_POST(self) -> None:
            self._forward("POST")

        def do_PUT(self) -> None:
            self._forward("PUT")

        def do_PATCH(self) -> None:
            self._forward("PATCH")

        def do_DELETE(self) -> None:
            self._forward("DELETE")

        def do_OPTIONS(self) -> None:
            self._forward("OPTIONS")

    return QShieldHandler


class QShieldProxy:
    """Threaded reverse proxy. ``start()`` spawns serving; ``stop()`` shuts down."""

    def __init__(self, config: ProxyConfig, alert_router: AlertRouter | None = None,
                 *, host: str = "127.0.0.1", port: int = 0):
        self.config = config
        self.router = alert_router or build_alert_router(None, None, config.alert_min_severity)
        self.state = ProxyState()
        self._server = ThreadingHTTPServer((host, port),
                                           make_handler(config, self.router, self.state))
        self._server.daemon_threads = True
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[0], self._server.server_address[1]
        return str(host), int(port)

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def start(self) -> QShieldProxy:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2.0)

    def stats_snapshot(self) -> dict:
        return self.state.stats.snapshot()
