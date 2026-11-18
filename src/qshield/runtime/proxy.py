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

import hmac
import ipaddress
import json
import math
import os
import re
import ssl
import stat
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from qshield.core.parsers.qasm_parser import parse_qasm
from qshield.runtime import adapters
from qshield.runtime.alerting import Alert, AlertRouter, JsonLinesSink, StderrSink
from qshield.runtime.integrity import HASH_HEADER, SEVERITY_RANK, inspect_circuit
from qshield.runtime.validation import validate_counts

HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade", "host",
})
AUTH_SCOPES = frozenset({"proxy:read", "proxy:submit", "proxy:manage", "proxy:admin"})
BEARER_TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9._~+/-]+=*$")


@dataclass
class ProxyConfig:
    upstream: str = "http://localhost:9999"
    policy: str = "observe"                # "observe" | "enforce"
    min_severity: str = "high"             # enforce-mode block threshold
    alert_min_severity: str = "medium"     # router threshold for circuit events
    failure_mode: str | None = None          # "open" | "closed"; defaults by policy mode
    policy_version: str = "local-unversioned"
    auth_tokens: dict[str, tuple[str, ...]] = field(default_factory=dict, repr=False)
    max_workers: int = 32
    request_queue_size: int = 128
    block_on_commitment_mismatch: bool = True
    max_body_bytes: int = adapters.MAX_BODY_BYTES
    max_response_bytes: int = adapters.MAX_BODY_BYTES
    upstream_timeout: float = 30.0
    validate_results: bool = True
    run_static: bool = True
    prediction_ttl_seconds: float = 900.0
    prediction_max_qubits: int = 12
    extra_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.policy not in ("observe", "enforce"):
            raise ValueError("policy must be 'observe' or 'enforce'")
        if self.failure_mode is None:
            # Preserve the existing mode's default behavior, but make the
            # failure policy explicit and inspectable for each deployment.
            self.failure_mode = "open" if self.policy == "observe" else "closed"
        if self.failure_mode not in ("open", "closed"):
            raise ValueError("failure_mode must be 'open' or 'closed'")
        if self.min_severity not in SEVERITY_RANK:
            raise ValueError(f"min_severity must be one of {sorted(SEVERITY_RANK)}")
        if self.alert_min_severity not in SEVERITY_RANK:
            raise ValueError(f"alert_min_severity must be one of {sorted(SEVERITY_RANK)}")
        if not isinstance(self.policy_version, str) or not self.policy_version.strip() or len(self.policy_version) > 128:
            raise ValueError("policy_version must be a non-empty string of at most 128 characters")
        if not isinstance(self.auth_tokens, dict):
            raise TypeError("auth_tokens must map bearer-token strings to scope lists")
        normalized_tokens: dict[str, tuple[str, ...]] = {}
        for token, scopes in self.auth_tokens.items():
            if not isinstance(token, str) or not 32 <= len(token) <= 8_192 or not BEARER_TOKEN_PATTERN.fullmatch(token):
                raise ValueError("bearer tokens must be 32 to 8192 characters using the HTTP bearer-token alphabet")
            if not isinstance(scopes, (list, tuple, set, frozenset)) or not scopes:
                raise ValueError("each bearer token must have at least one scope")
            if any(not isinstance(scope, str) or scope not in AUTH_SCOPES for scope in scopes):
                raise ValueError(f"bearer scopes must be drawn from {sorted(AUTH_SCOPES)}")
            normalized_tokens[token] = tuple(sorted(set(scopes)))
        self.auth_tokens = normalized_tokens
        if type(self.max_workers) is not int or not 1 <= self.max_workers <= 1024:
            raise ValueError("max_workers must be an integer from 1 to 1024")
        if type(self.request_queue_size) is not int or not 1 <= self.request_queue_size <= 65535:
            raise ValueError("request_queue_size must be an integer from 1 to 65535")
        if type(self.max_body_bytes) is not int or self.max_body_bytes < 1:
            raise ValueError("max_body_bytes must be a positive integer")
        if type(self.max_response_bytes) is not int or self.max_response_bytes < 1:
            raise ValueError("max_response_bytes must be a positive integer")
        if isinstance(self.upstream_timeout, bool) or not isinstance(self.upstream_timeout, (int, float)):
            raise TypeError("upstream_timeout must be a finite number greater than zero")
        if not math.isfinite(self.upstream_timeout) or self.upstream_timeout <= 0:
            raise ValueError("upstream_timeout must be a finite number greater than zero")
        if not isinstance(self.upstream, str):
            raise TypeError("upstream must be a URL string")
        parsed_upstream = urlsplit(self.upstream)
        if parsed_upstream.scheme not in {"http", "https"} or not parsed_upstream.hostname:
            raise ValueError("upstream must be an absolute http:// or https:// URL with a hostname")
        if parsed_upstream.username is not None or parsed_upstream.password is not None:
            raise ValueError("upstream URL must not embed credentials")
        if parsed_upstream.fragment or parsed_upstream.query:
            raise ValueError("upstream URL must not include a query or fragment")
        if not isinstance(self.extra_headers, dict):
            raise TypeError("extra_headers must be a dictionary of header names and string values")
        header_name = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
        reserved_headers = HOP_BY_HOP | {
            "content-length", "x-qshield-intercepted", "x-qshield-overhead-ms",
            "x-qshield-result", "x-qshield-decision",
        }
        for key, value in self.extra_headers.items():
            if not isinstance(key, str) or not header_name.fullmatch(key):
                raise ValueError("extra header names must be valid HTTP tokens")
            if key.lower() in reserved_headers:
                raise ValueError(f"extra header {key!r} is reserved by the proxy")
            if not isinstance(value, str) or "\r" in value or "\n" in value:
                raise ValueError(f"extra header {key!r} must have a single-line string value")


def load_bearer_tokens(path: str | Path) -> dict[str, tuple[str, ...]]:
    """Load scoped bearer tokens from a local JSON file with restrictive permissions."""
    token_path = Path(path)
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(token_path, flags)
        try:
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode):
                raise ValueError("token file must be a regular file")
            if file_stat.st_size > 64 * 1024:
                raise ValueError("token file exceeds the 64 KiB limit")
            if os.name == "posix" and stat.S_IMODE(file_stat.st_mode) & 0o077:
                raise ValueError("token file permissions must be 0600 or stricter")
            with os.fdopen(fd, "rb") as token_stream:
                fd = -1
                raw = token_stream.read(64 * 1024 + 1)
        finally:
            if fd >= 0:
                os.close(fd)
    except OSError as exc:
        raise ValueError(f"could not safely read token file: {exc}") from exc
    if len(raw) > 64 * 1024:
        raise ValueError("token file exceeds the 64 KiB limit")
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid token file JSON: {exc}") from exc
    if not isinstance(data, dict) or set(data) != {"tokens"} or not isinstance(data["tokens"], list):
        raise ValueError("token file must contain exactly a 'tokens' array")
    tokens: dict[str, tuple[str, ...]] = {}
    for index, record in enumerate(data["tokens"]):
        if not isinstance(record, dict) or set(record) != {"token", "scopes"}:
            raise ValueError(f"token entry {index} must contain exactly token and scopes")
        token, scopes = record["token"], record["scopes"]
        if not isinstance(token, str) or len(token) < 32 or not BEARER_TOKEN_PATTERN.fullmatch(token):
            raise ValueError(f"token entry {index} must have a valid bearer token of at least 32 characters")
        if token in tokens:
            raise ValueError(f"duplicate bearer token at entry {index}")
        if not isinstance(scopes, list) or not scopes or any(
            not isinstance(scope, str) or scope not in AUTH_SCOPES for scope in scopes
        ):
            raise ValueError(f"token entry {index} has invalid scopes; expected values from {sorted(AUTH_SCOPES)}")
        tokens[token] = tuple(scopes)
    if not tokens:
        raise ValueError("token file must define at least one bearer token")
    # Reuse runtime validation, including line-break and token-scope checks.
    return ProxyConfig(auth_tokens=tokens).auth_tokens


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
    overloaded: int = 0
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
            "overloaded": self.overloaded,
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


def _required_scope(method: str) -> str:
    if method in {"GET", "HEAD", "OPTIONS"}:
        return "proxy:read"
    if method == "DELETE":
        return "proxy:manage"
    return "proxy:submit"


def _token_authorization_status(header: str | None, tokens: dict[str, tuple[str, ...]], method: str) -> int | None:
    """Return 401/403 when token auth fails, else None. Never expose tokens in errors."""
    if not header or len(header) > 8_199:
        return 401
    scheme, separator, supplied = header.partition(" ")
    if not separator or scheme.lower() != "bearer" or not BEARER_TOKEN_PATTERN.fullmatch(supplied):
        return 401
    granted: tuple[str, ...] | None = None
    for expected, scopes in tokens.items():
        if hmac.compare_digest(expected, supplied):
            granted = scopes
    if granted is None:
        return 401
    required = _required_scope(method)
    return None if "proxy:admin" in granted or required in granted else 403


def _emit_gate_decision(
    router: AlertRouter,
    config: ProxyConfig,
    decision: str,
    *,
    coverage_status: str,
    reasons: list[str] | None = None,
    circuit_hashes: list[str] | None = None,
    circuit_coverage: list[dict[str, Any]] | None = None,
) -> None:
    hashes = circuit_hashes or []
    router.emit_audit(Alert(
        severity="info",
        category="gate.decision",
        message=f"gate decision: {decision}",
        circuit_hash=hashes[0] if len(hashes) == 1 else None,
        details={
            "decision": decision,
            "policy_mode": config.policy,
            "policy_version": config.policy_version,
            "failure_mode": config.failure_mode,
            "coverage": {
                "status": coverage_status,
                "reasons": reasons or [],
                "circuits": circuit_coverage or [],
            },
            "circuit_hashes": hashes,
        },
    ))


class _BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Bound active handler threads and make overload follow the gate failure mode."""

    def __init__(self, address, handler, *, config: ProxyConfig, router: AlertRouter, state: ProxyState):
        self.request_queue_size = config.request_queue_size
        self._slots = threading.BoundedSemaphore(config.max_workers)
        self._request_local = threading.local()
        self._config = config
        self._router = router
        self._state = state
        super().__init__(address, handler)

    @property
    def bypass_current_request(self) -> bool:
        return bool(getattr(self._request_local, "overloaded_bypass", False))

    def process_request(self, request, client_address) -> None:
        if self._slots.acquire(blocking=False):
            try:
                super().process_request(request, client_address)
            except Exception:
                self._slots.release()
                raise
            return

        with self._state.lock:
            self._state.stats.overloaded += 1
        if self._config.failure_mode == "closed":
            with self._state.lock:
                self._state.stats.requests += 1
                self._state.stats.blocked += 1
            decision = "block"
            body = json.dumps({
                "error": {"code": "qshield_overloaded", "decision": decision,
                          "failure_mode": "closed", "policy_version": self._config.policy_version}
            }).encode("utf-8")
            self._router.emit_audit(Alert(
                severity="info", category="gate.decision", message="gate blocked request due to overload",
                details={
                    "decision": decision,
                    "policy_version": self._config.policy_version,
                    "policy_mode": self._config.policy,
                    "failure_mode": self._config.failure_mode,
                    "coverage": {"status": "skipped", "reasons": ["bounded worker capacity exhausted"]},
                },
            ))
            response = (
                b"HTTP/1.1 503 Service Unavailable\r\n"
                b"Content-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Connection: close\r\nX-QShield-Decision: block\r\n\r\n"
                + body
            )
            try:
                request.sendall(response)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return

        # Fail-open overload is explicit: process this one request on the
        # accept loop, bypass inspection, and forward it. The bounded kernel
        # listen queue absorbs only the configured backlog while this happens.
        self._request_local.overloaded_bypass = True
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
            self._request_local.overloaded_bypass = False

    def process_request_thread(self, request, client_address) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_handler(config: ProxyConfig, router: AlertRouter, state: ProxyState) -> type[BaseHTTPRequestHandler]:
    class QShieldHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "qshield-runtime/0.1"

        # ------------------------------------------------------------------
        def log_message(self, fmt: str, *args) -> None:  # quiet by default
            return

        def _send_json(self, status: int, payload: dict, *, decision: str | None = None) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            if decision:
                self.send_header("X-QShield-Decision", decision)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _forward(self, method: str) -> None:
            t0 = time.monotonic()
            with state.lock:
                state.stats.requests += 1
            auth_status = _token_authorization_status(
                self.headers.get("Authorization"), config.auth_tokens, method,
            ) if config.auth_tokens else None
            if auth_status is not None:
                _emit_gate_decision(
                    router, config, "block", coverage_status="not_run",
                    reasons=["client authentication failed" if auth_status == 401 else "client token lacks required scope"],
                )
                error_code = "qshield_unauthorized" if auth_status == 401 else "qshield_forbidden"
                self._send_json(auth_status, {"error": {"code": error_code}}, decision="block")
                return
            transfer_encoding = self.headers.get("Transfer-Encoding")
            if transfer_encoding:
                _emit_gate_decision(
                    router, config, "block", coverage_status="inconclusive",
                    reasons=["chunked/transfer-encoded request bodies are not supported"],
                )
                self._send_json(501, {"error": {"code": "qshield_transfer_encoding_unsupported"}}, decision="block")
                return
            raw_length = self.headers.get("Content-Length", "0")
            try:
                length = int(raw_length)
            except ValueError:
                _emit_gate_decision(router, config, "block", coverage_status="inconclusive", reasons=["invalid Content-Length"])
                self._send_json(400, {"error": {"code": "qshield_invalid_content_length"}}, decision="block")
                return
            if length < 0:
                _emit_gate_decision(router, config, "block", coverage_status="inconclusive", reasons=["negative Content-Length"])
                self._send_json(400, {"error": {"code": "qshield_invalid_content_length"}}, decision="block")
                return
            if length > config.max_body_bytes:
                _emit_gate_decision(
                    router, config, "block", coverage_status="inconclusive",
                    reasons=[f"request body exceeds configured {config.max_body_bytes}-byte cap"],
                )
                self._send_json(413, {"error": {"code": "qshield_body_too_large",
                                                "max_body_bytes": config.max_body_bytes}}, decision="block")
                return
            body = self.rfile.read(length) if length else b""
            if len(body) != length:
                _emit_gate_decision(
                    router, config, "block", coverage_status="inconclusive",
                    reasons=["request body ended before Content-Length bytes were received"],
                )
                self._send_json(400, {"error": {"code": "qshield_incomplete_request_body"}}, decision="block")
                return

            expected_hash = self.headers.get(HASH_HEADER)
            overhead_ms = 0.0
            decision_header: str | None = None
            stored_tmp_keys: list[str] = []
            if getattr(self.server, "bypass_current_request", False):
                decision_header = "allow-with-alert"
                _emit_gate_decision(
                    router, config, decision_header, coverage_status="skipped",
                    reasons=["bounded worker capacity exhausted; fail-open bypassed inspection"],
                )
            elif method in ("POST", "PUT", "PATCH") and body:
                overhead_ms, blocked, stored_tmp_keys, decision_header = self._inspect_submission(body, expected_hash, t0)
                if blocked is not None:
                    status, payload = blocked
                    self._send_json(status, payload, decision="block")
                    return

            upstream_url = config.upstream.rstrip("/") + self.path
            fwd_headers = {
                k: v for k, v in self.headers.items()
                if k.lower() not in HOP_BY_HOP
                and k.lower() != "content-length"
                and not (config.auth_tokens and k.lower() == "authorization")
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
                    resp_body = resp.read(config.max_response_bytes + 1)
            except urllib.error.HTTPError as exc:
                # upstream answered with an error status — that is a valid response
                with exc:
                    status_code = exc.code
                    resp_headers = dict(exc.headers.items()) if exc.headers else {}
                    resp_body = exc.read(config.max_response_bytes + 1)
            except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
                self._send_json(502, {"error": {"code": "qshield_upstream_unavailable",
                                                "detail": str(exc)}}, decision="upstream-unavailable")
                return
            if len(resp_body) > config.max_response_bytes:
                self._send_json(502, {"error": {"code": "qshield_upstream_response_too_large",
                                                "max_response_bytes": config.max_response_bytes}},
                                decision="upstream-unavailable")
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
            self._relay_response(status_code, resp_headers, resp_body, result_hdr, overhead_ms, decision_header)

        # ------------------------------------------------------------------
        def _inspect_submission(self, body: bytes, expected_hash: str | None, t0: float):
            """Inspect a submission and return its explicit gate action and coverage."""
            inspect_start = time.monotonic()
            stored_tmp_keys: list[str] = []
            coverage_entries: list[dict[str, Any]] = []
            reasons: list[str] = []
            try:
                circuits = adapters.extract_circuits(body, self.headers.get("Content-Type", ""))
            except ValueError as exc:
                reason = str(exc)
                router.emit(Alert(severity="high", category="body.oversize", message=reason))
                _emit_gate_decision(router, config, "block", coverage_status="inconclusive", reasons=[reason])
                return 0.0, (413, {"error": {"code": "qshield_body_too_large", "detail": reason}}), stored_tmp_keys, "block"

            if not circuits:
                _emit_gate_decision(
                    router, config, "allow", coverage_status="not_applicable",
                    reasons=["request body did not match a known circuit submission shape"],
                )
                return 0.0, None, stored_tmp_keys, "allow"

            with state.lock:
                state.stats.intercepted_submissions += 1
                state.stats.circuits_seen += len(circuits)

            blocked: tuple[int, dict] | None = None
            alerts: list[Alert] = []
            circuit_hashes: list[str] = []
            for idx, tc in enumerate(circuits):
                try:
                    ir = parse_qasm(tc.qasm, name=f"wire{idx}")
                except Exception as exc:  # parser must not 500 the proxy
                    reason = f"could not parse intercepted circuit #{idx}: {exc}"
                    reasons.append(reason)
                    coverage_entries.append({"circuit_index": idx, "status": "inconclusive", "reason": reason})
                    alerts.append(Alert(severity="medium", category="circuit.parse_failure", message=reason))
                    if config.failure_mode == "closed":
                        blocked = (400, {"error": {"code": "qshield_unverifiable", "detail": reason}})
                        break
                    continue

                parser_notes = list((ir.metadata or {}).get("warnings", []))
                try:
                    report = inspect_circuit(
                        ir, expected_hash=expected_hash if len(circuits) == 1 else None,
                        run_static=config.run_static,
                    )
                except Exception as exc:
                    reason = f"integrity analysis failed for circuit #{idx}: {exc}"
                    reasons.append(reason)
                    coverage_entries.append({"circuit_index": idx, "status": "inconclusive", "reason": reason})
                    alerts.append(Alert(severity="high", category="circuit.analysis_failure", message=reason))
                    if config.failure_mode == "closed":
                        blocked = (503, {"error": {"code": "qshield_analysis_unavailable", "detail": reason}})
                        break
                    continue

                circuit_hash = report.circuit_hash
                circuit_hashes.append(circuit_hash)
                entry_reasons = list(parser_notes)
                if not config.run_static:
                    entry_reasons.append("static integrity analysis disabled by configuration")
                status = "inconclusive" if entry_reasons else "completed"
                coverage_entries.append({
                    "circuit_index": idx,
                    "circuit_hash": circuit_hash,
                    "status": status,
                    "checks": {
                        "canonical_hash": "completed",
                        "commitment": report.commitment.status,
                        "static_analysis": "completed" if config.run_static else "not_run",
                    },
                    "reasons": entry_reasons,
                })
                reasons.extend(entry_reasons)

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

                threshold_findings = report.findings_at_least(config.min_severity)
                for finding in threshold_findings:
                    alerts.append(Alert(
                        severity=finding.severity, category="static.finding",
                        message=f"{finding.threat_type}: {finding.title}",
                        circuit_hash=circuit_hash,
                        details={"threat_type": finding.threat_type,
                                 "confidence": finding.confidence,
                                 "analysis_type": finding.analysis_type},
                    ))
                if config.policy == "enforce" and threshold_findings:
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

            if blocked is not None and len(coverage_entries) < len(circuits):
                reasons.append("analysis stopped after a blocking decision; remaining circuits were not checked")
                for pending_index in range(len(coverage_entries), len(circuits)):
                    coverage_entries.append({
                        "circuit_index": pending_index,
                        "status": "not_run",
                        "reason": "earlier circuit triggered a fail-closed gate decision",
                    })

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
            if blocked is not None:
                decision = "block"
            elif alerts or reasons:
                decision = "allow-with-alert"
            else:
                decision = "allow"
            coverage_status = "inconclusive" if reasons else "completed"
            _emit_gate_decision(
                router, config, decision, coverage_status=coverage_status,
                reasons=reasons, circuit_hashes=circuit_hashes, circuit_coverage=coverage_entries,
            )
            return overhead_ms, blocked, stored_tmp_keys, decision

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
                            result_hdr: str | None, overhead_ms: float,
                            decision: str | None = None) -> None:
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
            if decision:
                self.send_header("X-QShield-Decision", decision)
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


def _is_loopback_bind(host: str) -> bool:
    value = host.strip().strip("[]").lower()
    if value == "localhost":
        return True
    try:
        return ipaddress.ip_address(value.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


class QShieldProxy:
    """Threaded reverse proxy. ``start()`` spawns serving; ``stop()`` shuts down."""

    def __init__(
        self,
        config: ProxyConfig,
        alert_router: AlertRouter | None = None,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        tls_certfile: str | Path | None = None,
        tls_keyfile: str | Path | None = None,
        client_ca_file: str | Path | None = None,
        trusted_front_proxy: bool = False,
    ):
        if bool(tls_certfile) != bool(tls_keyfile):
            raise ValueError("TLS server certificate and private key must be configured together")
        if client_ca_file and not tls_certfile:
            raise ValueError("client certificate authentication requires TLS")
        tls_context: ssl.SSLContext | None = None
        if tls_certfile and tls_keyfile:
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
            try:
                tls_context.load_cert_chain(str(tls_certfile), str(tls_keyfile))
                if client_ca_file:
                    tls_context.load_verify_locations(cafile=str(client_ca_file))
                    tls_context.verify_mode = ssl.CERT_REQUIRED
            except (OSError, ssl.SSLError) as exc:
                raise ValueError(f"could not configure proxy TLS: {exc}") from exc

        remote_bind = not _is_loopback_bind(host)
        if remote_bind and not trusted_front_proxy:
            if tls_context is None:
                raise ValueError("non-loopback binds require TLS or an explicit trusted_front_proxy")
            if not config.auth_tokens and not client_ca_file:
                raise ValueError("remote TLS listeners require scoped bearer tokens or client certificates")

        self.config = config
        self.router = alert_router or build_alert_router(None, None, config.alert_min_severity)
        self.state = ProxyState()
        self._server = _BoundedThreadingHTTPServer(
            (host, port), make_handler(config, self.router, self.state),
            config=config, router=self.router, state=self.state,
        )
        self._server.daemon_threads = True
        self.tls_enabled = tls_context is not None
        self.client_auth_enabled = bool(client_ca_file)
        if tls_context is not None:
            self._server.socket = tls_context.wrap_socket(self._server.socket, server_side=True)
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
