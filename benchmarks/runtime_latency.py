"""M4.1 acceptance benchmark: runtime proxy latency overhead per API call.

Interposes the QSHIELD interceptor proxy between a synthetic quantum-cloud
client and a synthetic upstream, and measures the overhead added to each API
call relative to calling the upstream directly. Spec acceptance criterion:
**< 100 ms overhead per API call**; we assert on the p95.

The synthetic cloud speaks a representative wire shape:

    POST /jobs   {"program_id": "...", "params": {"circuits": [<qasm>], "shots": 200}}
               → {"id": "job-…", "status": "ok"}
    GET  /jobs/{id} where circuits are terminal Bell-like states
               → {"id": "job-…", "shots": 200, "counts": {"00": 99, "11": 101}}

Run:  python benchmarks/runtime_latency.py
Exit code 0 iff p95 overhead < 100 ms on both paths.
"""

from __future__ import annotations

import json
import statistics
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import ClassVar

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from qshield.runtime.alerting import AlertRouter
from qshield.runtime.proxy import ProxyConfig, QShieldProxy

BELL_QASM = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n"
N_CALLS = 60
LIMIT_MS = 100.0

_counter = {"n": 0}
_lock = threading.Lock()


def _make_upstream():
    class Upstream(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        counts: ClassVar[dict] = {"00": 99, "11": 101}

        def log_message(self, *a):
            pass

        def _json(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            if self.path == "/jobs":
                length = int(self.headers.get("Content-Length") or 0)
                self.rfile.read(length)
                with _lock:
                    _counter["n"] += 1
                    job_id = f"job-{_counter['n']:05d}"
                self._json(200, {"id": job_id, "status": "ok"})
            else:
                self._json(404, {"error": "not found"})

        def do_GET(self) -> None:
            if self.path.startswith("/jobs/"):
                job_id = self.path.rsplit("/", 1)[-1]
                self._json(200, {"id": job_id, "shots": 200, "counts": dict(self.counts)})
            else:
                self._json(404, {"error": "not found"})

    return ThreadingHTTPServer(("127.0.0.1", 0), Upstream)


def _call(url: str, method: str, payload: dict | None = None, timeout: float = 5.0) -> tuple[int, float, bytes]:
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=body, method=method,  # noqa: S310 - benchmark client for a local synthetic upstream
                                 headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - benchmark client for a local synthetic upstream
        data = resp.read()
        dt = (time.perf_counter() - t0) * 1000.0
        return resp.status, dt, data


def main() -> int:
    upstream = _make_upstream()
    upstream.daemon_threads = True
    up_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    up_thread.start()
    up_port = upstream.server_address[1]
    base_direct = f"http://127.0.0.1:{up_port}"

    config = ProxyConfig(upstream=base_direct, policy="observe", run_static=True,
                         validate_results=True)
    proxy = QShieldProxy(config, AlertRouter(sinks=[], min_severity="critical"),
                         host="127.0.0.1", port=0).start()
    base_proxy = f"http://127.0.0.1:{proxy.port}"

    payload = {"program_id": "qshield-bench",
               "params": {"circuits": [BELL_QASM], "shots": 200}}

    def bench(label: str, base: str) -> tuple[list[float], list[float]]:
        post_times, get_times = [], []
        for _ in range(N_CALLS):
            _, dt, body = _call(f"{base}/jobs", "POST", payload)
            post_times.append(dt)
            job_id = json.loads(body)["id"]
            _, dt, _ = _call(f"{base}/jobs/{job_id}", "GET")
            get_times.append(dt)
        p50 = statistics.median(post_times)
        print(f"{label}: POST p50={p50:.2f}ms p95={statistics.quantiles(post_times, n=20)[18]:.2f}ms | "
              f"GET p50={statistics.median(get_times):.2f}ms p95={statistics.quantiles(get_times, n=20)[18]:.2f}ms")
        return post_times, get_times

    try:
        # warm-up (also primes import caches)
        _call(f"{base_proxy}/jobs", "POST", payload)
        _call(f"{base_direct}/jobs", "POST", payload)

        post_direct, get_direct = bench("direct", base_direct)
        post_proxy, get_proxy = bench("proxy ", base_proxy)

        post_over = [p - d for p, d in zip(post_proxy, post_direct, strict=True)]
        get_over = [p - d for p, d in zip(get_proxy, get_direct, strict=True)]
        # pair-wise overhead can be negative on single samples; clamp at 0 for the gate,
        # report both raw and clamped numbers honestly.
        post_p95 = statistics.quantiles([max(0.0, x) for x in post_over], n=20)[18]
        get_p95 = statistics.quantiles([max(0.0, x) for x in get_over], n=20)[18]
        post_mean = statistics.mean([max(0.0, x) for x in post_over])
        get_mean = statistics.mean([max(0.0, x) for x in get_over])

        print(f"\noverhead (clamped at 0): POST mean={post_mean:.2f}ms p95={post_p95:.2f}ms | "
              f"GET mean={get_mean:.2f}ms p95={get_p95:.2f}ms")
        print(f"proxy stats: {proxy.stats_snapshot()}")

        ok = post_p95 < LIMIT_MS and get_p95 < LIMIT_MS
        print(f"\n{'PASS' if ok else 'FAIL'}: p95 overhead {'<' if ok else '>='} {LIMIT_MS} ms")
        return 0 if ok else 1
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


if __name__ == "__main__":
    raise SystemExit(main())
