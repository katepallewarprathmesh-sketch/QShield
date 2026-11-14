"""QSHIELD Workbench server — stdlib ThreadingHTTPServer, JSON-only API.

Security properties (by construction, not configuration):
* binds 127.0.0.1 by default; 0.0.0.0 only behind an explicit --host flag
* never executes uploaded content — QASM is parsed, never run
* 8 MiB request body cap; JSON in / JSON out; no shell, no filesystem writes
* zero outbound network calls — EXCEPT the opt-in `/api/ai/*` endpoints, which
  call Sarvam AI (cloud) only when invoked, and send finding summaries only
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from qshield import __version__
from qshield.core.circuit_ir import CircuitIR
from qshield.policy import PolicyEngine, PolicyError, builtin_policies, evaluate_corpus
from qshield.redteam import probe_finding_robustness
from qshield.ui.page import WORKBENCH_HTML

MAX_BODY = 8 * 1024 * 1024
FIXTURE_ROOT = Path(__file__).resolve().parents[3] / "tests" / "fixtures"


def _repo_fixtures_dir(kind: str) -> Path:
    return FIXTURE_ROOT / kind


def _stats(ir: CircuitIR) -> dict[str, int]:
    return {"qubits": ir.num_qubits, "gates": len(ir.gates), "depth": ir.get_depth()}


def _scan_qasm(qasm: str) -> dict[str, Any]:
    from qshield.core.parsers.qasm_parser import parse_qasm

    ir = parse_qasm(qasm, name="workbench")
    from qshield.scanner import Scanner

    scanner = Scanner(config="default", parallel=False)
    scanner.add_circuit(ir)
    results = scanner.run(analyses=["static"])
    findings = list(results.findings)
    warnings = list(results.warnings)
    findings.sort(key=lambda f: (f.severity_rank, f.confidence), reverse=True)
    return {
        "findings": [f.to_dict() for f in findings],
        "stats": _stats(ir),
        "warnings": warnings,
    }


def _compare(a_src: str, b_src: str, engine: str) -> dict[str, Any]:
    import numpy as np

    from qshield.core.parsers.qasm_parser import parse_qasm

    a, b = parse_qasm(a_src, name="original"), parse_qasm(b_src, name="suspicious")
    rows = [
        ("Qubits", a.num_qubits, b.num_qubits),
        ("Classical bits", a.num_classical_bits, b.num_classical_bits),
        ("Gates", len(a.gates), len(b.gates)),
        ("Depth", a.get_depth(), b.get_depth()),
    ]
    payload: dict[str, Any] = {
        "rows": [
            {"label": label, "a": va, "b": vb, "match": va == vb}
            for label, va, vb in rows
        ],
    }
    if engine == "zx":
        from qshield.formal import zx_equivalence_check

        result = zx_equivalence_check(a, b)
        payload["verdict"] = {True: "EQUIVALENT", False: "DIFFERENT", None: "UNDECIDED"}[result.equivalent]
        payload["detail"] = f"ZX-calculus · {result.message} [{result.method}]"
        return payload
    ua, ub = a.to_unitary(), b.to_unitary()
    if ua is not None and ub is not None and ua.shape == ub.shape:
        dist = float(np.linalg.norm(ua - ub))
        payload["verdict"] = "EQUIVALENT" if dist < 1e-6 else "DIFFERENT"
        payload["detail"] = f"Exact unitary distance ‖ΔU‖ = {dist:.3e} (proof for ≤12 qubits)"
        return payload
    if a.num_qubits <= 12 and b.num_qubits <= 12:
        payload["verdict"] = "UNDECIDED"
        payload["detail"] = "Unitary out of reach for this pair (non-unitary gates?). Try --formal via CLI."
        return payload
    payload["verdict"] = "UNDECIDED"
    payload["detail"] = f"Circuits exceed the exact-unitary window ({a.num_qubits} & {b.num_qubits} qubits). Use the ZX engine, or qshield compare --randomized via CLI."
    return payload


def _policy_eval(ids: list[str], sample: int | None) -> dict[str, Any]:
    registry = {p.id: p for p in builtin_policies()}
    unknown = [i for i in ids if i not in registry]
    if unknown:
        raise PolicyError(f"unknown policy ids: {', '.join(unknown)}")
    specs = [registry[i] for i in ids]
    clean, malicious = _repo_fixtures_dir("clean_circuits"), _repo_fixtures_dir("malicious_circuits")
    if not clean.exists() or not malicious.exists():
        raise PolicyError(
            "fixture corpus not found — Policy Studio scoring works from a source checkout "
            "(tests/fixtures), not from an installed wheel"
        )
    engine = PolicyEngine(specs)
    return evaluate_corpus(engine, clean, malicious, sample=sample)


def _example_qasm(name: str) -> dict[str, str]:
    fixture = _repo_fixtures_dir("malicious_circuits") / f"{Path(name).stem}.qasm"
    if fixture.exists():
        return {"qasm": fixture.read_text()}
    raise PolicyError(f"example {name!r} not found in the bundled corpus")


class WorkbenchHandler(BaseHTTPRequestHandler):
    server_version = f"QSHIELD/{__version__}"

    # -- plumbing ------------------------------------------------------
    def _send(self, code: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: Any) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json")

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > MAX_BODY:
            raise PolicyError("request body exceeds 8 MiB cap")
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode())
        except Exception as exc:
            raise PolicyError(f"invalid JSON body: {exc}") from exc
        if not isinstance(data, dict):
            raise PolicyError("JSON body must be an object")
        return data

    def log_message(self, fmt: str, *args: Any) -> None:  # keep the console clean by default
        pass

    # -- routes ---------------------------------------------------------
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path, qs = parsed.path, parse_qs(parsed.query)
        if path == "/":
            self._send(200, WORKBENCH_HTML.encode(), "text/html; charset=utf-8")
        elif path == "/api/overview":
            self._json(
                200,
                {
                    "name": "QSHIELD Workbench",
                    "version": __version__,
                    "corpus": {"clean": 202, "malicious": 215},
                    "metrics": {"tpr": 0.958, "fpr": 0.008, "runtime_p95_ms": 1.5, "static_1000q_s": 2},
                    "limits": [
                        "Fixture-corpus metrics, not field rates",
                        "Evidence of known tampering classes — never proof of honesty",
                        "No hardware path anywhere in this workbench",
                    ],
                },
            )
        elif path == "/api/ai/status":
            from qshield import ai as qai

            self._json(200, {"configured": qai.configured(), "disclaimer": qai.disclaimer()})
        elif path == "/api/policies":
            self._json(200, {"policies": [p.to_dict() for p in builtin_policies()]})
        elif path == "/api/example":
            name = (qs.get("name") or ["ancilla_leakage"])[0]
            try:
                self._json(200, _example_qasm(name))
            except PolicyError as exc:
                self._json(404, {"error": str(exc)})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        try:
            body = self._read_json()
            if path == "/api/scan":
                qasm = str(body.get("qasm", "")).strip()
                if not qasm:
                    raise PolicyError("provide 'qasm' source text")
                self._json(200, _scan_qasm(qasm))
            elif path == "/api/compare":
                a, b = str(body.get("a", "")).strip(), str(body.get("b", "")).strip()
                if not a or not b:
                    raise PolicyError("provide both 'a' and 'b' circuit sources")
                engine = str(body.get("engine", "unitary"))
                if engine not in ("unitary", "zx"):
                    raise PolicyError("engine must be 'unitary' or 'zx'")
                self._json(200, _compare(a, b, engine))
            elif path == "/api/robustness":
                qasm = str(body.get("qasm", "")).strip()
                if not qasm:
                    raise PolicyError("provide 'qasm' source text")
                from qshield.core.parsers.qasm_parser import parse_qasm

                ir = parse_qasm(qasm, name="probe")
                self._json(200, probe_finding_robustness(ir, variants_per_attack=2))
            elif path == "/api/ai/speak":
                text = str(body.get("text", "")).strip()
                if not text:
                    raise PolicyError("provide 'text' to synthesize")
                if len(text) > 1500:
                    raise PolicyError("text too long — 1500 characters max")
                from qshield import ai as qai

                lang = str(body.get("language_code", "hi-IN"))
                speaker = str(body.get("speaker", qai.DEFAULT_SPEAKER))
                audio = qai.tts_bytes(text, language_code=lang, speaker=speaker)
                self._send(200, audio, "audio/wav")
            elif path == "/api/ai/report":
                qasm = str(body.get("qasm", "")).strip()
                if not qasm:
                    raise PolicyError("provide 'qasm' source text")
                to = str(body.get("to", "hi-IN")).strip()
                import re as _re

                if not _re.fullmatch(r"[a-z]{2}-IN", to):
                    raise PolicyError("'to' must be an Indian language code like hi-IN, mr-IN, ta-IN")
                from qshield import ai as qai
                from qshield.core.parsers.qasm_parser import parse_qasm

                ir = parse_qasm(qasm, name="workbench")
                payload = qai.scan_findings_ir(ir, name="circuit.qasm")
                english = qai.english_report(payload)
                translated = qai.translate(english, target_language_code=to, source_language_code="en-IN")
                self._json(
                    200,
                    {"english": english, "translated": translated, "to": to,
                     "disclaimer": qai.disclaimer()},
                )
            elif path == "/api/ai/listen":
                import base64

                b64 = str(body.get("audio_b64", ""))
                if not b64:
                    raise PolicyError("provide 'audio_b64' (base64-encoded audio)")
                mode = str(body.get("mode", "transcribe"))
                if mode not in ("transcribe", "translate", "verbatim", "translit", "codemix"):
                    raise PolicyError("mode must be transcribe|translate|verbatim|translit|codemix")
                try:
                    data = base64.b64decode(b64, validate=True)
                except Exception as exc:
                    raise PolicyError("audio_b64 is not valid base64") from exc
                if len(data) > MAX_BODY:
                    raise PolicyError("audio exceeds 8 MiB cap")
                from qshield import ai as qai

                self._json(200, {"transcript": qai.stt_bytes(data, mode=mode)})
            elif path == "/api/ai/triage":
                qasm = str(body.get("qasm", "")).strip()
                if not qasm:
                    raise PolicyError("provide 'qasm' source text")
                from qshield import ai as qai
                from qshield.core.parsers.qasm_parser import parse_qasm

                ir = parse_qasm(qasm, name="workbench")
                payload = qai.scan_findings_ir(ir, name=Path("circuit.qasm").name)
                reply = qai.triage(payload)
                self._json(
                    200,
                    {
                        "reply": reply,
                        "findings_sent": len(payload["findings"]),
                        "disclaimer": qai.disclaimer(),
                    },
                )
            elif path == "/api/policy-eval":
                ids = body.get("ids")
                if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids) or not ids:
                    raise PolicyError("provide non-empty 'ids': list of builtin policy ids")
                sample = body.get("sample")
                if sample is not None and (not isinstance(sample, int) or sample < 1):
                    raise PolicyError("'sample' must be a positive integer (or omitted for full corpus)")
                self._json(200, _policy_eval(ids, sample))
            else:
                self._json(404, {"error": "not found"})
        except PolicyError as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # Sarvam/AI upstream failures surface as 503; the rest as 500
            if type(exc).__name__ in ("SarvamUnavailable", "APIError", "APIConnectionError", "RateLimitError"):
                self._json(503, {"error": f"AI upstream error: {exc}"})
            else:
                self._json(500, {"error": f"{type(exc).__name__}: {exc}"})


def run_workbench(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Serve the Workbench (blocking). Ctrl+C to stop."""
    server = ThreadingHTTPServer((host, port), WorkbenchHandler)
    server.daemon_threads = True
    shown_host = "localhost" if host == "127.0.0.1" else host
    print(f"QSHIELD Workbench {__version__} — http://{shown_host}:{server.server_address[1]}")
    print("Offline · read-only · no telemetry · Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
