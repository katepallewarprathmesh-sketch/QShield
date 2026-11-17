"""Workbench HTTP surface: page loads, JSON APIs respond, bad input → 400."""

from __future__ import annotations

import json
import re
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from qshield.ui.server import WorkbenchHandler, _is_loopback_host, run_workbench

REPO = Path(__file__).resolve().parents[2]
ANCILLA = REPO / "tests" / "fixtures" / "malicious_circuits" / "ancilla_leakage.qasm"

BELL = (
    'OPENQASM 2.0; include "qelib1.inc"; qreg q[2]; creg c[2];\n'
    "h q[0]; cx q[0],q[1]; measure q -> c;"
)


@pytest.fixture()
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), WorkbenchHandler)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_remote_bind_requires_explicit_opt_in():
    assert _is_loopback_host("127.0.0.1")
    assert _is_loopback_host("::1")
    assert _is_loopback_host("localhost")
    assert not _is_loopback_host("0.0.0.0")  # noqa: S104 - asserting the remote-bind guard
    assert not _is_loopback_host("192.168.1.20")
    with pytest.raises(ValueError, match="--allow-remote"):
        run_workbench(host="0.0.0.0", port=0)  # noqa: S104 - must be rejected before binding


def _get(url):
    with urllib.request.urlopen(url, timeout=15) as r:
        return r.status, r.read().decode()


def _post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, r.read().decode()


def _post_raw(url, raw: bytes):
    req = urllib.request.Request(url, data=raw, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        with e:
            return e.code, e.read().decode()


def test_page_serves(server):
    with urllib.request.urlopen(server + "/", timeout=15) as response:
        status = response.status
        body = response.read().decode()
        headers = response.headers
    assert status == 200 and "QSHIELD" in body and "Workbench" in body
    csp = headers["Content-Security-Policy"]
    nonce = re.search(r'<script nonce="([^"]+)"', body)
    assert nonce and f"script-src 'nonce-{nonce.group(1)}'" in csp
    assert "unsafe-inline" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    assert "frame-ancestors 'none'" in csp
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["Referrer-Policy"] == "no-referrer"
    assert re.search(r"<[^>]+\bon[a-z]+\s*=", body, flags=re.IGNORECASE) is None
    assert 'role="tablist"' in body
    assert "trust-banner" not in body
    assert "Know your trust boundary" not in body
    assert "Opt-in cloud feature" not in body
    assert "Findings summary is sent" not in body
    assert "OFFLINE · NO NETWORK" not in body
    with urllib.request.urlopen(server + "/", timeout=15) as second_response:
        second_body = second_response.read().decode()
    second_nonce = re.search(r'<script nonce="([^"]+)"', second_body)
    assert second_nonce and second_nonce.group(1) != nonce.group(1)


def test_overview_and_policies(server):
    status, body = _get(server + "/api/overview")
    assert status == 200 and json.loads(body)["corpus"]["malicious"] == 215
    status, body = _get(server + "/api/policies")
    data = json.loads(body)
    policies = data["policies"]
    assert len(policies) >= 6 and all("id" in p for p in policies)
    assert data["corpus_available"] is True


def test_policy_endpoint_reports_missing_fixture_corpus(server, monkeypatch, tmp_path):
    import qshield.ui.server as ui_server

    monkeypatch.setattr(ui_server, "FIXTURE_ROOT", tmp_path / "missing")
    status, body = _get(server + "/api/policies")
    assert status == 200 and json.loads(body)["corpus_available"] is False
    code, body = _post_raw(server + "/api/policy-eval", json.dumps({"ids": ["POL-001"]}).encode())
    assert code == 400
    assert "fixture corpus unavailable" in body
    assert "QSHIELD_FIXTURES_DIR" in body


def test_default_fixture_root_falls_back_to_packaged_corpus(monkeypatch, tmp_path):
    import qshield.ui.server as ui_server

    packaged = ui_server._PACKAGED_FIXTURE_ROOT
    monkeypatch.delenv("QSHIELD_FIXTURES_DIR", raising=False)
    monkeypatch.setattr(ui_server, "_REPO_FIXTURE_ROOT", tmp_path / "no-repo-fixtures")
    assert ui_server._default_fixture_root() == packaged
    for kind, expected_count in (("clean_circuits", 202), ("malicious_circuits", 215)):
        source_files = {path.name: path.read_bytes() for path in (REPO / "tests" / "fixtures" / kind).glob("*.qasm")}
        packaged_files = {path.name: path.read_bytes() for path in (packaged / kind).glob("*.qasm")}
        assert len(packaged_files) == expected_count
        assert packaged_files == source_files


def test_fixture_root_environment_override(monkeypatch, tmp_path):
    import qshield.ui.server as ui_server

    custom = tmp_path / "my-corpus"
    monkeypatch.setenv("QSHIELD_FIXTURES_DIR", str(custom))
    assert ui_server._default_fixture_root() == custom


def test_scan_endpoint_bell_is_clean_ish(server):
    status, body = _post(server + "/api/scan", {"qasm": BELL})
    assert status == 200
    data = json.loads(body)
    assert data["stats"]["qubits"] == 2 and data["stats"]["gates"] >= 2  # gates exclude position-less measurements
    assert isinstance(data["findings"], list)


@pytest.mark.skipif(not ANCILLA.exists(), reason="fixture not present")
def test_scan_endpoint_flags_ancilla_leakage(server):
    status, body = _post(server + "/api/scan", {"qasm": ANCILLA.read_text()})
    assert status == 200
    findings = json.loads(body)["findings"]
    assert any(f.get("severity") in ("critical", "high") for f in findings)


def test_compare_identical_circuits_equivalent(server):
    status, body = _post(server + "/api/compare", {"a": BELL, "b": BELL, "engine": "unitary"})
    assert status == 200
    data = json.loads(body)
    assert data["verdict"] == "EQUIVALENT"
    assert all(r["match"] for r in data["rows"])


def test_compare_rejects_bad_engine(server):
    code, body = _post_raw(server + "/api/compare", json.dumps({"a": BELL, "b": BELL, "engine": "wat"}).encode())
    assert code in (400, 422, 500)
    assert "engine" in body


def test_robustness_requires_qasm(server):
    code, body = _post_raw(server + "/api/robustness", json.dumps({}).encode())
    assert code == 400 and "qasm" in body


def test_invalid_json_body_is_400(server):
    code, body = _post_raw(server + "/api/scan", b"{not json")
    assert code == 400
    assert "invalid JSON" in body


@pytest.mark.skipif(not (REPO / "tests" / "fixtures" / "clean_circuits").exists(), reason="corpus not present")
def test_policy_eval_small_sample(server):
    status, body = _post(server + "/api/policy-eval", {"ids": ["POL-001", "POL-002"], "sample": 8})
    assert status == 200
    data = json.loads(body)
    assert len(data["per_policy"]) == 2
    assert 0.0 <= data["any_policy"]["tpr"] <= 1.0


def test_policy_eval_unknown_id_is_400(server):
    code, body = _post_raw(server + "/api/policy-eval", json.dumps({"ids": ["NOPE-1"]}).encode())
    assert code == 400 and "unknown policy" in body
