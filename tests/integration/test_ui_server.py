"""Workbench HTTP surface: page loads, JSON APIs respond, bad input → 400."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from qshield.ui.server import WorkbenchHandler

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
        return e.code, e.read().decode()


def test_page_serves(server):
    status, body = _get(server + "/")
    assert status == 200 and "QSHIELD" in body and "Workbench" in body


def test_overview_and_policies(server):
    status, body = _get(server + "/api/overview")
    assert status == 200 and json.loads(body)["corpus"]["malicious"] == 215
    status, body = _get(server + "/api/policies")
    policies = json.loads(body)["policies"]
    assert len(policies) >= 6 and all("id" in p for p in policies)


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
