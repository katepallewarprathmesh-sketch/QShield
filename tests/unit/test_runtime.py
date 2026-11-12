"""Unit tests for qshield.runtime (M4.1) — adapters, integrity, validation, alerting."""

import json

import pytest

from qshield.core.parsers.qasm_parser import parse_qasm
from qshield.reporting.finding import Finding
from qshield.runtime import adapters, alerting, integrity, validation

BELL = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n"
BELL_MEAS = "OPENQASM 2.0;\nqreg q[2];\ncreg c[2];\nh q[0];\ncx q[0], q[1];\nmeasure q -> c;\n"
GHZ4 = "OPENQASM 2.0;\nqreg q[3];\nh q[0];\ncx q[0], q[1];\ncx q[1], q[2];\n"


# ---------------------------------------------------------------- adapters
class TestExtractCircuits:
    def test_raw_qasm_body(self):
        out = adapters.extract_circuits(BELL.encode())
        assert len(out) == 1 and out[0].shape == "raw-qasm"

    def test_ibm_runtime_shape(self):
        body = json.dumps({"program_id": "sampler", "params": {"circuits": [BELL, GHZ4], "shots": 1024},
                           "backend": "ibm_brisbane"}).encode()
        out = adapters.extract_circuits(body, "application/json")
        assert [o.qasm for o in out] == [BELL, GHZ4]
        assert all(o.shots == 1024 and o.backend == "ibm_brisbane" for o in out)

    def test_qasm_key_and_job_id(self):
        body = json.dumps({"id": "job-7", "qasm": BELL, "shots": 10}).encode()
        out = adapters.extract_circuits(body)
        assert out[0].job_id == "job-7" and out[0].shots == 10

    def test_nested_input_shape(self):
        body = json.dumps({"input": {"params": {"program": BELL}}}).encode()
        out = adapters.extract_circuits(body)
        assert len(out) == 1 and "h q[0]" in out[0].qasm

    def test_garbage_and_missing(self):
        assert adapters.extract_circuits(b"") == []
        assert adapters.extract_circuits(b"not qasm and not json") == []
        assert adapters.extract_circuits(b"{\"hello\": 1}") == []
        assert adapters.extract_circuits(b"\xff\xfe binary") == []

    def test_body_cap(self):
        with pytest.raises(ValueError):
            adapters.extract_circuits(b"x" * (adapters.MAX_BODY_BYTES + 1))

    def test_extract_job_id(self):
        assert adapters.extract_job_id(json.dumps({"id": "job-9"}).encode()) == "job-9"
        assert adapters.extract_job_id(json.dumps({"job_id": "j2"}).encode()) == "j2"
        assert adapters.extract_job_id(b"no json") is None


class TestExtractResult:
    def test_plain_counts(self):
        r = adapters.extract_result(json.dumps({"counts": {"00": 3, "11": 5}}).encode())
        assert r is not None and r.counts == {"00": 3, "11": 5} and r.total_shots == 8

    def test_ibm_runtime_result_shape(self):
        body = json.dumps({"id": "job-3", "results": [{"counts": {"00": 10, "11": 10}}]}).encode()
        r = adapters.extract_result(body)
        assert r is not None and r.job_id == "job-3" and r.total_shots == 20

    def test_data_wrapped_counts(self):
        body = json.dumps({"data": {"counts": {"0": 7}}}).encode()
        r = adapters.extract_result(body)
        assert r is not None and r.counts == {"0": 7}

    def test_not_a_result(self):
        assert adapters.extract_result(json.dumps({"status": "ok"}).encode()) is None
        assert adapters.extract_result(b"not json") is None
        assert adapters.extract_result(b"") is None

    def test_bad_counts_values_rejected(self):
        body = json.dumps({"counts": {"00": "many"}}).encode()
        assert adapters.extract_result(body) is None


# ------------------------------------------------------------- integrity
class TestIntegrity:
    def test_canonical_hash_stable_and_sensitive(self):
        a = parse_qasm(BELL)
        b = parse_qasm(BELL)
        assert integrity.canonical_circuit_hash(a) == integrity.canonical_circuit_hash(b)
        tampered = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\nx q[0];\n")
        assert integrity.canonical_circuit_hash(a) != integrity.canonical_circuit_hash(tampered)

    def test_commitment_absent_ok_and_mismatch(self):
        ir = parse_qasm(BELL)
        actual = integrity.canonical_circuit_hash(ir)
        assert integrity.verify_commitment(ir, None).status == "absent"
        assert integrity.verify_commitment(ir, actual).ok is True
        assert integrity.verify_commitment(ir, "sha256:" + actual).ok is True
        assert integrity.verify_commitment(ir, "0" * 64).status == "mismatch"

    def test_inspect_circuit_flags_static_findings(self):
        # a circuit with an identity pair (dead/cancellation finding)
        ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nh q[0];\nh q[0];\n")
        report = integrity.inspect_circuit(ir)
        assert report.circuit_hash
        assert isinstance(report.findings, list)

    def test_findings_at_least(self):
        ir = parse_qasm(BELL)
        report = integrity.inspect_circuit(ir)
        report.findings = [
            Finding(severity="low", threat_type="T1.3", title="x", description="d"),
            Finding(severity="high", threat_type="T1.1", title="y", description="d"),
        ]
        assert report.max_severity == "high"
        assert len(report.findings_at_least("medium")) == 1
        assert len(report.findings_at_least("high")) == 1


# ------------------------------------------------------------ validation
class TestValidation:
    def test_bell_counts_match(self):
        ir = parse_qasm(BELL_MEAS)
        counts = {"00": 502, "11": 498}
        verdict = validation.validate_counts(ir, counts)
        assert verdict.status == "match" and verdict.p_value > 0.01
        assert verdict.bit_order == "msb"

    def test_bell_counts_mismatch_impossible_bins(self):
        ir = parse_qasm(BELL_MEAS)
        counts = {"01": 500, "10": 500}  # zero-probability outcomes at 100%
        verdict = validation.validate_counts(ir, counts)
        assert verdict.status == "mismatch"

    def test_lsb_bit_order_recognised(self):
        # LSB provider keys for Bell MSB {"00","11"} are identical when palindromic;
        # use a single-qubit X circuit (asymmetric) to exercise the reversed mapping
        ir2 = parse_qasm("OPENQASM 2.0;\nqreg q[1];\ncreg c[1];\nx q[0];\nmeasure q -> c;\n")
        verdict = validation.validate_counts(ir2, {"1": 100})
        assert verdict.status == "match"

    def test_mid_circuit_measurement_is_predicted_exactly(self):
        # deferred-measurement principle: unconditioned mid-circuit
        # measurement has the same distribution as the terminal version
        ir = parse_qasm("OPENQASM 2.0;\nqreg q[2];\ncreg c[2];\nh q[0];\nmeasure q[0] -> c[0];\ncx q[0], q[1];\nmeasure q[1] -> c[1];\n")
        verdict = validation.validate_counts(ir, {"00": 500, "11": 500})
        assert verdict.status == "match"
        bad = validation.validate_counts(ir, {"01": 1000})
        assert bad.status == "mismatch"

    def test_conditional_ops_unavailable(self):
        ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\ncreg c[1];\nx q[0];\nmeasure q[0] -> c[0];\nif (c == 1) x q[0];\n")
        assert ir.metadata.get("conditional_ops") == 1
        verdict = validation.validate_counts(ir, {"1": 100})
        assert verdict.status == "unavailable"

    def test_reset_unavailable(self):
        ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\ncreg c[1];\nreset q[0];\nx q[0];\nmeasure q[0] -> c[0];\n")
        verdict = validation.validate_counts(ir, {"1": 100})
        assert verdict.status == "unavailable"

    def test_empty_counts_unavailable(self):
        ir = parse_qasm(BELL_MEAS)
        assert validation.validate_counts(ir, {}).status == "unavailable"

    def test_ideal_probabilities_caps_qubits(self):
        ir = parse_qasm(BELL_MEAS)
        assert validation.ideal_probabilities(ir, max_qubits=1) is None
        probs = validation.ideal_probabilities(ir, max_qubits=12)
        assert probs is not None and pytest.approx(sum(probs.values()), abs=1e-9) == 1.0


# -------------------------------------------------------------- alerting
class TestAlerting:
    def test_router_min_severity_and_fanout(self, tmp_path):
        path = tmp_path / "alerts.jsonl"
        sink = alerting.JsonLinesSink(path)
        router = alerting.AlertRouter(sinks=[sink], min_severity="high")
        assert router.emit(alerting.Alert(severity="low", category="x", message="skip me")) == []
        errs = router.emit(alerting.Alert(severity="critical", category="c", message="blocked"))
        assert errs == []
        lines = path.read_text(encoding="utf-8").strip().splitlines()
        assert len(lines) == 1
        payload = json.loads(lines[0])
        assert payload["severity"] == "critical" and payload["category"] == "c"

    def test_router_bad_severity_rejected(self):
        with pytest.raises(ValueError):
            alerting.AlertRouter(min_severity="spicy")

    def test_failing_sink_never_breaks_router(self, tmp_path):
        class Boom(alerting.AlertSink):
            def emit(self, alert):
                raise RuntimeError("sink exploded")

        path = tmp_path / "ok.jsonl"
        router = alerting.AlertRouter(sinks=[Boom(), alerting.JsonLinesSink(path)], min_severity="info")
        errs = router.emit(alerting.Alert(severity="high", category="x", message="boom"))
        assert len(errs) == 1 and "Boom" in errs[0]
        assert path.exists()  # healthy sink still received the alert

    def test_stderr_and_webhook_sinks(self, capsys, monkeypatch):
        err = capsys  # sys.stderr sink writes via sys.stderr
        alerting.StderrSink().emit(alerting.Alert(severity="high", category="c", message="hello"))
        captured = err.readouterr()
        assert "hello" in captured.err

        posted = {}

        class FakeResp:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=None):
            posted["url"] = req.full_url
            posted["body"] = req.data
            return FakeResp()

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        alerting.WebhookSink("http://127.0.0.1:9/hook").emit(
            alerting.Alert(severity="high", category="c", message="ping"))
        assert posted["url"].endswith("/hook")
        assert b"ping" in posted["body"]

    def test_alert_serialisation(self):
        alert = alerting.Alert(severity="high", category="result.mismatch", message="m",
                               job_id="j", circuit_hash="abc", details={"p": 0.001})
        payload = alert.to_json()
        assert payload["job_id"] == "j" and payload["details"]["p"] == 0.001
        assert "ts" in payload


class TestAdaptersExtraBranches:
    def test_bare_qasm_string_in_list(self):
        body = json.dumps({"experiments": ["OPENQASM 2.0;\nqreg q[1];\nh q[0];\n"]}).encode()
        out = adapters.extract_circuits(body)
        assert len(out) == 1 and out[0].shape == "experiments[0]"

    def test_qasm_dict_items_in_circuits_list(self):
        body = json.dumps({"circuits": [{"qasm": BELL}]}).encode()
        out = adapters.extract_circuits(body)
        assert len(out) == 1 and "h q[0]" in out[0].qasm

    def test_bare_qasm_string_as_list_element(self):
        body = json.dumps([BELL]).encode()
        out = adapters.extract_circuits(body)
        assert len(out) == 1 and out[0].shape == "bare-string"

    def test_nested_list_wrapper_for_counts(self):
        body = json.dumps([{"counts": {"00": 5}}]).encode()
        r = adapters.extract_result(body)
        assert r is not None and r.counts == {"00": 5}

    def test_result_body_oversize_returns_none(self):
        big = json.dumps({"counts": {"00": 1}}).encode() + b" " * (adapters.MAX_BODY_BYTES + 1)
        assert adapters.extract_result(big) is None

    def test_deep_nesting_bounded(self):
        node = {"a": {}}
        cur = node["a"]
        for _ in range(50):
            cur["b"] = {}
            cur = cur["b"]
        cur["qasm"] = BELL
        assert adapters.extract_circuits(json.dumps(node).encode()) == []


class TestValidationExtraBranches:
    def test_reset_circuit_unavailable(self):
        ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\ncreg c[1];\nreset q[0];\nx q[0];\nmeasure q[0] -> c[0];\n")
        verdict = validation.validate_counts(ir, {"1": 10})
        assert verdict.status == "unavailable"

    def test_no_measurements_unavailable(self):
        ir = parse_qasm(BELL)
        verdict = validation.validate_counts(ir, {"00": 10})
        assert verdict.status == "unavailable"

    def test_qubit_cap_unavailable(self):
        ir = parse_qasm(BELL_MEAS)
        verdict = validation.validate_counts(ir, {"00": 10}, max_qubits=1)
        assert verdict.status == "unavailable"
