import json

from qshield.reporting import to_sarif
from qshield.reporting.finding import CircuitLocation, Evidence, Finding
from qshield.scanner import Scanner


def sample_findings():
    return [
        Finding(
            severity="high", threat_type="T1.3", title="Test finding",
            description="A test finding", circuit_id="c1",
            location=CircuitLocation(gate_ids=["g1", "g2"], gate_indices=[0, 1], qubit_indices=[0]),
            evidence=Evidence(evidence_type="structural", details={"k": 1}),
            confidence=0.8, remediation="fix it",
        )
    ]


def test_sarif_structure():
    sarif = to_sarif(sample_findings())
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "QSHIELD"
    assert run["results"][0]["ruleId"].startswith("QSHIELD-")
    assert run["results"][0]["level"] == "error"
    # round-trips as JSON
    json.dumps(sarif)


def test_json_export(tmp_path):
    circuit = tmp_path / "bell.qasm"
    circuit.write_text("OPENQASM 2.0;\nqreg q[1];\nx q[0];\n")
    scanner = Scanner()
    scanner.add_circuit(str(circuit))
    results = scanner.run()
    payload = json.loads(results.to_json())
    assert payload["tool"]["name"] == "QSHIELD"
    assert payload["summary"]["circuits_scanned"] == 1
    assert "findings" in payload


def test_html_export_self_contained(tmp_path):
    circuit = tmp_path / "backdoor.qasm"
    # cancelling CX pair -> finding WITH evidence details (exercises tojson path)
    circuit.write_text("OPENQASM 2.0;\nqreg q[2];\ncreg c[2];\ncx q[0], q[1];\ncx q[0], q[1];\nmeasure q -> c;\n")
    scanner = Scanner()
    scanner.add_circuit(str(circuit), name="backdoor")
    results = scanner.run()
    html = results.to_html()
    assert "<!DOCTYPE html>" in html
    assert "QSHIELD" in html
    assert "http://" not in html  # no external resources (embedded CSS)
    assert "latin1" not in html


def test_finding_to_dict():
    d = sample_findings()[0].to_dict()
    assert d["severity"] == "high"
    assert d["severity_rank"] == 3
    assert d["location"]["gate_ids"] == ["g1", "g2"]
