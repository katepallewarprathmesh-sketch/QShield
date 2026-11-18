"""Per-run coverage reports remain distinct from clean findings."""

import json
from pathlib import Path

from qshield.scanner import Scanner

BELL = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n"


def test_static_run_emits_per_circuit_coverage_in_all_exports():
    scanner = Scanner(signatures="disabled")
    scanner.add_circuit(BELL, name="bell")
    result = scanner.run(analyses=["static"])

    coverage = result.to_dict()["coverage"]
    assert coverage["spec_version"] == "qshield-coverage-v1"
    assert coverage["overall_status"] == "complete"
    assert coverage["summary"]["circuits_processed"] == 1
    circuit = coverage["circuits"][0]
    assert circuit["processed"] is True
    assert circuit["analyses"]["static"]["status"] == "completed"
    assert {check["id"] for check in circuit["analyses"]["static"]["checks"]} == {
        "structural_analysis", "signature_matching", "expected_unitary",
        "ancilla_independence", "parser_coverage",
    }
    assert coverage["supply_chain"]["status"] == "not_run"

    sarif = json.loads(result.to_sarif())
    assert sarif["runs"][0]["properties"]["qshieldCoverage"] == coverage
    html = result.to_html()
    assert "Analysis coverage: complete" in html
    assert "No findings were emitted; consult the analysis coverage" in html


def test_global_timeout_marks_requested_analyses_not_run():
    scanner = Scanner(signatures="disabled")
    scanner.add_circuit(BELL, name="bell")
    result = scanner.run(analyses=["static", "dynamic"], timeout=0)

    coverage = result.coverage
    assert coverage["overall_status"] == "inconclusive"
    circuit = coverage["circuits"][0]
    assert not circuit["processed"]
    assert circuit["analyses"]["static"]["status"] == "not_run"
    assert circuit["analyses"]["dynamic"]["status"] == "not_run"
    assert coverage["summary"]["requested_pipeline_runs_not_started"] == 2


def test_dynamic_skip_is_inconclusive_and_not_clean_coverage(monkeypatch):
    scanner = Scanner(signatures="disabled")
    scanner.add_circuit(BELL, name="bell")

    def skipped(self, circuit, shots, warnings):
        warnings.append("optional backend missing")
        from qshield.reporting.coverage import coverage_item
        return [], coverage_item("skipped", "optional backend missing", shots=shots)

    monkeypatch.setattr(Scanner, "_run_dynamic", skipped)
    result = scanner.run(analyses=["dynamic"], dynamic_shots=321)
    coverage = result.coverage
    dynamic = coverage["circuits"][0]["analyses"]["dynamic"]
    assert dynamic["status"] == "skipped"
    assert dynamic["reasons"] == ["optional backend missing"]
    assert dynamic["details"]["shots"] == 321
    assert coverage["overall_status"] == "inconclusive"
    assert result.to_dict()["coverage_complete"] is False


def test_formal_without_reference_is_explicitly_inconclusive(monkeypatch):
    scanner = Scanner(signatures="disabled")
    scanner.add_circuit(BELL, name="bell")
    monkeypatch.setattr("qshield.formal.pyzx_available", lambda: True)
    coverage = scanner.run(analyses=["formal"]).coverage
    formal = coverage["circuits"][0]["analyses"]["formal"]
    assert formal["status"] == "skipped"
    assert "no expected artifact" in formal["reasons"][0]


def test_empty_circuit_run_and_unknown_analysis_are_inconclusive():
    scanner = Scanner(signatures="disabled")
    coverage = scanner.run(analyses=["static", "future_check"]).coverage
    assert coverage["overall_status"] == "inconclusive"
    assert coverage["unsupported_analyses"] == ["future_check"]
    assert coverage["summary"]["requested_pipeline_runs_not_started"] == 1
    assert coverage["summary"]["by_analysis"]["static"]["not_run"] == 1


def test_coverage_schema_accepts_generated_result():
    try:
        import jsonschema
    except ImportError:
        return
    schema_path = Path(__file__).parents[2] / "src/qshield/reporting/coverage-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    scanner = Scanner(signatures="disabled")
    scanner.add_circuit(BELL, name="bell")
    jsonschema.validate(scanner.run(analyses=["static"]).coverage, schema)
