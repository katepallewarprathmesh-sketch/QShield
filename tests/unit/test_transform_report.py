"""Tests for the transpilation-aware step report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qshield.cli.main import app
from qshield.provenance.transforms import TransformReportError, build_transform_report

runner = CliRunner()


def _qasm(path: Path, body: str) -> Path:
    path.write_text("OPENQASM 2.0;\n" + body, encoding="utf-8")
    return path


def test_equivalent_and_not_equivalent_steps_have_digests_and_methods(tmp_path):
    hh = _qasm(tmp_path / "hh.qasm", "qreg q[1];\nh q[0];\nh q[0];\n")
    identity = _qasm(tmp_path / "identity.qasm", "qreg q[1];\nid q[0];\n")
    x_gate = _qasm(tmp_path / "x.qasm", "qreg q[1];\nx q[0];\n")

    equivalent = build_transform_report(hh, [("cancel-h-pair", identity)])
    step = equivalent["transforms"][0]
    assert equivalent["overall_status"] == "equivalent"
    assert step["comparison"]["status"] == "equivalent"
    assert step["comparison"]["method"] == "exact_unitary"
    assert step["before"]["circuit_sha256"] != step["after"]["circuit_sha256"]

    different = build_transform_report(identity, [("inject-x", x_gate)])
    assert different["overall_status"] == "not_equivalent"
    assert different["transforms"][0]["comparison"]["status"] == "not_equivalent"


def test_pipeline_is_sequential_and_inconclusive_is_not_a_pass(tmp_path):
    source = _qasm(tmp_path / "source.qasm", "qreg q[2];\nh q[0];\n")
    same = _qasm(tmp_path / "same.qasm", "qreg q[2];\nh q[0];\n")
    different_measurement = _qasm(
        tmp_path / "measured.qasm",
        "qreg q[2];\ncreg c[2];\nmeasure q[1] -> c[1];\n",
    )
    report = build_transform_report(source, [("format", same), ("measure", different_measurement)])
    assert report["transforms"][0]["comparison"]["status"] == "equivalent"
    assert report["transforms"][1]["before"] == report["transforms"][0]["after"]
    assert report["transforms"][1]["comparison"]["status"] == "inconclusive"
    assert report["overall_status"] == "inconclusive"
    assert "reported separately" in report["limitations"][1]


def test_invalid_stage_and_tolerance_are_rejected(tmp_path):
    source = _qasm(tmp_path / "source.qasm", "qreg q[1];\nh q[0];\n")
    with pytest.raises(TransformReportError, match="at least one"):
        build_transform_report(source, [])
    with pytest.raises(TransformReportError, match="invalid stage label"):
        build_transform_report(source, [("bad label", source)])
    with pytest.raises(TransformReportError, match="positive"):
        build_transform_report(source, [("pass", source)], tolerance=0)


def test_cli_writes_json_and_returns_nonzero_for_inconclusive(tmp_path):
    source = _qasm(tmp_path / "source.qasm", "qreg q[2];\nh q[0];\n")
    measured = _qasm(
        tmp_path / "measured.qasm",
        "qreg q[2];\ncreg c[2];\nmeasure q[1] -> c[1];\n",
    )
    output = tmp_path / "transform.json"
    result = runner.invoke(app, [
        "provenance", "transform-report", str(source),
        "--stage", f"measure={measured}", "--output", str(output),
    ])
    assert result.exit_code == 2, result.output
    assert "INCONCLUSIVE" in result.output
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["spec_version"] == "qshield-transform-report-v1"
    assert report["overall_status"] == "inconclusive"
