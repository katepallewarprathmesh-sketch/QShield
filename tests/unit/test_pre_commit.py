from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from qshield.pre_commit import main

REPO_ROOT = Path(__file__).resolve().parents[2]
CLEAN = REPO_ROOT / "tests" / "fixtures" / "clean_circuits" / "bell_state.qasm"
MALICIOUS = REPO_ROOT / "tests" / "fixtures" / "malicious_circuits" / "ancilla_leakage.qasm"


def test_pre_commit_manifest_declares_scoped_qasm_hook():
    manifest = yaml.safe_load((REPO_ROOT / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
    assert len(manifest) == 1
    hook = manifest[0]
    assert hook["id"] == "qshield-scan"
    assert hook["language"] == "python"
    assert hook["require_serial"] is True
    assert "qasm" in hook["files"]


def test_clean_circuit_passes(capsys: pytest.CaptureFixture[str]):
    assert main([str(CLEAN)]) == 0
    assert "no findings" in capsys.readouterr().out


def test_high_severity_finding_fails_by_default(capsys: pytest.CaptureFixture[str]):
    assert main([str(MALICIOUS)]) == 1
    assert "HIGH T2.1" in capsys.readouterr().out


def test_fail_on_never_suppresses_finding_exit(capsys: pytest.CaptureFixture[str]):
    assert main(["--fail-on", "never", str(MALICIOUS)]) == 0
    assert "HIGH T2.1" in capsys.readouterr().out


def test_parse_errors_fail_closed(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    invalid = tmp_path / "broken.qasm"
    invalid.write_text("OPENQASM 2.0; this is not a valid circuit;", encoding="utf-8")
    assert main([str(invalid)]) == 2
    assert "could not scan" in capsys.readouterr().err


def test_non_qasm_existing_file_is_rejected(tmp_path: Path, capsys: pytest.CaptureFixture[str]):
    invalid = tmp_path / "circuit.py"
    invalid.write_text("print('not executed')", encoding="utf-8")
    assert main([str(invalid)]) == 2
    assert "unsupported file type" in capsys.readouterr().err


def test_deleted_path_is_ignored(tmp_path: Path):
    assert main([str(tmp_path / "deleted.qasm")]) == 0
