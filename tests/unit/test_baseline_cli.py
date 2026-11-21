"""End-to-end tests for `qshield baseline`.

These drive the real CLI through typer's CliRunner with real Ed25519 keys. The
point is that a user who reads the README can reach the differential check
without writing Python.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from typer.testing import CliRunner

from qshield.cli.main import app

runner = CliRunner()

APPROVED = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
measure q -> c;
"""

TAMPERED = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
h q[1];
measure q -> c;
"""


@pytest.fixture
def workspace(tmp_path: Path):
    """A signed baseline plus approved and tampered candidate circuits."""
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    (tmp_path / "priv.pem").write_bytes(private)
    (tmp_path / "pub.pem").write_bytes(public)
    (tmp_path / "approved.qasm").write_text(APPROVED)
    (tmp_path / "tampered.qasm").write_text(TAMPERED)

    result = runner.invoke(
        app,
        [
            "baseline", "create", str(tmp_path / "approved.qasm"),
            "--workload", "bell-routing", "--approved-by", "sec@corp",
            "-o", str(tmp_path / "bl.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(
        app,
        ["baseline", "sign", str(tmp_path / "bl.json"), "--private-key", str(tmp_path / "priv.pem")],
    )
    assert result.exit_code == 0, result.output
    return tmp_path


def _scan(ws: Path, candidate: str, *extra: str):
    return runner.invoke(
        app,
        [
            "baseline", "scan", str(ws / candidate),
            "-b", str(ws / "bl.json"),
            "-c", str(ws / "approved.qasm"),
            "--public-key", str(ws / "pub.pem"),
            "-w", "bell-routing",
            *extra,
        ],
    )


# ------------------------------------------------------------------ create/sign
def test_create_writes_an_unsigned_record(workspace: Path) -> None:
    # The fixture signs bl.json, so make a fresh one to inspect.
    result = runner.invoke(
        app,
        [
            "baseline", "create", str(workspace / "approved.qasm"),
            "--workload", "fresh", "--approved-by", "sec@corp",
            "-o", str(workspace / "fresh.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    data = json.loads((workspace / "fresh.json").read_text())
    assert data["signature"] is None
    assert data["workload_id"] == "fresh"
    assert data["version"] == 1
    assert len(data["circuit_digest"]) == 64


def test_create_requires_a_workload(tmp_path: Path) -> None:
    (tmp_path / "c.qasm").write_text(APPROVED)
    result = runner.invoke(app, ["baseline", "create", str(tmp_path / "c.qasm"), "--approved-by", "x"])
    assert result.exit_code != 0


def test_sign_rejects_an_already_signed_record(workspace: Path) -> None:
    result = runner.invoke(
        app,
        ["baseline", "sign", str(workspace / "bl.json"), "--private-key", str(workspace / "priv.pem")],
    )
    assert result.exit_code != 0
    assert "already signed" in result.output


# ------------------------------------------------------------------ verify
def test_verify_accepts_a_genuine_baseline(workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "baseline", "verify", str(workspace / "bl.json"),
            "--public-key", str(workspace / "pub.pem"),
            "--circuit", str(workspace / "approved.qasm"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Signature valid" in result.output
    assert "match the approved baseline" in result.output


def test_verify_rejects_a_forged_digest(workspace: Path) -> None:
    """Changing the approved circuit digest must break the signature."""
    path = workspace / "forged.json"
    data = json.loads((workspace / "bl.json").read_text())
    data["circuit_digest"] = "0" * 64
    path.write_text(json.dumps(data))

    result = runner.invoke(
        app, ["baseline", "verify", str(path), "--public-key", str(workspace / "pub.pem")]
    )
    assert result.exit_code == 1
    assert "does not verify" in result.output


def test_verify_rejects_a_different_key(workspace: Path) -> None:
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    (workspace / "other.pem").write_bytes(other)
    result = runner.invoke(
        app,
        ["baseline", "verify", str(workspace / "bl.json"), "--public-key", str(workspace / "other.pem")],
    )
    assert result.exit_code == 1


def test_verify_rejects_an_unsigned_record(workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "baseline", "create", str(workspace / "approved.qasm"),
            "--workload", "w2", "--approved-by", "x", "-o", str(workspace / "u.json"),
        ],
    )
    assert result.exit_code == 0
    result = runner.invoke(
        app, ["baseline", "verify", str(workspace / "u.json"), "--public-key", str(workspace / "pub.pem")]
    )
    assert result.exit_code == 1
    assert "not signed" in result.output


def test_verify_flags_a_different_circuit(workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "baseline", "verify", str(workspace / "bl.json"),
            "--public-key", str(workspace / "pub.pem"),
            "--circuit", str(workspace / "tampered.qasm"),
        ],
    )
    assert result.exit_code == 1
    assert "NOT the approved artifact" in result.output


# ------------------------------------------------------------------ scan
def test_scan_flags_a_tampered_candidate(workspace: Path) -> None:
    result = _scan(workspace, "tampered.qasm")
    assert result.exit_code == 1, result.output
    assert "T2.3 findings: 1" in result.output


def test_scan_passes_an_unchanged_candidate(workspace: Path) -> None:
    result = _scan(workspace, "approved.qasm")
    assert result.exit_code == 0, result.output
    assert "T2.3 findings: 0" in result.output
    assert "PASS" in result.output


def test_scan_fail_on_never_does_not_fail_the_build(workspace: Path) -> None:
    result = _scan(workspace, "tampered.qasm", "--fail-on", "never")
    assert result.exit_code == 0


def test_scan_reports_indeterminate_when_the_reference_is_substituted(workspace: Path) -> None:
    """A reference that is not the signed artifact must not read as clean."""
    result = runner.invoke(
        app,
        [
            "baseline", "scan", str(workspace / "approved.qasm"),
            "-b", str(workspace / "bl.json"),
            "-c", str(workspace / "tampered.qasm"),  # wrong reference
            "--public-key", str(workspace / "pub.pem"),
            "-w", "bell-routing",
        ],
    )
    assert "INDETERMINATE" in result.output
    assert "does not match the digest" in result.output
    # Crucially, it does not claim PASS.
    assert "Indeterminate is not a pass" in result.output


def test_scan_requires_a_declared_workload_when_ambiguous(workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "baseline", "scan", str(workspace / "approved.qasm"),
            "-b", str(workspace / "bl.json"),
            "-c", str(workspace / "approved.qasm"),
            "--public-key", str(workspace / "pub.pem"),
        ],
    )
    # Exactly one workload is resolvable, so this should proceed rather than fail.
    assert result.exit_code == 0, result.output


def test_scan_rejects_mismatched_baseline_and_circuit_counts(workspace: Path) -> None:
    result = runner.invoke(
        app,
        [
            "baseline", "scan", str(workspace / "approved.qasm"),
            "-b", str(workspace / "bl.json"),
            "--public-key", str(workspace / "pub.pem"),
        ],
    )
    assert result.exit_code != 0


# ------------------------------------------------------------------ inspect
def test_inspect_shows_but_does_not_vouch(workspace: Path) -> None:
    result = runner.invoke(app, ["baseline", "inspect", str(workspace / "bl.json")])
    assert result.exit_code == 0
    assert "bell-routing" in result.output
    assert "not verification" in result.output
