"""Offline provenance manifest and Ed25519 signing tests."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qshield.cli.main import app
from qshield.provenance import (
    PrivateKeyPassphraseRequired,
    ProvenanceError,
    create_manifest,
    generate_keypair,
    load_manifest,
    sign_manifest,
    verify_manifest,
    write_manifest,
)

runner = CliRunner()
QASM = "OPENQASM 2.0;\nqreg q[2];\ncreg c[2];\nh q[0];\ncx q[0], q[1];\nmeasure q -> c;\n"


def _source(path: Path, text: str = QASM) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def test_create_sign_verify_and_check_source_offline(tmp_path):
    circuit = _source(tmp_path / "bell.qasm")
    private_path = tmp_path / "private.pem"
    public_path = tmp_path / "public.pem"
    key_id = generate_keypair(private_path, public_path, passphrase=b"correct horse battery staple")
    if os.name != "nt":
        assert private_path.stat().st_mode & 0o777 == 0o600

    unsigned = create_manifest(circuit)
    assert unsigned["spec_version"] == "qshield-provenance-v1"
    assert unsigned["subject"]["canonicalization_spec"] == "qshield-circuit-c14n-v1"
    assert str(tmp_path) not in json.dumps(unsigned)
    with pytest.raises(PrivateKeyPassphraseRequired):
        sign_manifest(unsigned, private_path.read_bytes())

    signed = sign_manifest(unsigned, private_path.read_bytes(), passphrase=b"correct horse battery staple")
    assert signed["signature"]["key_id"] == key_id
    manifest_path = tmp_path / "manifest.json"
    write_manifest(manifest_path, signed)
    loaded = load_manifest(manifest_path)
    result = verify_manifest(loaded, public_path.read_bytes(), circuit_path=circuit)
    assert result.key_id == key_id
    assert result.source_verified is True
    assert result.circuit_sha256 == unsigned["subject"]["circuit_sha256"]


def test_tampered_manifest_wrong_key_and_changed_source_are_rejected(tmp_path):
    circuit = _source(tmp_path / "bell.qasm")
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    wrong_private = tmp_path / "wrong-private.pem"
    wrong_public = tmp_path / "wrong-public.pem"
    generate_keypair(private, public, passphrase=b"pass")
    generate_keypair(wrong_private, wrong_public, passphrase=b"pass")
    signed = sign_manifest(create_manifest(circuit), private.read_bytes(), passphrase=b"pass")

    with pytest.raises(ProvenanceError, match="does not match"):
        verify_manifest(signed, wrong_public.read_bytes())

    tampered = json.loads(json.dumps(signed))
    tampered["subject"]["circuit_sha256"] = "0" * 64
    with pytest.raises(ProvenanceError, match="signature is invalid"):
        verify_manifest(tampered, public.read_bytes())

    _source(circuit, QASM + "x q[0];\n")
    with pytest.raises(ProvenanceError, match="source does not match"):
        verify_manifest(signed, public.read_bytes(), circuit_path=circuit)


def test_duplicate_json_fields_and_existing_key_files_are_rejected(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"spec_version":"x","spec_version":"y"}', encoding="utf-8")
    with pytest.raises(ProvenanceError, match="duplicate JSON field"):
        load_manifest(duplicate)

    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    private.write_text("keep", encoding="utf-8")
    with pytest.raises(ProvenanceError, match="could not create key files"):
        generate_keypair(private, public, passphrase=b"pass")
    assert private.read_text(encoding="utf-8") == "keep"
    assert not public.exists()


def test_cli_keygen_create_sign_verify_flow(tmp_path):
    circuit = _source(tmp_path / "bell.qasm")
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    manifest = tmp_path / "manifest.json"

    result = runner.invoke(
        app,
        ["provenance", "keygen", "--private-key", str(private), "--public-key", str(public)],
        input="test passphrase\ntest passphrase\n",
    )
    assert result.exit_code == 0, result.output
    assert "Created Ed25519 keypair" in result.output

    result = runner.invoke(app, ["provenance", "create", str(circuit), "--output", str(manifest)])
    assert result.exit_code == 0, result.output
    assert "Wrote unsigned provenance manifest" in result.output

    result = runner.invoke(
        app,
        ["provenance", "sign", str(manifest), "--private-key", str(private)],
        input="test passphrase\n",
    )
    assert result.exit_code == 0, result.output
    assert "Signed provenance manifest" in result.output

    result = runner.invoke(app, [
        "provenance", "verify", str(manifest), "--public-key", str(public), "--circuit", str(circuit),
    ])
    assert result.exit_code == 0, result.output
    assert "Signature valid" in result.output
    assert "Source and canonical circuit digests match" in result.output
