"""Unit tests for the M3.4 community signature pack machinery."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qshield.cli.main import app
from qshield.signatures import community, updater
from qshield.signatures.updater import UpdateError

runner = CliRunner()

GOOD_SIG = '''id: "QSig-2026-0001"
name: "Test Inverse Pair"
version: "1.0"
author: "Unit Test <t@example.org>"
date: "2026-11-12"
severity: "low"
threat_type: "T1.3"
description: Test signature used only by unit tests.
detection:
  method: "structural"
  structural_pattern:
    type: "gate_sequence_inverse"
    window: 4
    tolerance: 1.0e-6
references:
  - "spec://QSHIELD/2.1#T1.3"
false_positive_probability: 0.5
remediation: "Remove the pair."
'''

BELL_H_PAIR = "OPENQASM 2.0;\nqreg q[1];\nh q[0];\nh q[0];\n"          # fires (h-h cancels)
BELL = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n"         # no cancelling pair


def _make_pack(tmp_path: Path, name: str = "src_pack") -> Path:
    pack = tmp_path / name
    pack.mkdir()
    (pack / "QSig-2026-0001.yaml").write_text(GOOD_SIG, encoding="utf-8")
    updater.build_manifest(pack, "2026.2")
    return pack


# ------------------------------------------------------------ manifest
def test_bundled_pack_verifies_clean():
    assert community.verify_pack() == []


def test_build_manifest_and_verify_roundtrip(tmp_path):
    pack = _make_pack(tmp_path)
    errors = community.verify_pack(pack)
    assert errors == []
    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["pack_version"] == "2026.2"
    assert [f["name"] for f in manifest["files"]] == ["QSig-2026-0001.yaml"]


def test_verify_pack_detects_drift(tmp_path):
    pack = _make_pack(tmp_path)
    target = pack / "QSig-2026-0001.yaml"
    target.write_text(target.read_text(encoding="utf-8") + "\n# drift\n", encoding="utf-8")
    errors = community.verify_pack(pack)
    assert any("sha256 drift" in e for e in errors)


# ------------------------------------------------------------- updater
def test_update_offline_installs_bundled_pack(tmp_path):
    install = tmp_path / "installed"
    report = updater.update(offline=True, install_dir=install)
    assert report.ok
    assert (install / "manifest.json").exists()


def test_update_from_file_url_installs_valid_pack(tmp_path):
    pack = _make_pack(tmp_path)
    install = tmp_path / "installed"
    report = updater.update(url=str(pack / "manifest.json"), install_dir=install)
    assert report.ok and report.installed_files == 1
    assert (install / "QSig-2026-0001.yaml").exists()


def test_update_rejects_tampered_pack_and_keeps_existing(tmp_path):
    pack = _make_pack(tmp_path)
    install = tmp_path / "installed"
    updater.update(url=str(pack / "manifest.json"), install_dir=install)
    # tamper with the file without updating the manifest
    (pack / "QSig-2026-0001.yaml").write_text(GOOD_SIG.replace("Test Inverse Pair", "Evil"), encoding="utf-8")
    with pytest.raises(UpdateError, match="sha256"):
        updater.update(url=str(pack / "manifest.json"), install_dir=install)
    # existing install untouched (still has the good signature)
    assert "Evil" not in (install / "QSig-2026-0001.yaml").read_text(encoding="utf-8")


def test_update_rejects_schema_invalid_signature(tmp_path):
    pack = tmp_path / "src_pack"
    pack.mkdir()
    (pack / "QSig-2026-0002.yaml").write_text("id: nope\n", encoding="utf-8")
    updater.build_manifest(pack, "2026.3")
    install = tmp_path / "installed"
    report = updater.update(url=str(pack / "manifest.json"), install_dir=install)
    assert not report.ok
    assert any("QSig-2026-0002" in e for e in report.errors)
    assert not install.exists()


def test_rollback_restores_previous_pack(tmp_path):
    pack = _make_pack(tmp_path)
    install = tmp_path / "installed"
    updater.update(url=str(pack / "manifest.json"), install_dir=install)
    updater.update(url=str(pack / "manifest.json"), install_dir=install)  # creates .bak
    assert updater.rollback(install)
    assert install.exists()
    # .bak was consumed by the rollback, so a second rollback reports nothing to restore
    assert updater.rollback(install) is False


def test_installed_status_empty_home(tmp_path):
    status = updater.installed_status(tmp_path / "nope")
    assert status["installed"] is False
    assert status["files"] == 0


# ------------------------------------------------------------ CLI: sig
def test_cli_id_suggest_format():
    result = runner.invoke(app, ["sig", "id-suggest"])
    assert result.exit_code == 0
    assert result.output.strip().startswith("QSig-")


def test_cli_validate_builtin_ok():
    from qshield.signatures import builtin_signatures

    sample = builtin_signatures()[0]
    assert sample.source_path
    result = runner.invoke(app, ["sig", "validate", sample.source_path])
    assert result.exit_code == 0, result.output


def test_cli_validate_rejects_bad_file(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("id: not-an-id\n", encoding="utf-8")
    result = runner.invoke(app, ["sig", "validate", str(bad)])
    assert result.exit_code == 1


def test_cli_new_scaffolds_valid_template(tmp_path):
    out = tmp_path / "new_sig.yaml"
    result = runner.invoke(app, ["sig", "new", "T2.2", "--severity", "high",
                                 "--name", "Unit Test Sig", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists()
    result = runner.invoke(app, ["sig", "validate", str(out)])
    assert result.exit_code == 0, result.output


def test_cli_new_rejects_bad_threat_type(tmp_path):
    result = runner.invoke(app, ["sig", "new", "T9.9", "--out", str(tmp_path / "x.yaml")])
    assert result.exit_code == 2


def _tiny_corpus(tmp_path: Path) -> tuple[Path, Path]:
    mal = tmp_path / "mal"
    clean = tmp_path / "clean"
    mal.mkdir()
    clean.mkdir()
    (mal / "fires.qasm").write_text(BELL_H_PAIR, encoding="utf-8")
    (clean / "nomatch.qasm").write_text(BELL, encoding="utf-8")
    return mal, clean


def test_cli_test_gate_passes_and_fails(tmp_path):
    sig = tmp_path / "sig.yaml"
    sig.write_text(GOOD_SIG, encoding="utf-8")
    mal, clean = _tiny_corpus(tmp_path)
    ok = runner.invoke(app, ["sig", "test", str(sig),
                             "--malicious-dir", str(mal), "--clean-dir", str(clean),
                             "--min-tpr", "0.5", "--max-fpr", "0.1"])
    assert ok.exit_code == 0, ok.output
    fail = runner.invoke(app, ["sig", "test", str(sig),
                               "--malicious-dir", str(mal), "--clean-dir", str(clean),
                               "--min-tpr", "1.1", "--max-fpr", "0.1"])
    assert fail.exit_code == 1


def test_cli_update_offline_and_status_and_rollback(tmp_path):
    install = tmp_path / "installed"
    result = runner.invoke(app, ["sig", "update", "--offline", "--install-dir", str(install)])
    assert result.exit_code == 0, result.output
    result = runner.invoke(app, ["sig", "status", "--install-dir", str(install)])
    assert result.exit_code == 0
    assert "installed pack" in result.output
    result = runner.invoke(app, ["sig", "rollback", "--install-dir", str(install)])
    # no previous backup on a first install
    assert result.exit_code == 1


def test_scanner_prefers_builtin_plus_community(tmp_path):
    """Default scan loads builtin signatures; community flag toggles the community pack."""
    from qshield.scanner import Scanner

    scanner = Scanner(config="strict")
    # spec default config has use_community: false; community pack is opt-in
    assert getattr(scanner.config, "signatures_community", None) is False
    scanner.add_circuit(BELL, name="smoke")
    res = scanner.run()
    assert res is not None  # must not crash with the community wiring in place

    scanner = Scanner(config="strict")
    scanner.config.signatures_community = True
    scanner.add_circuit(BELL, name="smoke2")
    res = scanner.run()
    assert res is not None


# ------------------------------------------------------ error paths
def test_fetch_bytes_file_url_and_missing(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"abc")
    assert updater._fetch_bytes(f"file://{f}") == b"abc"
    with pytest.raises(UpdateError, match="not found"):
        updater._fetch_bytes(str(tmp_path / "nope.bin"))


def test_fetch_bytes_http_failure_raises():
    with pytest.raises(UpdateError, match="failed to fetch"):
        updater._fetch_bytes("http://127.0.0.1:1/manifest.json", timeout=2)


def test_pack_base_url_variants():
    assert updater._pack_base_url("https://h/pkg/manifest.json") == "https://h/pkg/"
    assert updater._pack_base_url("https://h/pkg/") == "https://h/pkg/"


def test_read_manifest_rejects_garbage_and_bad_shapes(tmp_path):
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json", encoding="utf-8")
    with pytest.raises(UpdateError, match="not valid JSON"):
        updater.read_manifest(str(bad_json))
    for doc, msg in (([1, 2], "must be a JSON object"),
                     ({"no_files": 1}, "'files' array"),
                     ({"files": [{"name": "x.yaml"}]}, "'name' and 'sha256'"),
                     ({"files": ["x.yaml"]}, "'name' and 'sha256'")):
        p = tmp_path / "m.json"
        p.write_text(json.dumps(doc), encoding="utf-8")
        with pytest.raises(UpdateError, match=msg):
            updater.read_manifest(str(p))


def test_verify_and_load_files_error_matrix():
    assert updater.verify_and_load_files({"a.yaml": b"\xff\xfe\x00bad"})            # non-UTF8
    assert any("YAML" in e for e in updater.verify_and_load_files({"b.yaml": b"a: [unclosed"}))
    assert any("mapping" in e for e in updater.verify_and_load_files({"c.yaml": b"- just\n- a\n- list\n"}))
    assert any("missing required keys" in e or "id" in e
               for e in updater.verify_and_load_files({"d.yaml": b"id: nope\n"}))
    # valid file passes cleanly
    assert updater.verify_and_load_files({"e.yaml": GOOD_SIG.encode()}) == []


def test_update_uses_env_var(tmp_path, monkeypatch):
    pack = _make_pack(tmp_path)
    install = tmp_path / "installed"
    monkeypatch.setenv("QSHIELD_SIGNATURE_REPO", str(pack / "manifest.json"))
    report = updater.update(install_dir=install)
    assert report.ok and report.source == str(pack / "manifest.json")


def test_installed_status_with_corrupt_manifest(tmp_path):
    install = tmp_path / "installed"
    install.mkdir()
    (install / "manifest.json").write_text("{corrupt", encoding="utf-8")
    status = updater.installed_status(install)
    assert status["installed"] is True
    assert status["pack_version"] == "unknown"


def test_build_manifest_empty_pack_allowed(tmp_path):
    pack = tmp_path / "empty_pack"
    pack.mkdir()
    manifest = updater.build_manifest(pack, "2026.1")
    assert manifest["files"] == []
    assert (pack / "manifest.json").exists()


def test_community_signatures_missing_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(community, "bundled_community_dir", lambda: tmp_path / "nope")
    sigs, errors = community.community_signatures()
    assert sigs == [] and errors


def test_installed_community_signatures_paths(tmp_path, monkeypatch):
    # not installed -> ([], [])
    monkeypatch.setattr("qshield.signatures.updater.installed_status", lambda: {"installed": False})
    assert community.installed_community_signatures() == ([], [])
    # installed -> loads from the user dir
    pack = _make_pack(tmp_path)
    monkeypatch.setattr("qshield.signatures.updater.installed_status", lambda: {"installed": True})
    monkeypatch.setattr(community, "user_community_dir", lambda: pack)
    sigs, errors = community.installed_community_signatures()
    assert errors == [] and [s.id for s in sigs] == ["QSig-2026-0001"]


def test_load_pack_collects_errors(tmp_path):
    pack = tmp_path / "broken_pack"
    pack.mkdir()
    (pack / "bad.yaml").write_text("id: nope\n", encoding="utf-8")
    sigs, errors = community.load_pack(pack)
    assert sigs == [] and errors


def test_preferred_community_prefers_installed(tmp_path, monkeypatch):
    sentinel = object()
    monkeypatch.setattr(community, "installed_community_signatures", lambda: ([sentinel], []))
    monkeypatch.setattr(community, "community_signatures", lambda: ([], ["should not be called"]))
    sigs, _ = community.preferred_community_signatures()
    assert sigs == [sentinel]
    # falls back to bundled when installed is empty
    monkeypatch.setattr(community, "installed_community_signatures", lambda: ([], []))
    monkeypatch.setattr(community, "community_signatures", lambda: ([sentinel], []))
    sigs, _ = community.preferred_community_signatures()
    assert sigs == [sentinel]


def test_verify_pack_edge_cases(tmp_path):
    # missing manifest
    assert any("missing" in e for e in community.verify_pack(tmp_path))
    # unreadable manifest
    (tmp_path / "manifest.json").write_text("{oops", encoding="utf-8")
    assert any("unreadable" in e for e in community.verify_pack(tmp_path))
    # manifest lists a file that is missing on disk + extra file on disk
    (tmp_path / "manifest.json").write_text(json.dumps(
        {"pack_version": "x", "files": [{"name": "gone.yaml", "sha256": "0" * 64}]}), encoding="utf-8")
    errors = community.verify_pack(tmp_path)
    assert any("missing on disk" in e for e in errors)
    (tmp_path / "extra.yaml").write_text(GOOD_SIG, encoding="utf-8")
    errors = community.verify_pack(tmp_path)
    assert any("not in manifest" in e for e in errors)


def test_scanner_config_templates_include_use_community():
    from qshield.scanner import Scanner

    scanner = Scanner(config="strict")
    d = scanner.config.to_dict()
    assert d["signatures_community"] is False


# --------------------------------------------- CLI error/branch coverage
def test_cli_new_bad_severity(tmp_path):
    result = runner.invoke(app, ["sig", "new", "T1.1", "--severity", "spicy", "--out", str(tmp_path / "x.yaml")])
    assert result.exit_code == 2


def test_cli_new_refuses_overwrite_and_force(tmp_path):
    out = tmp_path / "keep.yaml"
    out.write_text("original", encoding="utf-8")
    result = runner.invoke(app, ["sig", "new", "T1.1", "--out", str(out)])
    assert result.exit_code == 2
    assert out.read_text(encoding="utf-8") == "original"
    result = runner.invoke(app, ["sig", "new", "T1.1", "--out", str(out), "--force"])
    assert result.exit_code == 0
    assert "QSig-" in out.read_text(encoding="utf-8")


def test_cli_test_json_output(tmp_path):
    sig = tmp_path / "sig.yaml"
    sig.write_text(GOOD_SIG, encoding="utf-8")
    mal, clean = _tiny_corpus(tmp_path)
    result = runner.invoke(app, ["sig", "test", str(sig),
                                 "--malicious-dir", str(mal), "--clean-dir", str(clean),
                                 "--json"])
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["signature"] == "QSig-2026-0001"
    assert payload["tpr"] == 1.0


def test_cli_test_skips_malformed_fixtures(tmp_path):
    sig = tmp_path / "sig.yaml"
    sig.write_text(GOOD_SIG, encoding="utf-8")
    mal, clean = _tiny_corpus(tmp_path)
    (mal / "broken.qasm").write_text("this is not qasm {{{", encoding="utf-8")
    result = runner.invoke(app, ["sig", "test", str(sig),
                                 "--malicious-dir", str(mal), "--clean-dir", str(clean)])
    assert result.exit_code == 0
    assert "skipped" in result.output


def test_cli_update_failure_exit(tmp_path):
    result = runner.invoke(app, ["sig", "update", "--url", str(tmp_path / "nope.json")])
    assert result.exit_code == 1


def test_cli_update_report_not_ok(tmp_path):
    pack = tmp_path / "src_pack"
    pack.mkdir()
    (pack / "QSig-2026-0002.yaml").write_text("id: nope\n", encoding="utf-8")
    updater.build_manifest(pack, "2026.9")
    result = runner.invoke(app, ["sig", "update", "--url", str(pack / "manifest.json"),
                                 "--install-dir", str(tmp_path / "installed")])
    assert result.exit_code == 1
    assert "rejected" in result.output or "untouched" in result.output


def test_cli_rollback_success(tmp_path):
    pack = _make_pack(tmp_path)
    install = tmp_path / "installed"
    runner.invoke(app, ["sig", "update", "--url", str(pack / "manifest.json"), "--install-dir", str(install)])
    runner.invoke(app, ["sig", "update", "--url", str(pack / "manifest.json"), "--install-dir", str(install)])
    result = runner.invoke(app, ["sig", "rollback", "--install-dir", str(install)])
    assert result.exit_code == 0


def test_cli_status_not_installed(tmp_path):
    result = runner.invoke(app, ["sig", "status", "--install-dir", str(tmp_path / "nope")])
    assert result.exit_code == 0
    assert "No community pack" in result.output


def test_cli_status_detects_drift(tmp_path):
    pack = _make_pack(tmp_path)
    install = tmp_path / "installed"
    runner.invoke(app, ["sig", "update", "--url", str(pack / "manifest.json"), "--install-dir", str(install)])
    target = install / "QSig-2026-0001.yaml"
    target.write_text(target.read_text(encoding="utf-8") + "\n# drift\n", encoding="utf-8")
    result = runner.invoke(app, ["sig", "status", "--install-dir", str(install)])
    assert result.exit_code == 1


def test_cli_manifest_build(tmp_path):
    pack = tmp_path / "pack"
    pack.mkdir()
    (pack / "QSig-2026-0003.yaml").write_text(GOOD_SIG.replace("QSig-2026-0001", "QSig-2026-0003"),
                                              encoding="utf-8")
    result = runner.invoke(app, ["sig", "manifest-build", str(pack), "--version", "2026.7"])
    assert result.exit_code == 0, result.output
    manifest = json.loads((pack / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["pack_version"] == "2026.7"
