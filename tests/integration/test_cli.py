"""CLI integration tests (typer CliRunner)."""

import json

from typer.testing import CliRunner

from qshield.cli.main import app

runner = CliRunner()

BELL = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n"
BACKDOOR = "OPENQASM 2.0;\nqreg q[3];\ncreg c[3];\ncx q[0], q[2];\nh q[0];\ncx q[0], q[1];\nmeasure q -> c;\n"


def test_version():
    r = runner.invoke(app, ["version"])
    assert r.exit_code == 0 and "qshield" in r.output


def test_scan_clean_text(tmp_path):
    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    r = runner.invoke(app, ["scan", str(f)])
    assert r.exit_code == 0, r.output


def test_scan_malicious_fails_on_high(tmp_path):
    f = tmp_path / "trojan.qasm"
    f.write_text(BACKDOOR)
    r = runner.invoke(app, ["scan", str(f), "--fail-on", "high"])
    assert r.exit_code == 1


def test_scan_json_out(tmp_path):
    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    out = tmp_path / "out.json"
    r = runner.invoke(app, ["scan", str(f), "--format", "json", "-o", str(out)])
    assert r.exit_code == 0
    payload = json.loads(out.read_text())
    assert payload["tool"]["name"] == "QSHIELD"


def test_scan_sarif_out(tmp_path):
    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    out = tmp_path / "out.sarif"
    r = runner.invoke(app, ["scan", str(f), "--format", "sarif", "-o", str(out)])
    assert r.exit_code == 0
    assert json.loads(out.read_text())["version"] == "2.1.0"


def test_scan_html_out(tmp_path):
    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    out = tmp_path / "out.html"
    r = runner.invoke(app, ["scan", str(f), "--format", "html", "-o", str(out)])
    assert r.exit_code == 0
    assert "<!DOCTYPE html>" in out.read_text()


def test_scan_unknown_format(tmp_path):
    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    r = runner.invoke(app, ["scan", str(f), "--format", "yaml"])
    assert r.exit_code == 2


def test_scan_unparseable_exits_2(tmp_path):
    f = tmp_path / "broken.qasm"
    f.write_text("OPENQASM 2.0;\nqreg q[2];\nthis is not valid\n")
    r = runner.invoke(app, ["scan", str(f)])
    assert r.exit_code == 2


def test_compare_equivalent(tmp_path):
    a = tmp_path / "a.qasm"
    b = tmp_path / "b.qasm"
    a.write_text(BELL)
    b.write_text(BELL)
    r = runner.invoke(app, ["compare", str(a), str(b)])
    assert r.exit_code == 0, r.output


def test_compare_different(tmp_path):
    a = tmp_path / "a.qasm"
    b = tmp_path / "b.qasm"
    a.write_text(BELL)
    b.write_text(BELL + "x q[0];\n")
    r = runner.invoke(app, ["compare", str(a), str(b)])
    assert r.exit_code == 1, r.output


def test_compare_randomized_flag(tmp_path):
    a = tmp_path / "a.qasm"
    b = tmp_path / "b.qasm"
    a.write_text(BELL)
    b.write_text(BELL)
    r = runner.invoke(app, ["compare", str(a), str(b), "--randomized", "--samples", "2"])
    assert r.exit_code == 0, r.output


def test_compare_formal(tmp_path):
    pytest_mod = __import__("pytest")
    pytest_mod.importorskip("pyzx")
    a = tmp_path / "a.qasm"
    b = tmp_path / "b.qasm"
    a.write_text(BELL)
    b.write_text(BELL)
    r = runner.invoke(app, ["compare", str(a), str(b), "--formal"])
    assert r.exit_code == 0, r.output


def test_verify_exact_and_perturb(tmp_path):
    import numpy as np

    from qshield.core.circuit_ir import MAX_EXACT_QUBITS
    from qshield.core.parsers.qasm_parser import parse_qasm

    ir = parse_qasm(BELL)
    u = ir.to_unitary(max_qubits=MAX_EXACT_QUBITS)
    u_path = tmp_path / "u.npy"
    np.save(u_path, u)
    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    r = runner.invoke(app, ["verify", str(f), "--expected-unitary", str(u_path)])
    assert r.exit_code == 0, r.output
    u_bad = u.copy()
    u_bad[0, 0] *= 1.0001
    np.save(u_path, u_bad)
    r = runner.invoke(app, ["verify", str(f), "--expected-unitary", str(u_path)])
    assert r.exit_code == 1


def test_audit_deps(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("qiskit==1.2.0\nqisikt==1.0\nurllib3==1.26.4\n")
    r = runner.invoke(app, ["audit-deps", "--requirements", str(req)])
    assert r.exit_code == 1  # findings: typosquat + CVE
    req.write_text("qiskit==1.2.0\n")
    r = runner.invoke(app, ["audit-deps", "--requirements", str(req)])
    assert r.exit_code == 0


def test_audit_package():
    r = runner.invoke(app, ["audit-package", "qiskit", "--version", "1.2.0"])
    assert r.exit_code == 0
    r = runner.invoke(app, ["audit-package", "pynnylane"])
    assert r.exit_code == 1


def test_init_config_and_db(tmp_path):
    out = tmp_path / ".qshield.yaml"
    r = runner.invoke(app, ["init-config", str(out)])
    assert r.exit_code == 0 and out.exists()
    r = runner.invoke(app, ["db", "list"])
    assert r.exit_code == 0 and "QSig" in r.output
    r = runner.invoke(app, ["db", "search", "ancilla"])
    assert r.exit_code == 0 and "QSig" in r.output
    r = runner.invoke(app, ["db", "search", "zzzznomatch"])
    assert r.exit_code == 0


def test_github_actions_annotations(tmp_path):
    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    r = runner.invoke(app, ["scan", str(f), "--github-actions"])
    assert r.exit_code in (0, 1)


def test_scan_dir_no_qasm(tmp_path):
    r = runner.invoke(app, ["scan", str(tmp_path), "--recursive"])
    assert r.exit_code == 0


def test_scan_py_file_rejected(tmp_path):
    f = tmp_path / "evil.py"
    f.write_text("import os\n")
    r = runner.invoke(app, ["scan", str(f)])
    assert r.exit_code == 2


def test_scan_framework_informational(tmp_path):
    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    r = runner.invoke(app, ["scan", str(f), "--framework", "cirq"])
    assert r.exit_code == 0


def test_scan_full_dynamic(tmp_path):
    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    r = runner.invoke(app, ["scan", str(f), "--full", "--format", "json"])
    assert r.exit_code in (0, 1)


def test_scan_github_actions_annotations(tmp_path):
    trojan = tmp_path / "trojan.qasm"
    trojan.write_text(
        "OPENQASM 2.0;\nqreg q[3];\ncreg c[3];\n"
        "cx q[0], q[2];\nh q[0];\ncx q[0], q[1];\nmeasure q -> c;\n"
    )
    r = runner.invoke(app, ["scan", str(trojan), "--github-actions"])
    assert r.exit_code in (0, 1)


def test_scan_pdf_requires_output(tmp_path):
    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    r = runner.invoke(app, ["scan", str(f), "--format", "pdf"])
    assert r.exit_code == 2


def test_scan_pdf_with_weasyprint(tmp_path):
    pytest = __import__("pytest")
    pytest.importorskip("weasyprint")
    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    out = tmp_path / "report.pdf"
    r = runner.invoke(app, ["scan", str(f), "--format", "pdf", "-o", str(out)])
    assert r.exit_code in (0, 1)
    assert out.exists() and out.stat().st_size > 100


def test_compare_parse_error(tmp_path):
    bad = tmp_path / "bad.qasm"
    bad.write_text("OPENQASM 2.0;\ngarbage {{{\n")
    r = runner.invoke(app, ["compare", str(bad), str(bad)])
    assert r.exit_code == 2


def test_compare_gate_multiset_diff(tmp_path):
    a = tmp_path / "a.qasm"
    b = tmp_path / "b.qasm"
    a.write_text("OPENQASM 2.0;\nqreg q[1];\nh q[0];\n")
    b.write_text("OPENQASM 2.0;\nqreg q[1];\nx q[0];\n")
    r = runner.invoke(app, ["compare", str(a), str(b)])
    assert r.exit_code == 1
    assert "Only in" in r.output


def test_compare_formal_different(tmp_path):
    pytest = __import__("pytest")
    pytest.importorskip("pyzx")
    a = tmp_path / "a.qasm"
    b = tmp_path / "b.qasm"
    a.write_text("OPENQASM 2.0;\nqreg q[1];\nh q[0];\n")
    b.write_text("OPENQASM 2.0;\nqreg q[1];\nx q[0];\n")
    r = runner.invoke(app, ["compare", str(a), str(b), "--formal"])
    assert r.exit_code == 1


def test_compare_large_falls_back_to_randomized(tmp_path):
    # 13+ qubits -> dense unitary out of reach -> randomized check path
    n = 13
    ops = "".join(f"h q[{i}];\n" for i in range(n))
    a = tmp_path / "a.qasm"
    b = tmp_path / "b.qasm"
    a.write_text(f"OPENQASM 2.0;\nqreg q[{n}];\n{ops}")
    b.write_text(f"OPENQASM 2.0;\nqreg q[{n}];\n{ops}")
    r = runner.invoke(app, ["compare", str(a), str(b), "--samples", "2"])
    assert r.exit_code == 0


def test_compare_randomized_different(tmp_path):
    a = tmp_path / "a.qasm"
    b = tmp_path / "b.qasm"
    a.write_text("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n")
    b.write_text("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[1], q[0];\n")
    r = runner.invoke(app, ["compare", str(a), str(b), "--randomized", "--samples", "4"])
    assert r.exit_code in (0, 1)


def test_verify_shape_mismatch(tmp_path):
    import numpy as np

    f = tmp_path / "bell.qasm"
    f.write_text(BELL)
    u_path = tmp_path / "u.npy"
    np.save(u_path, np.eye(2, dtype=complex))  # wrong shape for 2-qubit circuit
    r = runner.invoke(app, ["verify", str(f), "--expected-unitary", str(u_path)])
    assert r.exit_code in (1, 2)


def test_init_config_default_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    r = runner.invoke(app, ["init-config"])
    assert r.exit_code == 0
    assert (tmp_path / ".qshield.yaml").exists()


def test_db_list_and_search_unknown(tmp_path):
    r = runner.invoke(app, ["db", "list"])
    assert r.exit_code == 0
    r = runner.invoke(app, ["db", "search", "zzz"])
    assert r.exit_code == 0
