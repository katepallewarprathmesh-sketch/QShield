import json

from typer.testing import CliRunner

from qshield import Scanner, scan
from qshield.cli.main import app

runner = CliRunner()


def test_qshield_scan_clean_bell(clean_dir):
    results = scan(str(clean_dir / "bell_state.qasm"))
    assert results.summary.circuits_scanned == 1
    assert results.is_clean


def test_scan_malicious_parameter_encoded(malicious_dir):
    scanner = Scanner(config="strict")
    scanner.add_circuit(str(malicious_dir / "parameter_encoded.qasm"))
    results = scanner.run()
    assert any(f.threat_type == "T2.2" for f in results.findings)


def test_scan_malicious_measurement_manipulation(malicious_dir):
    results = scan(str(malicious_dir / "measurement_manipulation.qasm"))
    assert any(f.threat_type == "T2.3" for f in results.findings)


def test_scan_ancilla_leakage_exact_detection(malicious_dir):
    scanner = Scanner(config="strict")
    scanner.add_circuit(str(malicious_dir / "ancilla_leakage.qasm"))
    results = scanner.run()
    leak_findings = [f for f in results.findings if f.threat_type == "T2.1" and f.severity == "high"]
    assert leak_findings, "expected the exact partial-trace ancilla-leakage finding"


def test_scan_distributed_backdoor(malicious_dir):
    results = scan(str(malicious_dir / "distributed_backdoor.qasm"))
    assert any("micro-rotation" in f.title.lower() for f in results.findings)


def test_unitary_verification_detects_tiny_perturbation(tmp_path, malicious_dir, clean_dir):
    from qshield.core.parsers import parse_file
    expected = parse_file(clean_dir / "bell_state.qasm").to_unitary()
    perturbed = tmp_path / "perturbed.qasm"
    perturbed.write_text("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\nrz(0.001) q[0];\n")
    scanner = Scanner()
    scanner.add_circuit(str(perturbed), expected_unitary=expected)
    results = scanner.run()
    assert any(f.threat_type == "T1.2" and f.severity == "critical" for f in results.findings)


def test_cli_scan_json_output(tmp_path, clean_dir):
    result = runner.invoke(app, ["scan", str(clean_dir / "bell_state.qasm"), "--format", "json"])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["summary"]["circuits_scanned"] == 1


def test_cli_fail_on_exit_code(malicious_dir):
    result = runner.invoke(app, ["scan", str(malicious_dir / "parameter_encoded.qasm"), "--fail-on", "high"])
    assert result.exit_code == 1
    result = runner.invoke(app, ["scan", str(malicious_dir / "parameter_encoded.qasm"), "--fail-on", "never"])
    assert result.exit_code == 0


def test_cli_db_search():
    result = runner.invoke(app, ["db", "search", "ancilla"])
    assert result.exit_code == 0
    assert "QSig-2024-0002" in result.stdout


def test_cli_init_config(tmp_path):
    target = tmp_path / ".qshield.yaml"
    result = runner.invoke(app, ["init-config", str(target)])
    assert result.exit_code == 0
    assert "thresholds" in target.read_text()


def test_cli_compare_same_circuit(clean_dir):
    bell = str(clean_dir / "bell_state.qasm")
    result = runner.invoke(app, ["compare", bell, bell])
    assert result.exit_code == 0


def test_cli_compare_different_circuits(clean_dir, malicious_dir):
    result = runner.invoke(
        app, ["compare", str(clean_dir / "bell_state.qasm"), str(malicious_dir / "identity_pair_hidden.qasm")]
    )
    assert result.exit_code == 1


def test_cli_audit_deps(tmp_path):
    reqs = tmp_path / "requirements.txt"
    reqs.write_text("urllib3==1.26.4\nqiskit==1.2.0\n")
    result = runner.invoke(app, ["audit-deps", "--requirements", str(reqs)])
    assert result.exit_code == 1  # urllib3 1.26.4 is flagged; high severity
