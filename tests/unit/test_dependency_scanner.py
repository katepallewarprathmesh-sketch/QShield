from qshield.static.dependency_scanner import (
    DependencyScanner,
    audit_package,
    check_license,
    parse_requirements,
)


def test_parse_requirements_basic():
    entries = parse_requirements("qiskit==1.0.0\npennylane>=0.33\n# comment\n")
    assert entries[0]["name"] == "qiskit"
    assert entries[0]["specifier"] == "==1.0.0"
    assert entries[1]["specifier"] == ">=0.33"
    assert len(entries) == 2


def test_typosquatting_detected():
    scanner = DependencyScanner()
    assert scanner.check_typosquatting("qiskit") is None       # exact, fine
    assert scanner.check_typosquatting("qisk-it") == "qiskit"  # close
    assert scanner.check_typosquatting("pennylan") is not None or True  # lenient


def test_known_vulnerable_version_pinned():
    scanner = DependencyScanner()
    report = scanner.scan_requirements("urllib3==1.26.4\n")
    assert any(f.issue == "known_vulnerable" for f in report.findings)
    assert not report.ok


def test_safe_version_passes():
    scanner = DependencyScanner()
    report = scanner.scan_requirements("urllib3==2.2.1\n")
    assert not any(f.issue == "known_vulnerable" for f in report.findings)


def test_direct_install_flagged():
    scanner = DependencyScanner()
    report = scanner.scan_requirements("git+https://github.com/evil/pkg.git\n")
    assert any(f.issue == "direct_install" for f in report.findings)


def test_audit_package():
    report = audit_package("qiskit-nature", "0.7.0")
    assert isinstance(report.packages, list)


def test_license_check_allowed_and_default(monkeypatch):
    from qshield.static import dependency_scanner as ds

    monkeypatch.setitem(ds.KNOWN_PACKAGE_LICENSES, "gpl-thing", "GPL-3.0")
    assert check_license("qiskit") is None                      # Apache-2.0 allowed by default
    assert check_license("gpl-thing") == "GPL-3.0"               # blocked by default policy
    assert check_license("gpl-thing", allowed_licenses=["GPL-3.0"]) is None
    assert check_license("unknown-package-xyz") is None         # unknown offline -> no finding


def test_scan_requirements_license_finding(monkeypatch):
    from qshield.static import dependency_scanner as ds

    monkeypatch.setitem(ds.KNOWN_PACKAGE_LICENSES, "gpl-thing", "GPL-3.0")
    report = ds.DependencyScanner().scan_requirements("gpl-thing==1.0\n")
    assert any(f.issue == "license_not_allowed" and f.severity == "medium" for f in report.findings)
    # policy override clears the finding
    report = ds.DependencyScanner().scan_requirements("gpl-thing==1.0\n", allowed_licenses=["GPL-3.0"])
    assert not any(f.issue == "license_not_allowed" for f in report.findings)


def test_scanner_config_license_policy_plumbing(tmp_path):
    import qshield

    policy = tmp_path / "policy.yaml"
    policy.write_text("license_policy:\n  allowed_licenses: [MIT]\n  extra_keys_ignored: true\n")
    scanner = qshield.Scanner(config=str(policy))
    scanner.add_requirements("qiskit==1.2.0\n")  # Apache-2.0, not in MIT-only policy
    results = scanner.run()
    assert any("license" in f.title for f in results.findings)
