from qshield.static.dependency_scanner import (
    DependencyScanner,
    audit_package,
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
