import pytest


def test_scan_results_filter_and_dunder(tmp_path):
    from qshield.scanner import Scanner

    scanner = Scanner()
    scanner.add_circuit("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n", name="bell")
    results = scanner.run_quick()
    assert len(results) == len(results.findings)
    assert bool(results) == results.is_clean
    assert "<ScanResults" in repr(results)
    filtered = results.filter(severity="high")
    assert all(f.severity == "high" for f in filtered.findings)
    filtered = results.filter(threat_type="T1.3")
    assert all(f.threat_type == "T1.3" for f in filtered.findings)
    filtered = results.filter(analysis_type="structural")
    assert all(f.analysis_type == "structural" for f in filtered.findings)


def test_to_pdf_without_weasyprint(monkeypatch, tmp_path):
    import builtins

    from qshield.scanner import Scanner

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "weasyprint":
            raise ImportError("blocked")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    scanner = Scanner()
    scanner.add_circuit("OPENQASM 2.0;\nqreg q[1];\nh q[0];\n", name="bell")
    results = scanner.run_quick()
    with pytest.raises(RuntimeError, match="weasyprint"):
        results.to_pdf(str(tmp_path / "out.pdf"))


def test_scanner_add_package_requirements_and_signatures(tmp_path):
    import qshield

    sig = tmp_path / "s.yaml"
    sig.write_text("""id: "QSig-2026-9991"
name: "Test sig"
version: "1.0"
author: "test"
date: "2026-11-12"
severity: "low"
threat_type: "T1.3"
description: "test"
detection:
  method: "structural"
  structural_pattern:
    type: "leaf_ancilla"
    max_ancilla_uses: 1
""")
    scanner = qshield.Scanner()
    scanner.add_package("qiskit", version="1.2.0")
    scanner.add_requirements("qiskit==1.2.0\nurllib3==1.26.4\n")
    scanner.add_signatures(str(sig))
    results = scanner.run()
    assert any(f.threat_type == "T3.1" for f in results.findings)
    assert any("urllib3" in f.title for f in results.findings)


def test_scanner_expected_unitary(tmp_path):

    from qshield.scanner import Scanner

    scanner = Scanner()
    bell = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n"
    from qshield.core.parsers import parse_qasm

    u = parse_qasm(bell).to_unitary()
    scanner.add_circuit(bell, name="bell", expected_unitary=u)
    results = scanner.run()
    assert results is not None


def test_scanner_default_scan_one_shot(tmp_path):
    import qshield

    out = qshield.scan("OPENQASM 2.0;\nqreg q[1];\nh q[0];\n", name="bell")
    assert out is not None
