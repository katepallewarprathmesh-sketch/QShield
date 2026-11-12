import math

from qshield.core.config import load_config
from qshield.core.parsers import parse_qasm
from qshield.static.structural_analyzer import StructuralAnalyzer


def analyze(source: str):
    circuit = parse_qasm(source)
    return StructuralAnalyzer(load_config("default")).analyze(circuit)


def test_clean_bell_has_no_high_findings():
    findings = analyze("""OPENQASM 2.0;
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
measure q -> c;
""")
    assert not [f for f in findings if f.severity in ("critical", "high", "medium")]


def test_cancelling_cx_pair_detected():
    findings = analyze("""OPENQASM 2.0;
qreg q[2];
cx q[0], q[1];
cx q[0], q[1];
""")
    titles = [f.title for f in findings]
    assert any("cancellation" in t.lower() for t in titles)


def test_cancelling_rotation_pair_detected():
    findings = analyze("""OPENQASM 2.0;
qreg q[1];
rz(0.5) q[0];
rz(-0.5) q[0];
""")
    assert any("cancellation" in f.title.lower() for f in findings)


def test_cancellation_not_flagged_across_overlap():
    # gates between the pair touch q[0], so no naive pair should be flagged
    findings = analyze("""OPENQASM 2.0;
qreg q[2];
rz(0.5) q[0];
x q[0];
rz(-0.5) q[0];
""")
    assert not any("cancellation" in f.title.lower() for f in findings)


def test_unused_measured_qubit_flagged():
    analyze("""OPENQASM 2.0;
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
measure q -> c;
""")
    # q[1] is low-activity but entangled; default profile filters low-confidence,
    # so just check the analyzer can see it via strict config
    from qshield.core.config import load_config
    from qshield.static.structural_analyzer import StructuralAnalyzer
    circuit = parse_qasm("""OPENQASM 2.0;
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
measure q -> c;
""")
    strict = StructuralAnalyzer(load_config("strict")).analyze(circuit)
    assert any(f.threat_type == "T2.1" for f in strict)


def test_micro_rotation_spread_detected():
    body = "\n".join(["rz(0.001) q[0];"] * 8)
    findings = analyze(f"""OPENQASM 2.0;
qreg q[1];
{body}
""")
    assert any("micro-rotation" in f.title.lower() for f in findings)


def test_parameter_ascii_encoding_detected():
    lines = ["OPENQASM 2.0;", "qreg q[4];"]
    for i, b in enumerate(b"BACKDOOR"):
        lines.append(f"rz({math.pi * b / 4096.0!r}) q[{i % 4}];")
    findings = analyze("\n".join(lines))
    enc = [f for f in findings if f.threat_type == "T2.2"]
    assert enc, "expected a parameter-encoding finding"
    assert enc[0].severity == "high"


def test_basis_change_before_measurement():
    findings = analyze("""OPENQASM 2.0;
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
h q[0];
h q[1];
measure q -> c;
""")
    assert any(f.threat_type == "T2.3" for f in findings)


def test_empty_circuit_no_high_findings():
    findings = analyze("OPENQASM 2.0;\nqreg q[2];\n")
    assert not [f for f in findings if f.severity_rank >= 2]
