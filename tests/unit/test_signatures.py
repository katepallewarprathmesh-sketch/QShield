import pytest

from qshield.core.parsers import parse_qasm
from qshield.signatures import SignatureMatcher, builtin_signatures
from qshield.signatures.loader import SignatureError, validate_signature


def test_builtin_signatures_load():
    sigs = builtin_signatures()
    assert len(sigs) >= 5
    ids = {s.id for s in sigs}
    assert "QSig-2024-0001" in ids


def test_validate_rejects_bad_id():
    with pytest.raises(SignatureError):
        validate_signature({
            "id": "NOPE", "name": "x", "version": "1", "severity": "low",
            "threat_type": "T1.1", "description": "d",
            "detection": {"method": "structural"},
        })


def test_validate_rejects_bad_severity():
    with pytest.raises(SignatureError):
        validate_signature({
            "id": "QSig-2024-0001", "name": "x", "version": "1", "severity": "apocalyptic",
            "threat_type": "T1.1", "description": "d",
            "detection": {"method": "structural"},
        })


def test_matcher_detects_cancelling_pair():
    circuit = parse_qasm("""OPENQASM 2.0;
qreg q[2];
cx q[0], q[1];
cx q[0], q[1];
""")
    findings = SignatureMatcher().match(circuit)
    assert any(f.signature_id == "QSig-2024-0001" for f in findings)


def test_matcher_detects_basis_manipulation():
    circuit = parse_qasm("""OPENQASM 2.0;
qreg q[1];
creg c[1];
h q[0];
measure q -> c;
""")
    findings = SignatureMatcher().match(circuit)
    assert any(f.signature_id == "QSig-2024-0004" for f in findings)


def test_matcher_clean_circuit_quiet():
    circuit = parse_qasm("""OPENQASM 2.0;
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
measure q -> c;
""")
    findings = SignatureMatcher().match(circuit)
    # bell is clean; nothing medium-or-above should fire
    assert not [f for f in findings if f.severity_rank >= 2]
