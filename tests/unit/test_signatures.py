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


def test_load_signature_missing_file(tmp_path):
    from qshield.signatures.loader import SignatureError, load_signature

    with pytest.raises(SignatureError, match="not found"):
        load_signature(tmp_path / "nope.yaml")


def test_load_signature_non_mapping(tmp_path):
    from qshield.signatures.loader import SignatureError, load_signature

    p = tmp_path / "bad.yaml"
    p.write_text("- just\n- a\n- list\n")
    with pytest.raises(SignatureError, match="mapping"):
        load_signature(p)


def test_validate_signature_missing_keys():
    from qshield.signatures.loader import SignatureError, validate_signature

    with pytest.raises(SignatureError, match="missing required keys"):
        validate_signature({"id": "QSig-2026-0001"})


def test_validate_signature_bad_id_and_severity_and_threat():
    from qshield.signatures.loader import SignatureError, validate_signature

    base = {
        "id": "QSig-2026-0001", "name": "n", "version": "1.0", "severity": "high",
        "threat_type": "T1.3", "description": "d",
        "detection": {"method": "structural", "structural_pattern": {"type": "leaf_ancilla"}},
    }
    with pytest.raises(SignatureError, match=r"QSig-YYYY-NNNN"):
        validate_signature({**base, "id": "sig-1"})
    with pytest.raises(SignatureError, match="severity"):
        validate_signature({**base, "severity": "catastrophic"})
    with pytest.raises(SignatureError, match="threat_type"):
        validate_signature({**base, "threat_type": "X9.9"})
    with pytest.raises(SignatureError, match=r"detection\.method"):
        validate_signature({**base, "detection": {"method": "magic"}})
    with pytest.raises(SignatureError, match="must be a mapping"):
        validate_signature({**base, "detection": "nope"})


def test_validate_signature_fp_clamping_and_bad_fp():
    from qshield.signatures.loader import validate_signature

    base = {
        "id": "QSig-2026-0001", "name": "n", "version": "1.0", "severity": "low",
        "threat_type": "T2.1", "description": "d",
        "detection": {"method": "unitary", "structural_pattern": {}},
    }
    s = validate_signature({**base, "false_positive_probability": "bogus"})
    assert s.false_positive_probability == 0.5
    s = validate_signature({**base, "false_positive_probability": 4.0})
    assert s.false_positive_probability == 1.0
    s = validate_signature({**base, "false_positive_probability": -1.0})
    assert s.false_positive_probability == 0.0


def test_load_directory_not_a_directory(tmp_path):
    from qshield.signatures.loader import SignatureError, load_directory

    f = tmp_path / "file.yaml"
    f.write_text("id: QSig-2026-0001\n")
    with pytest.raises(SignatureError, match="not a directory"):
        load_directory(f)


def test_signature_to_dict_roundtrip():
    from qshield.signatures.loader import builtin_signatures

    for s in builtin_signatures():
        d = s.to_dict()
        assert d["id"] == s.id
        assert d["detection"] == s.detection
        assert d["threat_type"] == s.threat_type
        assert s.method == s.detection["method"]
