"""Security benchmark: clean corpus must stay quiet; attacks must be caught."""


import json
from pathlib import Path

from qshield import Scanner, scan

ROOT = Path(__file__).resolve().parents[2]
_GEN = json.loads((ROOT / "benchmarks" / "corpus_index.json").read_text())
GENERATED_MALICIOUS = _GEN.get("generated_malicious", {})


def test_all_clean_circuits_quiet(clean_circuits):
    for stem, path in clean_circuits.items():
        results = scan(str(path))
        high = [f for f in results.findings if f.severity_rank >= 3]
        assert not high, f"{stem}: false positive(s): {[f.title for f in high]}"


def test_all_malicious_circuits_detected(malicious_circuits):
    expectations = {
        "ancilla_leakage": "T2.1",
        "identity_pair_hidden": "T1.3",
        "measurement_manipulation": "T2.3",
        "distributed_backdoor": "T1.1",
        "parameter_encoded": "T2.2",
        "z_cancellation_hidden": "T1.3",
        "s_sdg_separated": "T1.3",
        "tdg_before_measure": "T2.3",
        "micro_rotation_hidden": "T1.1",
        "stego_ascii_qshield": "T2.2",
        "leaf_ancilla_measure": "T2.1",
        "fanout_shadow_channel": "T2.1",
        # second expansion round
        "h_cancellation_adjacent": "T1.3",
        "cx_cx_separated": "T1.3",
        "micro_rotation_dense": "T1.1",
        "stego_ascii_backdoor": "T2.2",
        "y_before_measure": "T2.3",
        "x_before_measure": "T2.3",
        "y_y_pair_separated": "T1.3",
        "leaf_ancilla_swap": "T2.1",
    }
    expectations = {**expectations, **GENERATED_MALICIOUS}
    # corpus hygiene: every malicious fixture must have an expectation
    assert set(expectations) == set(malicious_circuits), (
        f"fixture/expectation drift: missing {set(malicious_circuits) - set(expectations)}, "
        f"extra {set(expectations) - set(malicious_circuits)}"
    )
    # T2.3 is a differential against an approved reference, so the scan supplies
    # one. A missing baseline would make the check INDETERMINATE, and that is
    # tested separately in tests/unit/test_t23_baseline.py.
    registry, public_key = _t23_baseline_registry(malicious_circuits, expectations)

    for stem, path in malicious_circuits.items():
        scanner = Scanner(config="strict")
        scanner.add_circuit(str(path))
        if expectations[stem] == "T2.3":
            scanner.set_baselines(
                registry, public_key_pem=public_key, workload_id=Path(path).stem
            )
        results = scanner.run()
        expected_threat = expectations[stem]
        assert any(f.threat_type == expected_threat for f in results.findings), (
            f"{stem}: expected a {expected_threat} finding, got "
            f"{[f.threat_type for f in results.findings]}"
        )


def _t23_baseline_registry(malicious_circuits, expectations):
    """Signed approved references for each T2.3 fixture.

    The reference is the fixture with its readout-stage gates removed: the
    pre-tamper circuit. It is reconstructed, never authored to include the
    malicious gate.
    """
    import sys

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
    from t23_reference import approved_reference_for

    from qshield.integrity.baseline import BaselineRegistry, create_baseline, sign_baseline

    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    registry = BaselineRegistry()
    for stem, path in malicious_circuits.items():
        if expectations.get(stem) != "T2.3":
            continue
        reference = approved_reference_for(Path(path))
        registry.register(
            sign_baseline(
                create_baseline(reference, workload_id=stem, approved_by="security-test"),
                private,
            ),
            public_key_pem=public,
        )
    return registry, public
