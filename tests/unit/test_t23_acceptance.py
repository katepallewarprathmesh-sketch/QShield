"""Acceptance criteria for the T2.3 redesign, measured over the real fixtures.

These are the tests the specification asks for in §14:

* no clean fixture produces a T2.3 finding against its own genuine reference;
* every malicious T2.3 fixture is detected against a genuine approved reference;
* unrelated detectors are unchanged;
* a missing baseline is explicit rather than silent.

The reference for each fixture is reconstructed, never hand-authored to contain
the malicious circuit. ``reference_provenance`` records how.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "benchmarks"))
from t23_baseline_eval import load_fixtures, reference_for

from qshield.core.parsers import parse_qasm
from qshield.integrity.baseline import BaselineRegistry, create_baseline, sign_baseline
from qshield.integrity.evaluate import Outcome, evaluate_t23

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(scope="module")
def material():
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
    provenance: dict[str, str] = {}
    for fixture in load_fixtures():
        if fixture.split != "clean" and fixture.expected != "T2.3":
            continue
        reference, how = reference_for(fixture)
        assert reference is not None, f"no reference reconstructable for {fixture.name}"
        provenance[fixture.name] = how
        record = sign_baseline(
            create_baseline(
                reference,
                workload_id=f"fixture:{fixture.name}",
                approved_by="tests/unit/test_t23_acceptance.py",
            ),
            private,
        )
        registry.register(record, public_key_pem=public)
    return registry, public, provenance


def _evaluate(fixture, registry, public):
    circuit = parse_qasm(fixture.path.read_text())
    return evaluate_t23(
        circuit, registry=registry, workload_id=f"fixture:{fixture.name}", public_key_pem=public
    )


def test_all_clean_fixtures_are_clean_against_genuine_references(material) -> None:
    registry, public, _ = material
    flagged = []
    for fixture in load_fixtures():
        if fixture.split != "clean":
            continue
        result = _evaluate(fixture, registry, public)
        if result.outcome is Outcome.FINDING:
            flagged.append((fixture.name, result.detail))
    assert flagged == [], f"clean fixtures produced T2.3 findings: {flagged}"


def test_all_t23_fixtures_are_detected_against_genuine_references(material) -> None:
    registry, public, _ = material
    fixtures = [f for f in load_fixtures() if f.expected == "T2.3"]
    assert len(fixtures) == 20

    missed = []
    for fixture in fixtures:
        result = _evaluate(fixture, registry, public)
        if result.outcome is not Outcome.FINDING:
            missed.append((fixture.name, result.outcome.value, result.detail))

    # The hypothesis in the specification is 20/20. Report the measured value.
    assert missed == [], f"T2.3 fixtures not detected: {missed}"


def test_duplicate_fixtures_are_counted_honestly(material) -> None:
    """Some corpus files are byte-identical; the distinct count is the real one."""
    fixtures = [f for f in load_fixtures() if f.expected == "T2.3"]
    digests = {f.path.read_bytes() for f in fixtures}
    assert len(fixtures) == 20
    assert len(digests) < len(fixtures), "expected duplicate fixtures in the corpus"
    distinct = len(digests)
    # Detection is per distinct artifact; both numbers are published.
    assert distinct == 11


def test_missing_baseline_is_explicit_for_every_t23_fixture(material) -> None:
    """Without a baseline the state must be INDETERMINATE, never PASS or FINDING."""
    outcomes = set()
    for fixture in load_fixtures():
        circuit = parse_qasm(fixture.path.read_text())
        result = evaluate_t23(circuit, registry=None)
        outcomes.add(result.outcome)
        assert result.blocked is True
    assert outcomes == {Outcome.INDETERMINATE}


def test_reference_provenance_is_recorded(material) -> None:
    _, _, provenance = material
    assert set(provenance.values()) <= {"documented", "derived", "self"}
    assert sum(1 for v in provenance.values() if v == "documented") == 16
    assert sum(1 for v in provenance.values() if v == "derived") == 4


def test_t11_and_t22_families_are_unaffected_by_the_redesign() -> None:
    """The redesign touches T2.3 only; other families must not move."""
    results = json.loads(
        (Path(__file__).resolve().parents[2] / "benchmarks" / "results" / "benchmark-v1.json").read_text()
    )
    by_family = results["metrics"]["by_family"]
    assert by_family["T1.1"]["recall"] == 1.0
    assert by_family["T2.2"]["recall"] == 1.0


def test_t13_recall_was_previously_t23_assisted() -> None:
    """Documented regression: T1.3 crossings depended on T2.3 co-firing.

    Measured against the *pre-redesign* results, archived at
    ``benchmarks/results/benchmark-v1-pre-t23-redesign.json``. The live results
    file can no longer show this, because T2.3 no longer emits there — which is
    precisely why the historical record is kept.

    If T1.3 is later given independent detection, this test should be updated
    deliberately rather than deleted.
    """
    results = json.loads(
        (
            Path(__file__).resolve().parents[2]
            / "benchmarks" / "results" / "benchmark-v1-pre-t23-redesign.json"
        ).read_text()
    )
    t13 = [
        c for c in results["per_circuit"]
        if c["split"] == "malicious" and c["expected_threat"] == "T1.3"
    ]
    independent = [c for c in t13 if "T2.3" not in c["threat_types"]]
    assert len(t13) == 52
    assert len(independent) == 1, (
        "T1.3 had one independent detection; if this changes, the reported "
        "T1.3 recall must be re-derived rather than copied"
    )


def test_fixture_labels_are_unchanged() -> None:
    """No fixture may be relabelled to improve the numbers."""
    index = json.loads(
        (Path(__file__).resolve().parents[2] / "benchmarks" / "corpus_index.json").read_text()
    )
    generated = index["generated_malicious"]
    assert [k for k, v in generated.items() if v == "T2.3"] == sorted(
        k for k, v in generated.items() if v == "T2.3"
    )
    assert len([k for k, v in generated.items() if v == "T2.3"]) == 16
