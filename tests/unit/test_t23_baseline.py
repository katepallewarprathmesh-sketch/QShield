"""T2.3 readout-differential: comparison, baseline trust, and evaluation states."""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qshield.core.parsers import parse_qasm
from qshield.integrity.baseline import (
    BaselineError,
    BaselineRegistry,
    BaselineState,
    create_baseline,
    load_baseline_file,
    sign_baseline,
    verify_signature,
)
from qshield.integrity.evaluate import Outcome, evaluate_t23
from qshield.integrity.readout import (
    ComparisonVerdict,
    compare_readout,
    extract_readout,
)

BASE = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
measure q -> c;
"""

# The malicious counterpart: one injected basis rotation on q[1].
TAMPERED = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[2];
creg c[2];
h q[0];
cx q[0],q[1];
h q[1];
measure q -> c;
"""


def _ir(source: str):
    return parse_qasm(source)


@pytest.fixture
def keys():
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private, public


def _registry(keys, reference_source: str = BASE, workload: str = "w1") -> BaselineRegistry:
    private, public = keys
    registry = BaselineRegistry()
    record = sign_baseline(
        create_baseline(_ir(reference_source), workload_id=workload, approved_by="sec@corp"),
        private,
    )
    registry.register(record, public_key_pem=public)
    return registry


# ---------------------------------------------------------------- readout
def test_extract_readout_records_final_gate_and_basis_flag() -> None:
    profile = extract_readout(_ir(TAMPERED))
    point = profile.point_for(1)
    assert point is not None
    assert point.final_gate == "h"
    assert point.is_basis_rotation is True
    assert extract_readout(_ir(BASE)).point_for(1).final_gate == "cx"


def test_identical_circuits_compare_identical() -> None:
    diff = compare_readout(_ir(BASE), _ir(BASE))
    assert diff.verdict is ComparisonVerdict.IDENTICAL
    assert diff.differences == []


def test_injected_basis_gate_is_a_readout_difference() -> None:
    diff = compare_readout(_ir(TAMPERED), _ir(BASE))
    assert diff.verdict is ComparisonVerdict.READOUT_DIFFERS
    kinds = {d.kind for d in diff.differences}
    assert "final_operation_changed" in kinds
    detail = diff.differences[0].detail
    assert "q[1]" in detail and "cx" in detail and "h" in detail


def test_legitimate_deutsch_circuit_matches_its_reference() -> None:
    """A correct Hadamard-basis readout must not be a difference against itself."""
    deutsch = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[1];
creg c[1];
x q[0];
h q[0];
z q[0];
h q[0];
measure q[0] -> c[0];
"""
    assert compare_readout(_ir(deutsch), _ir(deutsch)).verdict is ComparisonVerdict.IDENTICAL


def test_legitimate_bernstein_vazirani_matches_its_reference() -> None:
    bv = """OPENQASM 2.0;
include "qelib1.inc";
qreg q[4];
creg c[4];
x q[3];
h q[3];
h q[0];
h q[1];
h q[2];
cx q[0],q[3];
cx q[2],q[3];
h q[0];
h q[1];
h q[2];
measure q[0] -> c[0];
measure q[1] -> c[1];
measure q[2] -> c[2];
"""
    assert compare_readout(_ir(bv), _ir(bv)).verdict is ComparisonVerdict.IDENTICAL


def test_classical_bit_remap_is_detected() -> None:
    remapped = BASE.replace("measure q -> c;", "measure q[0] -> c[1];\nmeasure q[1] -> c[0];")
    diff = compare_readout(_ir(remapped), _ir(BASE))
    assert diff.verdict is ComparisonVerdict.READOUT_DIFFERS
    assert "classical_bit_remapped" in {d.kind for d in diff.differences}


def test_dropped_measurement_is_detected() -> None:
    fewer = BASE.replace("measure q -> c;", "measure q[0] -> c[0];")
    diff = compare_readout(_ir(fewer), _ir(BASE))
    assert diff.verdict is ComparisonVerdict.READOUT_DIFFERS
    assert "qubit_no_longer_measured" in {d.kind for d in diff.differences}


def test_width_change_is_reported() -> None:
    wider = BASE.replace("qreg q[2];", "qreg q[3];").replace("creg c[2];", "creg c[3];")
    diff = compare_readout(_ir(wider), _ir(BASE))
    assert diff.verdict is ComparisonVerdict.READOUT_DIFFERS
    assert diff.differences[0].kind == "width_changed"


def test_change_outside_readout_is_not_a_readout_difference() -> None:
    """An extra gate that does not become the last operation on a measured qubit."""
    modified = BASE.replace("h q[0];", "h q[0];\nz q[0];")
    diff = compare_readout(_ir(modified), _ir(BASE))
    assert diff.verdict in (ComparisonVerdict.STRUCTURE_DIFFERS, ComparisonVerdict.UNRESOLVED)
    assert diff.is_readout_change is False


def test_readout_digest_is_stable_and_sensitive() -> None:
    a = extract_readout(_ir(BASE)).digest()
    b = extract_readout(_ir(BASE)).digest()
    c = extract_readout(_ir(TAMPERED)).digest()
    assert a == b
    assert a != c


# ---------------------------------------------------------------- baseline trust
def test_signed_baseline_verifies(keys) -> None:
    private, public = keys
    record = sign_baseline(create_baseline(_ir(BASE), workload_id="w1", approved_by="a"), private)
    assert verify_signature(record, public) is True


def test_baseline_substitution_is_rejected(keys) -> None:
    private, public = keys
    record = sign_baseline(create_baseline(_ir(BASE), workload_id="w1", approved_by="a"), private)
    substituted = dataclasses.replace(record, circuit_digest="0" * 64)
    assert verify_signature(substituted, public) is False


def test_registry_refuses_substituted_signature(keys) -> None:
    private, public = keys
    record = sign_baseline(create_baseline(_ir(BASE), workload_id="w1", approved_by="a"), private)
    forged = dataclasses.replace(record, readout_digest="1" * 64)
    with pytest.raises(BaselineError, match="signature does not verify"):
        BaselineRegistry().register(forged, public_key_pem=public)


def test_registry_refuses_a_different_key(keys) -> None:
    private, _ = keys
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    record = sign_baseline(create_baseline(_ir(BASE), workload_id="w1", approved_by="a"), private)
    with pytest.raises(BaselineError, match="signature does not verify"):
        BaselineRegistry().register(record, public_key_pem=other)


def test_rollback_is_refused(keys) -> None:
    private, public = keys
    registry = BaselineRegistry()
    v1 = sign_baseline(
        create_baseline(_ir(BASE), workload_id="w1", approved_by="a", version=1), private
    )
    registry.register(v1, public_key_pem=public)
    with pytest.raises(BaselineError, match="rollback refused"):
        registry.register(v1, public_key_pem=public)


def test_newer_version_is_accepted_and_history_retained(keys) -> None:
    private, public = keys
    registry = BaselineRegistry()
    v1 = sign_baseline(
        create_baseline(_ir(BASE), workload_id="w1", approved_by="a", version=1), private
    )
    v2 = sign_baseline(
        create_baseline(_ir(TAMPERED), workload_id="w1", approved_by="b", version=2), private
    )
    registry.register(v1, public_key_pem=public)
    registry.register(v2, public_key_pem=public)
    assert registry.resolve("w1", public_key_pem=public).record.version == 2
    assert registry.history("w1")[0]["version"] == 2


def test_unsigned_baseline_cannot_be_registered() -> None:
    record = create_baseline(_ir(BASE), workload_id="w1", approved_by="a")
    with pytest.raises(BaselineError, match="must be signed"):
        BaselineRegistry().register(record)


def test_missing_baseline_state() -> None:
    status = BaselineRegistry().resolve("nope")
    assert status.state is BaselineState.MISSING
    assert status.usable is False


def test_revoked_baseline_state(keys) -> None:
    _, public = keys
    registry = _registry(keys)
    registry.revoke("w1", by="sec@corp", reason="superseded")
    status = registry.resolve("w1", public_key_pem=public)
    assert status.state is BaselineState.REVOKED
    assert status.usable is False


def test_expired_baseline_state(keys) -> None:
    private, public = keys
    past = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    registry = BaselineRegistry()
    record = sign_baseline(
        create_baseline(_ir(BASE), workload_id="w1", approved_by="a", expires_at=past), private
    )
    registry.register(record, public_key_pem=public)
    assert registry.resolve("w1", public_key_pem=public).state is BaselineState.EXPIRED


def test_parser_incompatible_state(keys) -> None:
    private, public = keys
    registry = BaselineRegistry()
    record = sign_baseline(
        create_baseline(_ir(BASE), workload_id="w1", approved_by="a"), private
    )
    record = dataclasses.replace(record, canonicalization_spec="qshield-circuit-c14n-v0")
    # Re-sign so the record is otherwise valid; only the spec differs.
    unsigned = dataclasses.replace(record, signature=None)
    registry.register(sign_baseline(unsigned, private), public_key_pem=public)
    assert registry.resolve("w1", public_key_pem=public).state is BaselineState.PARSER_INCOMPATIBLE


def test_baseline_manifest_roundtrip_rejects_unknown_fields(tmp_path: Path, keys) -> None:
    private, _ = keys
    record = sign_baseline(create_baseline(_ir(BASE), workload_id="w1", approved_by="a"), private)
    payload = record.to_dict()
    target = tmp_path / "b.json"
    target.write_text(json.dumps(payload))
    assert load_baseline_file(target).workload_id == "w1"

    payload["unexpected"] = "x"
    target.write_text(json.dumps(payload))
    with pytest.raises(BaselineError, match="unknown baseline field"):
        load_baseline_file(target)


def test_baseline_manifest_rejects_duplicate_keys(tmp_path: Path) -> None:
    target = tmp_path / "dup.json"
    target.write_text('{"baseline_id": "a", "baseline_id": "b"}')
    with pytest.raises(BaselineError, match="duplicate key"):
        load_baseline_file(target)


# ---------------------------------------------------------------- evaluator states
def test_unchanged_candidate_passes(keys) -> None:
    registry = _registry(keys)
    result = evaluate_t23(_ir(BASE), registry=registry, workload_id="w1",
                          public_key_pem=keys[1])
    assert result.outcome is Outcome.PASS
    assert result.finding is None


def test_modified_readout_produces_a_finding_with_evidence(keys) -> None:
    registry = _registry(keys)
    result = evaluate_t23(_ir(TAMPERED), registry=registry, workload_id="w1",
                          public_key_pem=keys[1])
    assert result.outcome is Outcome.FINDING
    assert result.finding is not None
    details = result.finding.evidence.details
    assert details["candidate_digest"]
    assert details["reference_digest"]
    assert details["candidate_digest"] != details["reference_digest"]
    assert details["difference_category"] == "readout"
    assert details["differences"]
    assert "approved" in result.finding.description


def test_missing_baseline_is_indeterminate_not_pass(keys) -> None:
    result = evaluate_t23(_ir(BASE), registry=BaselineRegistry(), workload_id="w1")
    assert result.outcome is Outcome.INDETERMINATE
    assert result.blocked is True


def test_no_registry_is_indeterminate() -> None:
    result = evaluate_t23(_ir(TAMPERED), registry=None)
    assert result.outcome is Outcome.INDETERMINATE
    assert result.finding is None


def test_unverified_signature_is_indeterminate(keys) -> None:
    _, _ = keys
    other = Ed25519PrivateKey.generate().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    registry = _registry(keys)
    result = evaluate_t23(_ir(TAMPERED), registry=registry, workload_id="w1",
                          public_key_pem=other)
    assert result.outcome is Outcome.INDETERMINATE
    assert result.baseline is not None
    assert result.baseline.state is BaselineState.UNVERIFIED


def test_revoked_baseline_is_indeterminate(keys) -> None:
    registry = _registry(keys)
    registry.revoke("w1", by="sec", reason="test")
    result = evaluate_t23(_ir(TAMPERED), registry=registry, workload_id="w1",
                          public_key_pem=keys[1])
    assert result.outcome is Outcome.INDETERMINATE


def test_wrong_workload_resolves_missing(keys) -> None:
    registry = _registry(keys)
    result = evaluate_t23(_ir(TAMPERED), registry=registry, workload_id="other-workload",
                          public_key_pem=keys[1])
    assert result.outcome is Outcome.INDETERMINATE
    assert result.baseline.state is BaselineState.MISSING


def test_reference_mismatched_with_signed_digest_is_indeterminate(keys) -> None:
    """A verified record whose reference circuit was swapped must not be compared."""
    private, public = keys
    registry = BaselineRegistry()
    record = sign_baseline(
        create_baseline(_ir(BASE), workload_id="w1", approved_by="a"), private
    )
    substituted = dataclasses.replace(record, reference_circuit=_ir(TAMPERED))
    registry.register(substituted, public_key_pem=public)
    result = evaluate_t23(_ir(BASE), registry=registry, workload_id="w1",
                          public_key_pem=public)
    assert result.outcome is Outcome.INDETERMINATE
    assert "does not match the digest" in result.detail


def test_result_is_json_serialisable(keys) -> None:
    registry = _registry(keys)
    result = evaluate_t23(_ir(TAMPERED), registry=registry, workload_id="w1",
                          public_key_pem=keys[1])
    json.dumps(result.to_dict())


# ---------------------------------------------------------------- no regression
def test_structural_analyzer_no_longer_emits_t23() -> None:
    from qshield.core.config import load_config
    from qshield.static.structural_analyzer import StructuralAnalyzer

    analyzer = StructuralAnalyzer(load_config("default"))
    findings = analyzer.analyze(_ir(TAMPERED))
    assert [f for f in findings if f.threat_type == "T2.3"] == []


def test_signature_matcher_no_longer_emits_t23() -> None:
    from qshield.signatures.matcher import SignatureMatcher

    matcher = SignatureMatcher()
    findings = matcher.match(_ir(TAMPERED))
    assert [f for f in findings if f.threat_type == "T2.3"] == []


def test_exactly_one_t23_producer_remains() -> None:
    """Guard against re-introducing a second, context-free T2.3 source."""
    from qshield.core.config import load_config
    from qshield.signatures.matcher import SignatureMatcher
    from qshield.static.structural_analyzer import StructuralAnalyzer

    circuit = _ir(TAMPERED)
    sources = (
        StructuralAnalyzer(load_config("default")).analyze(circuit)
        + SignatureMatcher().match(circuit)
    )
    assert [f for f in sources if f.threat_type == "T2.3"] == []


def test_scanner_reports_indeterminate_without_baselines() -> None:
    import qshield

    circuit = _ir(TAMPERED)
    scanner = qshield.Scanner()
    scanner.add_circuit(circuit)
    results = scanner.run(analyses=["static"])
    assert circuit.metadata["t23_outcome"] == "indeterminate"
    assert [f for f in results.findings if f.threat_type == "T2.3"] == []
