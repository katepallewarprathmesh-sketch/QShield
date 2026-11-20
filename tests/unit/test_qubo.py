"""QUBO/Ising model audit: parsing, digest commitment, and model checks."""

from __future__ import annotations

import json
import math
from pathlib import Path

import numpy as np
import pytest

from qshield.qubo import (
    QUBO_SPEC_VERSION,
    WEAK_COUPLING_FLOOR,
    QuboModel,
    analyse_qubo,
    from_dict,
    from_matrix,
    parse_qubo,
    to_findings,
)


def _simple_model():
    matrix = np.zeros((4, 4))
    matrix[0, 0] = -2.0
    matrix[1, 1] = -3.0
    matrix[0, 1] = 2.0
    matrix[2, 2] = 1.0
    return from_matrix(matrix)


# ---------------------------------------------------------------- parsing
def test_from_matrix_reads_upper_triangle() -> None:
    model = _simple_model()
    assert model.num_variables == 4
    assert model.linear() == {0: -2.0, 1: -3.0, 2: 1.0}
    assert model.couplings() == {(0, 1): 2.0}


def test_from_matrix_rejects_non_square() -> None:
    with pytest.raises(ValueError, match="square"):
        from_matrix(np.zeros((2, 3)))


def test_from_dict_accepts_qubo_mapping() -> None:
    model = from_dict({"qubo": {"0,0": -1.0, "0,1": 2.0}})
    assert model.num_variables == 2
    assert model.linear() == {0: -1.0}
    assert model.couplings() == {(0, 1): 2.0}


def test_from_dict_accepts_matrix_form() -> None:
    model = from_dict({"qubo": [[0, 3.0], [0, 0]]})
    assert model.couplings() == {(0, 1): 3.0}


def test_from_dict_accepts_ising_terms() -> None:
    model = from_dict({"linear": {"0": -1.0}, "quadratic": {"0,1": 0.5}})
    assert model.num_variables == 2
    assert model.linear() == {0: -1.0}
    assert model.couplings() == {(0, 1): 0.5}


def test_from_dict_rejects_unknown_document() -> None:
    with pytest.raises(ValueError, match="unrecognised"):
        from_dict({"unexpected": []})


def test_parse_qubo_reads_file(tmp_path: Path) -> None:
    target = tmp_path / "model.qubo"
    target.write_text(json.dumps({"qubo": {"0,1": 4.0}}), encoding="utf-8")
    model = parse_qubo(target)
    assert model.couplings() == {(0, 1): 4.0}
    assert model.source == str(target)


def test_parse_qubo_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        parse_qubo("/nonexistent/model.qubo")


# ---------------------------------------------------------------- digest
def test_digest_is_deterministic() -> None:
    assert _simple_model().digest() == _simple_model().digest()


def test_digest_changes_when_a_coefficient_changes() -> None:
    baseline = _simple_model()
    tampered = np.zeros((4, 4))
    tampered[0, 0] = -2.0
    tampered[1, 1] = -3.0009  # the subtle change a tampered model would carry
    tampered[0, 1] = 2.0
    tampered[2, 2] = 1.0
    assert from_matrix(tampered).digest() != baseline.digest()


def test_digest_ignores_term_insertion_order() -> None:
    a = from_dict({"qubo": {"0,0": -1.0, "0,1": 2.0, "1,1": 3.0}})
    b = from_dict({"qubo": {"1,1": 3.0, "0,1": 2.0, "0,0": -1.0}})
    assert a.digest() == b.digest()


def test_digest_mismatch_is_a_high_severity_finding() -> None:
    report = analyse_qubo(_simple_model(), expected_digest="0" * 64)
    titles = {f.title for f in report.findings}
    assert "digest mismatch" in titles
    assert report.max_severity == "high"


def test_matching_digest_raises_no_finding() -> None:
    model = _simple_model()
    report = analyse_qubo(model, expected_digest=model.digest())
    assert "digest mismatch" not in {f.title for f in report.findings}


# ---------------------------------------------------------------- checks
def test_variable_budget_overflow_detected() -> None:
    report = analyse_qubo(_simple_model(), hardware_variables=2)
    assert "model exceeds the stated variable budget" in {f.title for f in report.findings}


def test_variable_budget_within_limit_is_quiet() -> None:
    report = analyse_qubo(_simple_model(), hardware_variables=5000)
    assert "model exceeds the stated variable budget" not in {f.title for f in report.findings}


def test_weak_couplings_are_flagged() -> None:
    matrix = np.zeros((3, 3))
    matrix[0, 1] = WEAK_COUPLING_FLOOR / 10.0
    report = analyse_qubo(from_matrix(matrix))
    assert "weak couplings below the control-error floor" in {f.title for f in report.findings}


def test_chain_strength_uses_uniform_torque_compensation() -> None:
    matrix = np.zeros((3, 3))
    matrix[0, 1] = 4.0
    matrix[1, 2] = 0.005
    report = analyse_qubo(from_matrix(matrix))
    chain = report.stats["chain_strength"]
    assert chain["available"] is True
    assert chain["method"] == "uniform_torque_compensation"
    # 1.414 * sqrt((16 + 0.000025) / 3)
    assert chain["recommended_chain_strength"] == pytest.approx(
        1.414 * math.sqrt((16.0 + 0.005**2) / 3), rel=1e-6
    )
    assert chain["largest_coupling"] == pytest.approx(4.0)
    assert chain["smallest_coupling"] == pytest.approx(0.005)


def test_chain_strength_counts_bias_torque() -> None:
    """A chain must resist bias torque as well as coupling torque."""
    matrix = np.zeros((2, 2))
    matrix[0, 0] = -1.0
    matrix[1, 1] = -1.0
    chain = analyse_qubo(from_matrix(matrix)).stats["chain_strength"]
    assert chain["available"] is True
    assert chain["recommended_chain_strength"] == pytest.approx(1.414 * math.sqrt(2.0 / 2))


def test_chain_strength_absent_for_an_empty_model() -> None:
    assert analyse_qubo(from_matrix(np.zeros((3, 3)))).stats["chain_strength"]["available"] is False


def test_unconstrained_variables_flagged() -> None:
    matrix = np.zeros((4, 4))
    matrix[0, 1] = 1.0
    report = analyse_qubo(from_matrix(matrix))
    assert "variables with no terms" in {f.title for f in report.findings}


def test_non_finite_coefficient_is_high_severity() -> None:
    model = from_dict({"qubo": {"0,0": -1.0, "0,1": 2.0}})
    model.quadratic[(1, 1)] = float("inf")
    report = analyse_qubo(model)
    assert report.max_severity == "high"
    assert any("non-finite" in f.title for f in report.findings)


def test_clean_model_reports_no_findings() -> None:
    matrix = np.zeros((3, 3))
    matrix[0, 0] = -0.5
    matrix[1, 1] = -0.5
    matrix[0, 1] = 0.5
    matrix[1, 2] = 0.5
    matrix[0, 2] = 0.25
    matrix[2, 2] = -0.75
    report = analyse_qubo(from_matrix(matrix))
    assert report.findings == []


# ---------------------------------------------------------------- integration
def test_findings_use_the_published_threat_taxonomy() -> None:
    report = analyse_qubo(_simple_model(), hardware_variables=1)
    findings = to_findings(report)
    assert findings
    assert all(f.threat_type.startswith("T") for f in findings)


def test_report_dict_is_json_serialisable() -> None:
    payload = analyse_qubo(_simple_model()).to_dict()
    json.dumps(payload)
    assert payload["spec_version"] == QUBO_SPEC_VERSION
    assert len(payload["digest"]) == 64


def test_scanner_accepts_qubo_and_reports_findings() -> None:
    import qshield

    matrix = np.zeros((3, 3))
    matrix[0, 1] = 2.0
    matrix[1, 2] = WEAK_COUPLING_FLOOR / 10.0
    scanner = qshield.Scanner()
    scanner.add_qubo(matrix)
    results = scanner.run(analyses=["static"])
    assert results.findings
    assert all("QUBO model" in f.title for f in results.findings)


# ---------------------------------------------------- commitment hardness
def test_digest_detects_perturbation_below_the_rounding_step() -> None:
    """A commitment that rounds coefficients is blind to the tamper it exists to catch."""
    baseline = from_dict({"qubo": {"0,0": -1.0, "0,1": 2.0}})
    nudged = from_dict({"qubo": {"0,0": -1.0, "0,1": 2.0 + 1e-13}})
    assert baseline.digest() != nudged.digest()


def test_digest_normalises_negative_zero() -> None:
    assert (
        from_dict({"qubo": {"0,0": -0.0}}).digest()
        == from_dict({"qubo": {"0,0": 0.0}}).digest()
    )


# ---------------------------------------------------- hostile input
@pytest.mark.parametrize(
    "document",
    [
        {"qubo": {"-1,0": 1.0}},
        {"qubo": {"a,b": 1.0}},
        {"qubo": {"0,1,2": 1.0}},
        {"qubo": {"99999999,0": 1.0}},
        {"qubo": {"0,1": 2.0, "1,0": 99.0}},
        {"qubo": [[0, 1], [0]]},
        {"qubo": {"0,0": 1.0}, "num_variables": 0},
    ],
)
def test_malformed_documents_are_rejected(document) -> None:
    with pytest.raises((TypeError, ValueError)):
        from_dict(document)


def test_string_coefficient_is_not_silently_coerced() -> None:
    with pytest.raises(TypeError, match="string"):
        from_dict({"qubo": {"0,0": "1.0"}})


def test_declared_variable_count_is_honoured() -> None:
    model = from_dict({"num_variables": 1000, "qubo": {"0,0": 1.0}})
    assert model.num_variables == 1000


def test_symmetric_matrix_is_not_double_counted() -> None:
    matrix = np.zeros((3, 3))
    matrix[0, 1] = matrix[1, 0] = 2.0
    assert from_matrix(matrix).couplings() == {(0, 1): 2.0}


def test_asymmetric_matrix_is_rejected() -> None:
    matrix = np.zeros((2, 2))
    matrix[0, 1] = 2.0
    matrix[1, 0] = 5.0
    with pytest.raises(ValueError, match="asymmetric"):
        from_matrix(matrix)


def test_parse_failure_names_the_file(tmp_path: Path) -> None:
    target = tmp_path / "broken.qubo"
    target.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="broken\\.qubo"):
        parse_qubo(target)


# ---------------------------------------------------- check correctness
def test_dynamic_range_reported_at_the_boundary() -> None:
    matrix = np.zeros((3, 3))
    matrix[0, 1] = 5e-3
    matrix[1, 2] = 5000.0  # ratio is exactly 1e6
    report = analyse_qubo(from_matrix(matrix))
    assert "extreme dynamic range across couplings" in {f.title for f in report.findings}


def test_dynamic_range_below_the_boundary_is_quiet() -> None:
    matrix = np.zeros((3, 3))
    matrix[0, 1] = 5e-3
    matrix[1, 2] = 4999.0
    report = analyse_qubo(from_matrix(matrix))
    assert "extreme dynamic range across couplings" not in {f.title for f in report.findings}


def test_ising_range_check_applies_to_ising_documents() -> None:
    ising = analyse_qubo(from_dict({"linear": {"0": -5.0}, "quadratic": {"0,1": 3.0}}))
    assert "Ising coefficients outside the [-1, 1] range" in {f.title for f in ising.findings}


def test_ising_range_check_does_not_fire_on_qubo_scale() -> None:
    qubo = analyse_qubo(from_dict({"qubo": {"0,0": -5.0, "0,1": 3.0}}))
    assert "Ising coefficients outside the [-1, 1] range" not in {f.title for f in qubo.findings}


def test_model_findings_are_reproducible() -> None:
    matrix = np.zeros((3, 3))
    matrix[0, 1] = 2.0
    matrix[1, 2] = WEAK_COUPLING_FLOOR / 10.0
    first = to_findings(analyse_qubo(from_matrix(matrix), hardware_variables=1))
    second = to_findings(analyse_qubo(from_matrix(matrix), hardware_variables=1))
    assert [f.circuit_id for f in first] == [f.circuit_id for f in second]


# ---------------------------------------------------- robustness
def test_undeclared_index_is_reported_not_crashed() -> None:
    """A term naming an undeclared variable is a finding, not a KeyError."""
    model = QuboModel(num_variables=2, quadratic={(0, 0): -1.0, (0, 7): 2.0})
    report = analyse_qubo(model)
    assert "index out of range" in {f.title for f in report.findings}
    assert report.stats["structural_ok"] is False


def test_negative_index_is_reported_not_crashed() -> None:
    model = QuboModel(num_variables=2, quadratic={(0, 0): -1.0, (-1, 0): 2.0})
    report = analyse_qubo(model)
    assert "index out of range" in {f.title for f in report.findings}
    assert report.stats["structural_ok"] is False


def test_lower_triangular_term_is_reported() -> None:
    model = QuboModel(num_variables=4, quadratic={(0, 0): -1.0, (3, 1): 2.0})
    report = analyse_qubo(model)
    assert "lower-triangular term" in {f.title for f in report.findings}


def test_non_finite_models_do_not_crash_the_analyser() -> None:
    model = QuboModel(
        num_variables=3,
        quadratic={(0, 0): float("nan"), (1, 1): float("inf"), (2, 2): -1.0},
    )
    report = analyse_qubo(model)
    assert report.max_severity == "high"
    json.dumps(report.to_dict())


def test_qubo_file_size_cap(tmp_path: Path, monkeypatch) -> None:
    import qshield.qubo as qubo_module

    target = tmp_path / "model.qubo"
    target.write_text('{"qubo": {"0,0": 1.0}}', encoding="utf-8")
    monkeypatch.setattr(qubo_module, "MAX_MODEL_BYTES", 4)
    with pytest.raises(ValueError, match="cap"):
        parse_qubo(target)
