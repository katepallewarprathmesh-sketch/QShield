import pytest

from qshield.dynamic.statistical_tests import (
    compare_distributions,
    detect_entropy_anomaly,
    jensen_shannon_divergence,
    kl_divergence,
    sample_counts_from_probabilities,
    shannon_entropy,
    total_variation_distance,
)


def test_identical_distributions_consistent():
    trusted = {"00": 500, "11": 500}
    untrusted = {"00": 498, "11": 502}
    result = compare_distributions(trusted, untrusted)
    assert not result.suspicious
    assert result.jensen_shannon < 0.01
    assert result.total_variation < 0.05


def test_divergent_distributions_flagged():
    trusted = {"00": 900, "01": 33, "10": 33, "11": 34}
    tampered = {"00": 10, "01": 330, "10": 330, "11": 330}
    result = compare_distributions(trusted, tampered)
    assert result.suspicious
    assert result.jensen_shannon > 0.1
    assert result.total_variation > 0.5


def test_js_and_tv_bounds():
    p = {"a": 0.5, "b": 0.5}
    q = {"a": 0.5, "b": 0.5}
    assert jensen_shannon_divergence(p, q) == pytest.approx(0.0)
    assert total_variation_distance(p, q) == pytest.approx(0.0)
    assert 0.0 <= jensen_shannon_divergence(p, {"a": 1.0, "b": 0.0}) <= 1.0


def test_kl_divergence_nonnegative():
    p = {"a": 0.7, "b": 0.3}
    q = {"a": 0.4, "b": 0.6}
    assert kl_divergence(p, q) > 0


def test_entropy():
    assert shannon_entropy({"0": 100}) == pytest.approx(0.0)
    assert shannon_entropy({"0": 50, "1": 50}) == pytest.approx(1.0)


def test_detect_entropy_anomaly():
    result = detect_entropy_anomaly({"0": 50, "1": 50}, (0.5, 1.5))
    assert result.in_range
    result = detect_entropy_anomaly({"0": 100}, (0.5, 1.5))
    assert not result.in_range


def test_sampler_reproducible():
    probs = {"00": 0.5, "11": 0.5}
    a = sample_counts_from_probabilities(probs, 1000)
    assert sum(a.values()) == 1000
