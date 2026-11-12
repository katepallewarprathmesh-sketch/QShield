"""Statistical tests for comparing measurement distributions."""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from scipy import stats


@dataclass
class ComparisonResult:
    chi_square_p: float
    kl_divergence: float
    jensen_shannon: float
    total_variation: float
    ks_statistic: float
    ks_pvalue: float
    significance_level: float
    suspicious: bool
    verdict: str
    js_threshold: float = 0.05
    tv_threshold: float = 0.1


@dataclass
class EntropyResult:
    entropy_bits: float
    expected_range: tuple[float, float]
    in_range: bool
    num_outcomes: int
    num_distinct: int


def _normalise(counts: dict[str, int]) -> dict[str, float]:
    total = sum(counts.values())
    if total <= 0:
        raise ValueError("Distribution has no samples")
    return {k: v / total for k, v in counts.items()}


def _aligned(p: dict[str, float], q: dict[str, float]) -> tuple[np.ndarray, np.ndarray]:
    keys = sorted(set(p) | set(q))
    pv = np.array([p.get(k, 0.0) for k in keys], dtype=float)
    qv = np.array([q.get(k, 0.0) for k in keys], dtype=float)
    return pv, qv


def chi_squared_test(observed: dict[str, int], expected_probs: dict[str, float]) -> tuple[float, float]:
    """Chi-squared goodness-of-fit; returns (statistic, p_value).

    Bins follow the *union* of observed and expected outcomes, with a
    pseudocount floor (0.5) on bins whose expected probability is zero —
    otherwise rigged outcomes outside the reference support would be
    invisible to the test.
    """
    keys = sorted(set(observed) | set(expected_probs))
    if not keys:
        raise ValueError("Expected distribution is empty")
    obs = np.array([observed.get(k, 0) for k in keys], dtype=float)
    total = obs.sum()
    if total <= 0:
        raise ValueError("Observed distribution is empty")
    exp = np.array([expected_probs.get(k, 0.0) for k in keys], dtype=float) * total
    exp = np.maximum(exp, 0.5)
    exp = exp / exp.sum() * total  # keep sums equal for scipy
    if len(keys) == 1:
        # single deterministic outcome: exact match or hopeless
        return (0.0, 1.0) if obs[0] == total else (float(total - obs[0]), 0.0)
    stat, p = stats.chisquare(f_obs=obs, f_exp=exp)
    return float(stat), float(p)


def chi_squared_homogeneity(a: dict[str, int], b: dict[str, int]) -> tuple[float, float]:
    """Two-sample chi-squared homogeneity test on two count histograms.

    Valid under arbitrary (unknown) shared noise, unlike goodness-of-fit
    against a reference probability vector.  Bins are the union of the two
    supports; expected counts come from the pooled proportions.
    """
    keys = sorted(set(a) | set(b))
    if len(keys) <= 1:
        return 0.0, 1.0
    va = np.array([a.get(k, 0) for k in keys], dtype=float)
    vb = np.array([b.get(k, 0) for k in keys], dtype=float)
    na, nb = va.sum(), vb.sum()
    if na == 0 or nb == 0:
        raise ValueError("Both distributions must be non-empty")
    pooled = va + vb
    prop = pooled / pooled.sum()
    ea, eb = prop * na, prop * nb
    ea = np.maximum(ea, 1e-9)
    eb = np.maximum(eb, 1e-9)
    stat = float(np.sum((va - ea) ** 2 / ea + (vb - eb) ** 2 / eb))
    # homogeneity chi2 with k bins has k-1 degrees of freedom
    p = float(stats.chi2.sf(stat, df=len(keys) - 1))
    return stat, p


def kl_divergence(p: dict[str, float], q: dict[str, float], epsilon: float = 1e-10) -> float:
    """KL(p || q) in nats, with additive smoothing."""
    pv, qv = _aligned(p, q)
    pv = pv + epsilon
    qv = qv + epsilon
    pv /= pv.sum()
    qv /= qv.sum()
    return float(np.sum(pv * np.log(pv / qv)))


def jensen_shannon_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    """Jensen-Shannon divergence in bits (0..1)."""
    pv, qv = _aligned(p, q)
    if pv.sum() == 0 or qv.sum() == 0:
        raise ValueError("Both distributions must be non-empty")
    pv /= pv.sum()
    qv /= qv.sum()
    mid = 0.5 * (pv + qv)
    def _kl(a, b):
        mask = a > 0
        return float(np.sum(a[mask] * np.log2(a[mask] / b[mask])))
    return 0.5 * _kl(pv, mid) + 0.5 * _kl(qv, mid)


def total_variation_distance(p: dict[str, float], q: dict[str, float]) -> float:
    pv, qv = _aligned(p, q)
    if pv.sum() > 0:
        pv = pv / pv.sum()
    if qv.sum() > 0:
        qv = qv / qv.sum()
    return float(0.5 * np.sum(np.abs(pv - qv)))


def compare_distributions(
    trusted_results: dict[str, int],
    untrusted_results: dict[str, int],
    significance_level: float = 0.01,
    js_threshold: float = 0.05,
    tv_threshold: float = 0.1,
    noise_aware: bool = False,
    chi_mode: str = "homogeneity",
) -> ComparisonResult:
    """Full statistical comparison of two measurement distributions.

    ``js_threshold``/``tv_threshold`` are the noise-aware cut-offs: when the
    untrusted backend is expected to run with a noise floor (e.g. a depolarizing
    channel of rate ``eps``), raise them so honest noise does not trip the
    alarm.  Benchmark-calibrated guidance (see ``benchmarks/evaluate_dynamic.py``):
    TV drift from per-gate depolarizing noise grows roughly linearly with
    ``eps * n_noisy_gates``; a safe inflation is ``tv_threshold + 2*eps*gate_count``
    and the analogous ``js_threshold + 1.5*eps*gate_count``.  The defaults keep
    the original strict behaviour (JS > 0.05 or TV > 0.1).

    ``chi_mode`` selects the chi-squared flavour:

    - ``"homogeneity"`` (default): two-sample chi-squared between the two
      count histograms — the statistically correct test when both backends
      contribute sampling noise (the trusted reference is itself counts, and
      goodness-of-fit against *empirical* probabilities approximately doubles
      the statistic, inflating false positives ~10x above nominal).
    - ``"goodness_of_fit"``: Pearson chi-squared against the trusted
      probabilities.  Only valid when the reference probabilities are exact
      (e.g. analytic) — otherwise wildly anti-conservative at large shots.

    With ``noise_aware=True`` the homogeneity test is used *and* the caller
    typically inflates ``js_threshold``/``tv_threshold`` to the noise floor.
    """
    p_norm = _normalise(trusted_results)
    q_norm = _normalise(untrusted_results)

    if chi_mode == "homogeneity" or noise_aware:
        _chi_stat, chi_p = chi_squared_homogeneity(trusted_results, untrusted_results)
    elif chi_mode == "goodness_of_fit":
        _chi_stat, chi_p = chi_squared_test(untrusted_results, p_norm)
    else:
        raise ValueError(f"Unknown chi_mode {chi_mode!r}; expected 'homogeneity' or 'goodness_of_fit'")
    kl = kl_divergence(q_norm, p_norm)
    js = jensen_shannon_divergence(p_norm, q_norm)
    tv = total_variation_distance(p_norm, q_norm)

    # Kolmogorov-Smirnov on cumulative distributions over sorted outcomes
    keys = sorted(set(p_norm) | set(q_norm))
    cdf_p = np.cumsum([p_norm.get(k, 0.0) for k in keys])
    cdf_q = np.cumsum([q_norm.get(k, 0.0) for k in keys])
    ks_stat = float(np.max(np.abs(cdf_p - cdf_q)))
    # approximate two-sample KS p-value
    n_eff = min(sum(trusted_results.values()), sum(untrusted_results.values()))
    en = np.sqrt(n_eff) * ks_stat
    ks_p = float(np.exp(-2 * en * en) * 2)

    suspicious = (chi_p < significance_level) or (js > js_threshold) or (tv > tv_threshold)
    if suspicious:
        verdict = "DIVERGENT: distributions differ significantly"
    else:
        verdict = "CONSISTENT: distributions are statistically indistinguishable"
    return ComparisonResult(
        chi_square_p=chi_p,
        kl_divergence=kl,
        jensen_shannon=js,
        total_variation=tv,
        ks_statistic=ks_stat,
        ks_pvalue=ks_p,
        significance_level=significance_level,
        suspicious=suspicious,
        verdict=verdict,
        js_threshold=js_threshold,
        tv_threshold=tv_threshold,
    )


def shannon_entropy(results: dict[str, int]) -> float:
    """Shannon entropy of the outcome distribution, in bits."""
    probs = _normalise(results)
    return float(-sum(p * math.log2(p) for p in probs.values() if p > 0))


def detect_entropy_anomaly(
    results: dict[str, int],
    expected_entropy_range: tuple[float, float],
) -> EntropyResult:
    ent = shannon_entropy(results)
    lo, hi = expected_entropy_range
    return EntropyResult(
        entropy_bits=ent,
        expected_range=(lo, hi),
        in_range=(lo <= ent <= hi),
        num_outcomes=sum(results.values()),
        num_distinct=len(results),
    )


def sample_counts_from_probabilities(
    probabilities: dict[str, float],
    shots: int,
    rng: np.random.Generator | None = None,
) -> dict[str, int]:
    """Draw ``shots`` samples from a {outcome: probability} distribution."""
    rng = rng or np.random.default_rng(20240611)
    outcomes = sorted(probabilities)
    probs = np.array([probabilities[k] for k in outcomes], dtype=float)
    probs = probs / probs.sum()
    idx = rng.choice(len(outcomes), size=shots, p=probs)
    counts: dict[str, int] = {}
    for i in idx:
        counts[outcomes[i]] = counts.get(outcomes[i], 0) + 1
    return counts
