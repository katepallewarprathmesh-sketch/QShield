"""The open benchmark must be reproducible and schema-valid."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import qshield
from qshield.benchmark import (
    CLEAN_DIR,
    MALICIOUS_DIR,
    corpus_labels,
    corpus_manifest,
    run_benchmark,
)

_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA = json.loads((_ROOT / "benchmarks" / "benchmark-v1.schema.json").read_text(encoding="utf-8"))
_RESULTS = _ROOT / "benchmarks" / "results" / "benchmark-v1.json"


def _validator():
    """jsonschema is an optional test dependency; only schema tests need it."""
    jsonschema = pytest.importorskip("jsonschema", reason="optional test dependency")
    return jsonschema


def _corpus_present() -> bool:
    return CLEAN_DIR.is_dir() and MALICIOUS_DIR.is_dir()


def test_corpus_labels_cover_every_malicious_fixture() -> None:
    labels = corpus_labels()
    names = {p.stem for p in MALICIOUS_DIR.glob("*.qasm")}
    missing = sorted(names - set(labels))
    assert not missing, f"unlabelled malicious fixtures: {missing[:5]}"
    assert all(value.startswith("T") for value in labels.values())


def test_corpus_manifest_is_deterministic() -> None:
    first = corpus_manifest()
    second = corpus_manifest()
    assert first["corpus_sha256"] == second["corpus_sha256"]
    assert first["clean"] == len(list(CLEAN_DIR.glob("*.qasm")))
    assert first["malicious"] == len(list(MALICIOUS_DIR.glob("*.qasm")))


@pytest.mark.skipif(not _corpus_present(), reason="fixture corpus absent")
def test_benchmark_counts_match_requested_sample() -> None:
    result = run_benchmark(sample=4, include_sweep=False)
    counts = result["metrics"]["counts"]
    assert counts["clean"] == counts["malicious"] == 4
    assert 0.0 <= result["metrics"]["tpr"] <= 1.0
    assert 0.0 <= result["metrics"]["fpr"] <= 1.0


@pytest.mark.skipif(not _corpus_present(), reason="fixture corpus absent")
def test_benchmark_is_reproducible() -> None:
    first = run_benchmark(sample=3, include_sweep=False)
    second = run_benchmark(sample=3, include_sweep=False)
    assert first == second


@pytest.mark.skipif(not _corpus_present(), reason="fixture corpus absent")
def test_benchmark_result_matches_schema() -> None:
    jsonschema = _validator()
    jsonschema.validate(run_benchmark(sample=4, include_sweep=False), _SCHEMA)


@pytest.mark.skipif(not _RESULTS.is_file(), reason="published results absent")
def test_published_results_are_schema_valid() -> None:
    jsonschema = _validator()
    jsonschema.validate(json.loads(_RESULTS.read_text(encoding="utf-8")), _SCHEMA)


@pytest.mark.skipif(not _RESULTS.is_file(), reason="published results absent")
def test_published_results_match_package_version() -> None:
    published = json.loads(_RESULTS.read_text(encoding="utf-8"))
    assert published["qshield_version"] == qshield.__version__


def test_unknown_threshold_rejected() -> None:
    with pytest.raises(ValueError, match="unknown threshold"):
        run_benchmark(threshold="severe", include_sweep=False)
