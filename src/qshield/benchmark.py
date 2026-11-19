"""QSHIELD open benchmark — corpus v1, scorer, and result schema.

This module is the reference implementation of the public benchmark protocol
described in ``benchmarks/benchmark-v1.md``. It is deliberately small and
dependency-free so that an outside party can rerun it and reproduce the
published numbers.

Design rules (see the architecture doc):

* The corpus is versioned and labelled; labels ship with the corpus.
* Every reported number is produced by this scorer, on this corpus, and is a
  fixture-corpus measurement. It is never presented as field performance.
* Undetected circuits and false positives are reported, not hidden.
* The output is deterministic, so two runs on the same corpus and the same
  QSHIELD version are byte-identical apart from timing fields.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

BENCHMARK_SPEC_VERSION = "qshield-benchmark-v1"
CORPUS_VERSION = "corpus-v1"

ROOT = Path(__file__).resolve().parent.parent

_REPO_FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
_PACKAGED_FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _fixture_root() -> Path:
    """Repo fixtures when developing, packaged fixtures after install."""
    override = os.environ.get("QSHIELD_FIXTURES_DIR")
    if override:
        return Path(override).expanduser()
    required = ("clean_circuits", "malicious_circuits")
    if all((_REPO_FIXTURES / name).is_dir() for name in required):
        return _REPO_FIXTURES
    return _PACKAGED_FIXTURES


FIXTURES = _fixture_root()
CLEAN_DIR = FIXTURES / "clean_circuits"
MALICIOUS_DIR = FIXTURES / "malicious_circuits"
# The index is only shipped in the repository; the curated label table below is
# authoritative for fixtures it does not cover.
CORPUS_INDEX = Path(__file__).resolve().parents[2] / "benchmarks" / "corpus_index.json"

# Published scoring threshold: a circuit counts as flagged when QSHIELD emits at
# least one finding at or above this severity. Ties are resolved by severity.
DEFAULT_THRESHOLD = "medium"

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Expected threat label for the hand-written (curated) malicious fixtures.
# Generated fixtures (gen_* prefix) take their label from corpus_index.json.
CURATED_LABELS: dict[str, str] = {
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
    "h_cancellation_adjacent": "T1.3",
    "cx_cx_separated": "T1.3",
    "y_y_pair_separated": "T1.3",
    "leaf_ancilla_swap": "T2.1",
    "micro_rotation_dense": "T1.1",
    "stego_ascii_backdoor": "T2.2",
    "x_before_measure": "T2.3",
    "y_before_measure": "T2.3",
}

# Attack family -> plain-English description, published with the corpus.
FAMILIES: dict[str, str] = {
    "T1.1": "Gate-level tampering: injected rotations or substituted gates that alter behavior.",
    "T1.3": "Concealed identity structure: cancellation and separation patterns used to hide payloads.",
    "T2.1": "Ancilla information leakage: auxiliary qubits that carry data-dependent state.",
    "T2.2": "Encoded payloads: parameter grids and steganographic instruction encoding.",
    "T2.3": "Measurement manipulation: basis or pre-measurement gates that corrupt results.",
}


@dataclass
class CircuitOutcome:
    """Scored outcome for one fixture."""

    name: str
    split: str            # "clean" | "malicious"
    expected: str | None  # expected threat type, None for clean
    flagged: bool
    findings: int
    max_severity: str | None
    threat_types: list[str] = field(default_factory=list)
    label_matched: bool | None = None


def corpus_labels() -> dict[str, str]:
    """Return the expected threat type for every malicious fixture."""
    labels = dict(CURATED_LABELS)
    if CORPUS_INDEX.is_file():
        generated = json.loads(CORPUS_INDEX.read_text(encoding="utf-8")).get(
            "generated_malicious", {}
        )
        labels.update(generated)
    return labels


def corpus_manifest() -> dict[str, Any]:
    """Describe the corpus: version, counts, per-file digests, and labels."""
    labels = corpus_labels()
    files: list[dict[str, Any]] = []
    digest = hashlib.sha256()

    for split, directory in (("clean", CLEAN_DIR), ("malicious", MALICIOUS_DIR)):
        for path in sorted(directory.glob("*.qasm")):
            data = path.read_bytes()
            sha = hashlib.sha256(data).hexdigest()
            digest.update(f"{split}/{path.name}:{sha}\n".encode())
            files.append(
                {
                    "name": path.stem,
                    "split": split,
                    "file": f"{directory.name}/{path.name}",
                    "sha256": sha,
                    "bytes": len(data),
                    "expected_threat": labels.get(path.stem) if split == "malicious" else None,
                }
            )

    return {
        "spec_version": BENCHMARK_SPEC_VERSION,
        "corpus_version": CORPUS_VERSION,
        "corpus_sha256": digest.hexdigest(),
        "clean": sum(1 for f in files if f["split"] == "clean"),
        "malicious": sum(1 for f in files if f["split"] == "malicious"),
        "families": FAMILIES,
        "files": files,
    }


def _threat_types(findings: list[Any]) -> list[str]:
    return sorted({f.threat_type for f in findings})


def score_circuit(
    name: str,
    source: str,
    split: str,
    expected: str | None,
    threshold: str = DEFAULT_THRESHOLD,
) -> CircuitOutcome:
    """Scan one circuit and score it against its published label."""
    from qshield.scanner import Scanner

    scanner = Scanner(config="default")
    scanner.add_circuit(source, name=name)
    findings = list(scanner.run(analyses=["static"]).findings)

    floor = _SEVERITY_ORDER[threshold]
    above = [f for f in findings if f.severity_rank >= floor]
    max_sev = (
        max((f.severity for f in findings), key=lambda s: _SEVERITY_ORDER[s]) if findings else None
    )
    threats = _threat_types(findings)
    flagged = bool(above)
    matched = None
    if split == "malicious" and expected is not None:
        matched = expected in threats
    return CircuitOutcome(
        name=name,
        split=split,
        expected=expected,
        flagged=flagged,
        findings=len(findings),
        max_severity=max_sev,
        threat_types=threats,
        label_matched=matched,
    )


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 4) if denominator else 0.0


def summarise(outcomes: list[CircuitOutcome], threshold: str) -> dict[str, Any]:
    """Aggregate per-circuit outcomes into the published metric block."""
    clean = [o for o in outcomes if o.split == "clean"]
    malicious = [o for o in outcomes if o.split == "malicious"]

    true_positives = sum(1 for o in malicious if o.flagged)
    false_negatives = len(malicious) - true_positives
    false_positives = sum(1 for o in clean if o.flagged)
    true_negatives = len(clean) - false_positives
    label_hits = sum(1 for o in malicious if o.label_matched)

    by_family: dict[str, dict[str, Any]] = {}
    for family in sorted(FAMILIES):
        members = [o for o in malicious if o.expected == family]
        if not members:
            continue
        detected = sum(1 for o in members if o.flagged)
        by_family[family] = {
            "circuits": len(members),
            "detected": detected,
            "recall": _ratio(detected, len(members)),
            "description": FAMILIES[family],
        }

    precision_denominator = true_positives + false_positives
    return {
        "threshold": threshold,
        "counts": {
            "clean": len(clean),
            "malicious": len(malicious),
            "true_positives": true_positives,
            "false_negatives": false_negatives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "label_matches": label_hits,
        },
        "tpr": _ratio(true_positives, len(malicious)),
        "fpr": _ratio(false_positives, len(clean)),
        "precision": _ratio(true_positives, precision_denominator),
        "recall": _ratio(label_hits, len(malicious)),
        "by_family": by_family,
    }


def threshold_sweep(
    sample: int | None = None,
    thresholds: tuple[str, ...] = ("medium", "high", "critical"),
) -> list[dict[str, Any]]:
    """Score the corpus at each flagging threshold so the tradeoff is visible.

    Reported alongside the headline result: readers choose their own operating
    point instead of being handed a single flattering number.
    """
    rows: list[dict[str, Any]] = []
    for threshold in thresholds:
        result = run_benchmark(sample=sample, threshold=threshold, include_sweep=False)
        metrics = result["metrics"]
        rows.append(
            {
                "threshold": threshold,
                "tpr": metrics["tpr"],
                "fpr": metrics["fpr"],
                "precision": metrics["precision"],
                "recall": metrics["recall"],
            }
        )
    return rows


def run_benchmark(
    sample: int | None = None,
    threshold: str = DEFAULT_THRESHOLD,
    include_sweep: bool = True,
) -> dict[str, Any]:
    """Score the whole corpus and return a schema-valid result document."""
    from qshield import __version__

    if threshold not in _SEVERITY_ORDER:
        raise ValueError(f"unknown threshold: {threshold}")
    if sample is not None and sample < 0:
        raise ValueError("sample must be non-negative")

    manifest = corpus_manifest()
    labels = corpus_labels()
    clean_files = sorted(CLEAN_DIR.glob("*.qasm"))
    malicious_files = sorted(MALICIOUS_DIR.glob("*.qasm"))
    if sample is not None:
        clean_files = clean_files[:sample]
        malicious_files = malicious_files[:sample]

    outcomes: list[CircuitOutcome] = []
    for path in clean_files:
        outcomes.append(
            score_circuit(path.stem, path.read_text(encoding="utf-8"), "clean", None, threshold)
        )
    for path in malicious_files:
        outcomes.append(
            score_circuit(
                path.stem,
                path.read_text(encoding="utf-8"),
                "malicious",
                labels.get(path.stem),
                threshold,
            )
        )

    metrics = summarise(outcomes, threshold)
    misses = [
        {"name": o.name, "expected": o.expected, "threat_types": o.threat_types}
        for o in outcomes
        if o.split == "malicious" and not o.flagged
    ]
    false_positives = [
        {"name": o.name, "threat_types": o.threat_types}
        for o in outcomes
        if o.split == "clean" and o.flagged
    ]

    result: dict[str, Any] = {
        "spec_version": BENCHMARK_SPEC_VERSION,
        "corpus_version": CORPUS_VERSION,
        "corpus_sha256": manifest["corpus_sha256"],
        "qshield_version": __version__,
        "threshold": threshold,
        "metrics": metrics,
        "misses": misses,
        "false_positives": false_positives,
        "per_circuit": [
            {
                "name": o.name,
                "split": o.split,
                "expected_threat": o.expected,
                "flagged": o.flagged,
                "findings": o.findings,
                "max_severity": o.max_severity,
                "threat_types": o.threat_types,
                "label_matched": o.label_matched,
            }
            for o in outcomes
        ],
    }
    if include_sweep:
        result["threshold_sweep"] = threshold_sweep(sample=sample)
    return result
