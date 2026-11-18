"""Coverage report model for a single QSHIELD scan run."""

from __future__ import annotations

from collections import Counter
from typing import Any

COVERAGE_SPEC = "qshield-coverage-v1"
COVERAGE_STATUSES = ("completed", "inconclusive", "skipped", "not_run", "not_applicable")


def coverage_item(status: str, *reasons: str, **details: Any) -> dict[str, Any]:
    if status not in COVERAGE_STATUSES:
        raise ValueError(f"invalid coverage status: {status}")
    item: dict[str, Any] = {"status": status, "reasons": [reason for reason in reasons if reason]}
    if details:
        item["details"] = details
    return item


def build_coverage_report(
    *,
    requested_analyses: list[str],
    circuits: list[dict[str, Any]],
    supply_chain: dict[str, Any],
    unsupported_analyses: list[str] | None = None,
) -> dict[str, Any]:
    """Aggregate per-circuit and supply-chain pipeline outcomes."""
    counts: dict[str, Counter[str]] = {}
    for circuit in circuits:
        for name, item in circuit["analyses"].items():
            counts.setdefault(name, Counter())[item["status"]] += 1
    if "supply_chain" in requested_analyses:
        counts.setdefault("supply_chain", Counter())[supply_chain["status"]] += 1
    circuit_analyses = {"static", "dynamic", "formal"}
    no_circuit_runs = sorted(set(requested_analyses) & circuit_analyses) if not circuits else []
    for name in no_circuit_runs:
        counts.setdefault(name, Counter())["not_run"] += 1
    analyses_summary = {
        name: {status: count.get(status, 0) for status in COVERAGE_STATUSES}
        for name, count in sorted(counts.items())
    }
    inconclusive = sum(
        count.get("inconclusive", 0) + count.get("skipped", 0)
        for name, count in counts.items() if name in requested_analyses
    )
    not_run_requested = sum(count.get("not_run", 0) for name, count in counts.items() if name in requested_analyses)
    unsupported = sorted(set(unsupported_analyses or []))
    if unsupported:
        inconclusive += len(unsupported)

    return {
        "spec_version": COVERAGE_SPEC,
        "granularity": "analysis-pipeline; not per-rule or per-gate",
        "requested_analyses": list(requested_analyses),
        "overall_status": "inconclusive" if inconclusive or not_run_requested else "complete",
        "summary": {
            "circuits_total": len(circuits),
            "circuits_processed": sum(1 for circuit in circuits if circuit["processed"]),
            "inconclusive_pipeline_runs": inconclusive,
            "requested_pipeline_runs_not_started": not_run_requested,
            "by_analysis": analyses_summary,
        },
        "circuits": circuits,
        "supply_chain": supply_chain,
        "unsupported_analyses": unsupported,
        "limitations": [
            "Completed means the named pipeline ran; it does not imply every detector matched every circuit construct.",
            "Inconclusive and not-run checks are not passes; review their reasons before relying on a clean result.",
            "Coverage is pipeline-level and does not establish that a circuit is safe or that unknown threats are absent.",
        ],
    }
