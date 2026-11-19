#!/usr/bin/env python3
"""Run the QSHIELD open benchmark and write reproducible results.

Usage:
    python benchmarks/benchmark.py                     # full corpus, medium threshold
    python benchmarks/benchmark.py --threshold high     # stricter flagging policy
    python benchmarks/benchmark.py --sample 20          # quick smoke run
    python benchmarks/benchmark.py --write              # update results/benchmark-v1.json
    python benchmarks/benchmark.py --check              # fail if results are stale

The published protocol is in ``benchmarks/benchmark-v1.md``. Results are a
fixture-corpus measurement produced by ``qshield.benchmark``; rerunning the
command above on the same QSHIELD version and corpus reproduces them exactly.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from qshield.benchmark import run_benchmark  # noqa: E402

RESULTS = ROOT / "benchmarks" / "results" / "benchmark-v1.json"

# Timing fields are the only nondeterministic part of a run; they are excluded
# from the staleness comparison.
_VOLATILE = {"generated_at", "wall_seconds"}


def _payload(threshold: str) -> dict:
    result = run_benchmark(threshold=threshold)
    return result


def _stable(result: dict) -> dict:
    return {k: v for k, v in result.items() if k not in _VOLATILE}


def _render(result: dict) -> str:
    m = result["metrics"]
    c = m["counts"]
    lines = [
        "=" * 66,
        "QSHIELD open benchmark — corpus v1",
        "=" * 66,
        f"spec         : {result['spec_version']}",
        f"corpus       : {result['corpus_version']} (sha256 {result['corpus_sha256'][:16]}…)",
        f"qshield      : {result['qshield_version']}",
        f"threshold    : {m['threshold']} or above",
        "",
        f"clean        : {c['clean']} circuits   ({c['false_positives']} false positives)",
        f"malicious    : {c['malicious']} circuits   ({c['false_negatives']} missed)",
        "",
        f"TPR          : {m['tpr']:.4f}   ({c['true_positives']}/{c['malicious']})",
        f"FPR          : {m['fpr']:.4f}   ({c['false_positives']}/{c['clean']})",
        f"precision    : {m['precision']:.4f}",
        f"recall       : {m['recall']:.4f}   (label-matched)",
        "",
        "by family:",
    ]
    for family, row in m["by_family"].items():
        lines.append(
            f"  {family}  {row['detected']:>3}/{row['circuits']:<3} {row['recall']:.4f}  {row['description']}"
        )
    if result["misses"]:
        lines += ["", f"missed ({len(result['misses'])}), reported not hidden:"]
        lines += [f"  {row['name']:<28} expected {row['expected']}" for row in result["misses"][:20]]
    if result["false_positives"]:
        lines += ["", f"false positives ({len(result['false_positives'])}):"]
        lines += [f"  {row['name']:<28} {','.join(row['threat_types'])}" for row in result["false_positives"][:20]]
    lines += [
        "",
        "Fixture-corpus measurement on the bundled corpus. Rerun to reproduce.",
    ]
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threshold", default="medium", choices=["low", "medium", "high", "critical"])
    parser.add_argument("--sample", type=int, default=None)
    parser.add_argument("--write", action="store_true", help="write results/benchmark-v1.json")
    parser.add_argument("--check", action="store_true", help="fail if the stored results are stale")
    parser.add_argument("--json", action="store_true", help="print machine-readable results")
    args = parser.parse_args()

    result = _payload(args.threshold)
    if args.json:
        print(json.dumps(result, indent=2))

    if args.write:
        RESULTS.parent.mkdir(parents=True, exist_ok=True)
        RESULTS.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"wrote {RESULTS.relative_to(ROOT)}")
        return 0

    if args.check:
        if not RESULTS.is_file():
            print(f"missing benchmark results: {RESULTS.relative_to(ROOT)}", file=sys.stderr)
            return 1
        stored = json.loads(RESULTS.read_text(encoding="utf-8"))
        if _stable(stored) == _stable(result):
            print("benchmark results are current")
            return 0
        print(
            "benchmark results are stale — rerun: python benchmarks/benchmark.py --write",
            file=sys.stderr,
        )
        return 1

    if not args.json:
        print(_render(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
