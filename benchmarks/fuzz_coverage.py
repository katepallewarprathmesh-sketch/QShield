"""Fuzz the analyzer over the benchmark corpus (informational + crash gate).

For each small clean/malicious fixture, generate mutants with the M2.3
fuzzer and static-scan them.  Reports per-class coverage buckets and a
mutation-evasion rate per starting fixture: the share of mutants whose
findings vanish — a robustness probe for the detector (the lower the
better; a true trojan should not be smuggled past the analyzer by
semantics-breaking mutations).

Exit code 0 if the analyzer does not *crash* on any mutant (the only
hard gate).  Two robustness signals are reported:
  * per-fixture "clean bucket" hits under random (mostly semantics-breaking)
    mutations — expectation: high, mutants rarely keep a trojan the analyzer
    can see is the same trojan; this is NOT the evasion metric
  * camouflage evasion under identity-pair insertion (semantics-preserving):
    the share of mutants where the malicious signature vanishes — the real
    evasion-resistance probe (spec M3.3)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from qshield.core.parsers import parse_any  # noqa: E402
from qshield.dynamic.quantum_fuzzer import CircuitFuzzer  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


def pick(cls_dir: Path, limit: int, max_qubits: int = 4, max_gates: int = 30) -> list[Path]:
    out = []
    for path in sorted(cls_dir.glob("*.qasm")):
        try:
            ir = parse_any(str(path))
        except Exception as exc:
            print(f"skipping {path.name}: {exc}")
            continue
        if ir.num_qubits <= max_qubits and 2 <= len(ir.gates) <= max_gates:
            out.append(path)
        if len(out) >= limit:
            break
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bases", type=int, default=6, help="fixtures per class")
    ap.add_argument("--mutants", type=int, default=24, help="mutants per fixture")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()

    rows = []
    all_crashes: list[tuple[str, str]] = []
    for label, cls in (("clean", FIX / "clean_circuits"), ("malicious", FIX / "malicious_circuits")):
        for path in pick(cls, args.bases):
            ir = parse_any(str(path))  # keep measurements: T2.x rules key on them
            fuzzer = CircuitFuzzer(ir, seed=args.seed, max_mutations_per_mutant=2)
            report = fuzzer.fuzz(iterations=args.mutants)

            # camouflage probe: identity-pair insertion preserves the payload,
            # so any loss of detection is true evasion
            camouflage = None
            cam_row = None
            if label == "malicious":
                ir2 = parse_any(str(path))
                cam = CircuitFuzzer(ir2, seed=args.seed, max_mutations_per_mutant=2,
                                    operators=["identity_pair_insertion"])
                cam_report = cam.fuzz(iterations=args.mutants)
                camouflage = cam_report.clean_bucket_hits / cam_report.num_mutants
                cam_row = {"camouflage_evasion": camouflage}
                all_crashes.extend(cam_report.crashes)

            row = {
                "class": label,
                "fixture": path.stem,
                "mutants": report.num_mutants,
                "crashes": len(report.crashes),
                "clean_bucket_hits": report.clean_bucket_hits,
                "coverage": report.coverage,
                **(cam_row or {}),
            }
            rows.append(row)
            all_crashes.extend(report.crashes)
            cam_s = f"cam-evasion={camouflage:.2f}" if camouflage is not None else "-"
            print(f"{label:9s} {path.stem:34s} coverage={sorted(report.coverage)} {cam_s} crashes={len(report.crashes)}")

    print()
    print("=" * 64)
    print(f"mutants evaluated  : {sum(r['mutants'] for r in rows)}")
    print(f"analyzer crashes   : {len(all_crashes)}  (gate: must be 0)")
    cam = [r["camouflage_evasion"] for r in rows if "camouflage_evasion" in r]
    if cam:
        print(f"camouflage evasion : mean {sum(cam) / len(cam):.3f}  (semantics-preserving; lower is better)")
    print("=" * 64)

    out = ROOT / "benchmarks" / "fuzz_results.json"
    out.write_text(json.dumps({"rows": rows, "crashes": all_crashes}, indent=2, sort_keys=True) + "\n")
    print(f"results -> {out}")
    return 0 if not all_crashes else 1


if __name__ == "__main__":
    sys.exit(main())
