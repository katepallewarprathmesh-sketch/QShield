"""QSHIELD Phase-1 benchmark evaluation.

Runs the fixture corpus through the scanner and prints a detection-rate
table: true-positive rate on malicious circuits and false-positive rate
on clean circuits (targets from the spec: TPR > 80%, FPR < 10%).

Usage:  python benchmarks/evaluate.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from qshield import Scanner

ROOT = Path(__file__).resolve().parent.parent
CLEAN = sorted((ROOT / "tests/fixtures/clean_circuits").glob("*.qasm"))
MALICIOUS = sorted((ROOT / "tests/fixtures/malicious_circuits").glob("*.qasm"))

EXPECTED = {
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
    # second expansion round
    "h_cancellation_adjacent": "T1.3",
    "cx_cx_separated": "T1.3",
    "micro_rotation_dense": "T1.1",
    "stego_ascii_backdoor": "T2.2",
    "y_before_measure": "T2.3",
    "x_before_measure": "T2.3",
    "y_y_pair_separated": "T1.3",
    "leaf_ancilla_swap": "T2.1",
}


def main() -> int:
    print("=" * 64)
    print("QSHIELD Phase-1 benchmark evaluation")
    print("=" * 64)

    print("\n-- Clean circuits (should be quiet) --")
    clean_fp = 0
    for path in CLEAN:
        scanner = Scanner(config="strict")
        scanner.add_circuit(str(path))
        findings = scanner.run().findings
        high = [f for f in findings if f.severity_rank >= 3]
        status = "CLEAN" if not high else "FLAGGED (FP!)"
        if high:
            clean_fp += 1
        print(f"  {path.stem:<32} {status}  ({len(findings)} low-severity hints)")

    print("\n-- Malicious circuits (should be caught) --")
    hits = 0
    for path in MALICIOUS:
        expected = EXPECTED.get(path.stem)
        scanner = Scanner(config="strict")
        scanner.add_circuit(str(path))
        findings = scanner.run().findings
        threat_types = {f.threat_type for f in findings}
        detected = expected in threat_types if expected else bool(findings)
        hits += bool(detected)
        mark = "DETECT" if detected else "MISS"
        print(f"  {path.stem:<32} {mark}  (expected {expected}, found {sorted(threat_types)})")

    tpr = hits / len(MALICIOUS) if MALICIOUS else 1.0
    fpr = clean_fp / len(CLEAN) if CLEAN else 0.0
    print("\n" + "=" * 64)
    print(f"True positive rate : {hits}/{len(MALICIOUS)} = {tpr:.0%}  (target > 80%)")
    print(f"False positive rate: {clean_fp}/{len(CLEAN)} = {fpr:.0%}  (target < 10%)")
    print("=" * 64)
    return 0 if tpr >= 0.8 and fpr <= 0.1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
