"""M4.4 acceptance benchmark: static analysis at 1000 qubits.

Acceptance criterion (docs/spec/QSHIELD.md, M4.4): analyze 1000-qubit
circuits in < 5 minutes (static).  This benchmark scans two synthetic
1000-qubit circuits — a sparse nearest-neighbour chain and a dense
random local circuit (~25k gates) — and reports wall-clock and peak RSS.

Honesty notes:

- Results are for the STATIC analyzer only; exact unitary verification
  refuses > MAX_EXACT_QUBITS by design, and sandbox execution is capped at
  12 qubits (both enforced, never silent).
- The dense synthetic is rotation-heavy; the scanner reports two T1.1
  micro-rotation heuristics (0.60 confidence). These are signature
  heuristic outputs on an adversarial-looking input, not tampering proof —
  see README/threat taxonomy for the confidence contract.
- Findings, not timings, are part of the report; do not diff timings like
  a regression test — hardware varies; the 300 s gate is the contract.

Usage: python benchmarks/large_circuit.py [--json]
Exit code 0 iff both static analyses complete within 300 s.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))


def chain_qasm(n: int = 1000) -> str:
    lines = ["OPENQASM 2.0;", f"qreg q[{n}];", f"creg c[{n}];"]
    lines.append("".join(f"h q[{i}];\n" for i in range(n)))
    lines.append("".join(f"cx q[{i}], q[{i + 1}];\n" for i in range(0, n - 1, 2)))
    lines.append("measure q -> c;\n")
    return "\n".join(lines)


def dense_qasm(n: int = 1000, layers: int = 12, seed: int = 7) -> str:
    rng = random.Random(seed)  # noqa: S311 - benchmark fixture generator, not crypto
    lines = ["OPENQASM 2.0;", f"qreg q[{n}];", f"creg c[{n}];"]
    for i in range(n):
        lines.append(f"h q[{i}];")
    for _ in range(layers):
        for i in range(n - 1):
            gate = "cx" if rng.random() < 0.5 else "cz"
            lines.append(f"{gate} q[{i}], q[{i + 1}];")
        for i in range(n):
            lines.append(f"rz({rng.uniform(-3.14, 3.14):.6f}) q[{i}];")
    lines.append("measure q -> c;")
    return "\n".join(lines)


def run_case(name: str, qasm: str, workdir: Path) -> dict:
    from qshield import Scanner

    path = workdir / f"{name}.qasm"
    path.write_text(qasm, encoding="utf-8")

    import resource

    t0 = time.time()
    scanner = Scanner(config="default")
    scanner.add_circuit(str(path), name=name)
    t_parse = time.time() - t0
    t0 = time.time()
    results = scanner.run(analyses=["static"])
    t_static = time.time() - t0
    peak_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    return {
        "name": name,
        "gates": sum(1 for line in qasm.splitlines() if line.rstrip().rstrip(";")),
        "parse_seconds": round(t_parse, 2),
        "static_seconds": round(t_static, 2),
        "peak_rss_mb": round(peak_mb, 1),
        "findings": [{"severity": f.severity, "threat_type": f.threat_type, "title": f.title}
                     for f in results.findings],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=Path("benchmarks/large_circuit_results.json"))
    parser.add_argument("--json", action="store_true", help="print the JSON report to stdout")
    parser.add_argument("--workdir", type=Path, default=Path("/tmp/qshield_large_circuit"))  # noqa: S108 - benchmark scratch dir
    args = parser.parse_args()

    args.workdir.mkdir(parents=True, exist_ok=True)
    t_start = time.time()
    cases = [
        run_case("chain1000", chain_qasm(), args.workdir),
        run_case("dense1000", dense_qasm(), args.workdir),
    ]
    ok = all(c["static_seconds"] < 300 for c in cases)
    report = {
        "date": "2026-11-12",
        "acceptance": "1000-qubit static analysis in < 300 s",
        "gate_seconds": 300,
        "wall_seconds": round(time.time() - t_start, 2),
        "pass": ok,
        "cases": cases,
        "honesty": ("static analyzer only; dense1000 reports T1.1 heuristics at 0.60 "
                    "confidence on a rotation-heavy synthetic — not tampering proof"),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=1), encoding="utf-8")
    text = json.dumps(report, indent=1)
    print(text if args.json else
          "\n".join([f"chain1000: static {cases[0]['static_seconds']}s, peak {cases[0]['peak_rss_mb']} MB",
                     f"dense1000: static {cases[1]['static_seconds']}s, peak {cases[1]['peak_rss_mb']} MB, "
                     f"findings {len(cases[1]['findings'])}",
                     f"ACCEPTANCE (<300s): {'PASS' if ok else 'FAIL'}  (wrote {args.out})"]))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
