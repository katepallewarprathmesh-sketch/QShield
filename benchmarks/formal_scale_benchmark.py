"""ZX-calculus scalability benchmark (spec M3.1, Phase 3).

Demonstrates the "100+ qubits" deliverable honestly: randomly generated
Clifford circuits at 20/50/100/150 qubits are checked for equivalence
against (a) themselves, (b) themselves plus camouflage identity-pair
insertions (s/sdg, t/tdg, h/h, cx/cx), and (c) themselves with one gate
substituted mid-circuit (a "trojaned" variant).

Measured outcomes per configuration:
  * proof rate   — fraction of pairs *proven* equivalent via ZX reduction
  * verdict      — method used (zx_calculus / tensor_exact / undecidable)
  * wall time    — seconds per check

The tampered case at >10 qubits must come back ``undecidable`` (exact
tensors are infeasible there) — that is the designed, honest answer, not a
failure.  Small circuits where full_reduce is inconclusive fall back to an
exact tensor comparison (sound).

Exit code 0 if: 100- and 150-qubit identical pairs are proven equivalent,
and all 100/150-qubit tampered pairs return ``undecidable`` (no false
equivalence verdicts); else 1.
"""

from __future__ import annotations

import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from qshield.core.circuit_ir import CircuitIR, GateNode, GateType
from qshield.formal import zx_equivalence_check
from qshield.formal.zx_calculus import pyzx_available

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "benchmarks" / "formal_results.json"

SIZES = (20, 50, 100, 150)
SEEDS = (42, 7)
GATE_SET = ("h", "s", "x", "z", "cx")


def random_clifford(n: int, depth: int, seed: int) -> CircuitIR:
    rng = random.Random(seed)  # noqa: S311 - deterministic benchmark generation, not crypto
    gates: list[GateNode] = []
    for i in range(depth):
        name = rng.choice(GATE_SET)
        q = rng.sample(range(n), 2) if name == "cx" else [rng.randrange(n)]
        gates.append(GateNode(f"g{i}", name, GateType.STANDARD, q, [], None))
    return CircuitIR(circuit_id="rc", name="rc", num_qubits=n, num_classical_bits=0,
                     gates=gates, measurements=[], ancilla_qubits=[],
                     source_framework="benchmark", source_hash=f"clifford-{n}-{depth}-{seed}",
                     metadata={})


def camouflage(ir: CircuitIR, insertions: int, seed: int) -> CircuitIR:
    """Insert semantics-preserving identity pairs at random positions."""
    rng = random.Random(seed)  # noqa: S311 - deterministic benchmark generation, not crypto
    gates = list(ir.gates)
    for k in range(insertions):
        q = rng.randrange(ir.num_qubits)
        pos = rng.randrange(len(gates) + 1)
        pair = rng.choice([("s", "sdg"), ("t", "tdg"), ("h", "h")])
        if rng.random() < 0.25 and ir.num_qubits >= 2:
            q2 = rng.randrange(ir.num_qubits)
            while q2 == q:
                q2 = rng.randrange(ir.num_qubits)
            g1 = GateNode(f"cam{k}a", "cx", GateType.STANDARD, [q, q2], [], None)
            g2 = GateNode(f"cam{k}b", "cx", GateType.STANDARD, [q, q2], [], None)
        else:
            g1 = GateNode(f"cam{k}a", pair[0], GateType.STANDARD, [q], [], None)
            g2 = GateNode(f"cam{k}b", pair[1], GateType.STANDARD, [q], [], None)
        gates[pos:pos] = [g1, g2]
    return CircuitIR(circuit_id="cam", name="cam", num_qubits=ir.num_qubits, num_classical_bits=0,
                     gates=gates, measurements=[], ancilla_qubits=[],
                     source_framework="benchmark", source_hash=f"cam-{ir.source_hash}",
                     metadata={})


def tamper(ir: CircuitIR) -> CircuitIR:
    """Substitute one mid-circuit gate with a different one (trojan model)."""
    gates = list(ir.gates)
    mid = len(gates) // 2
    g = gates[mid]
    replacement = GateNode(g.gate_id, "h" if g.gate_name != "h" else "x",
                           GateType.STANDARD, list(g.qubits), [], None)
    gates[mid] = replacement
    return CircuitIR(circuit_id="tam", name="tam", num_qubits=ir.num_qubits, num_classical_bits=0,
                     gates=gates, measurements=[], ancilla_qubits=[],
                     source_framework="benchmark", source_hash=f"tam-{ir.source_hash}",
                     metadata={})


def check(a: CircuitIR, b: CircuitIR) -> dict:
    t0 = time.perf_counter()
    res = zx_equivalence_check(a, b)
    return {"equivalent": res.equivalent, "method": res.method,
            "seconds": round(time.perf_counter() - t0, 3)}


def main() -> int:
    if not pyzx_available():
        print("pyzx is not installed; pip install 'qshield[formal]'")
        return 2

    report = {"gate_set": list(GATE_SET), "results": []}
    failures: list[str] = []

    for n in SIZES:
        for seed in SEEDS:
            a = random_clifford(n, depth=4 * n, seed=seed)
            b_ident = random_clifford(n, depth=4 * n, seed=seed)
            b_cam = camouflage(a, insertions=n // 2, seed=seed + 1000)
            b_tam = tamper(a)

            r_ident = check(a, b_ident)
            r_cam = check(a, b_cam)
            r_tam = check(a, b_tam)
            row = {"qubits": n, "depth": 4 * n, "seed": seed,
                   "identical": r_ident, "camouflaged": r_cam, "tampered": r_tam}
            report["results"].append(row)
            print(f"n={n:4d} seed={seed:3d} | identical: {r_ident['equivalent']} "
                  f"({r_ident['method']}, {r_ident['seconds']}s) | camouflaged: "
                  f"{r_cam['equivalent']} ({r_cam['method']}, {r_cam['seconds']}s) | "
                  f"tampered: {r_tam['equivalent']} ({r_tam['method']}, {r_tam['seconds']}s)")

            if n >= 100:
                if r_ident["equivalent"] is not True:
                    failures.append(f"n={n} seed={seed}: identical pair not proven equivalent ({r_ident['method']})")
                if r_cam["equivalent"] is not True:
                    failures.append(f"n={n} seed={seed}: camouflaged pair not proven equivalent ({r_cam['method']})")
                if r_tam["equivalent"] is not None:
                    failures.append(f"n={n} seed={seed}: tampered pair returned {r_tam['method']}/{r_tam['equivalent']}, expected undecidable (tensor budget)")

    OUT.write_text(json.dumps(report, indent=2))
    print(f"\nwrote {OUT}")
    if failures:
        print("FAILURES:")
        for f_ in failures:
            print(f"  - {f_}")
        return 1
    print("OK: 100+ qubit Clifford pairs proven equivalent via ZX reduction; "
          "tampered wide circuits correctly report undecidable (exact tensor fallback refused, no false equivalence).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
