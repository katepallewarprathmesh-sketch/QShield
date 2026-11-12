"""M4.2 — hardware-validation surrogate: device noise-twin evaluation.

Runs what the M4.2 acceptance criteria ask of real quantum hardware against
*digital twins* of three cloud backends, because no hardware credentials are
available (the user confirmed none exist). Results are synthetic evidence,
NOT hardware validation; the M4.2 acceptance criterion "Validated on IBM
Quantum, IonQ, and Rigetti hardware" is NOT met and is marked as such in the
spec.

What this measures
------------------
1. False-positive rate of QSHIELD's runtime result validation
   (``qshield.runtime.validation``) under realistic device noise, at several
   shot counts, comparing
   (a) ideal-Born validation — counts vs exact ideal probabilities;
   (b) twin-Born validation — counts vs exact frozen noise-twin probabilities.
2. Detection rate of the same check against delta-rigged backends (M2.2
   mixture model: fraction δ of shots answers with the least-probable
   outcome, the canonical stealthy backdoor).
3. A calibrated significance threshold per twin (smallest grid alpha whose
   empirical FPR ≤ 5 %), which is the honest "noise-aware detection
   threshold" deliverable.

Honesty notes
-------------
- Twins are illustrative: depolarizing 1q/2q gate error + symmetric readout
  bit-flip, parameters are order-of-magnitude medians published for current
  devices. They include NO T1/T2 relaxation, NO crosstalk, NO leakage, NO
  drift, NO correlated errors. Real hardware will differ; the readout-only
  confusion is applied analytically after the density-matrix evolution.
- Device-noise twins are not "honest twins with same model for FPR" in the
  B2 sense — twin-Born validation here uses the *true* noise model (oracle
  calibration). That is the calibration ceiling: real deployments must
  estimate the noise model from device tomography/benchmarks, which degrades
  to something between ideal and twin validation. Ideal validation is the
  no-calibration floor. Reported numbers bracket the achievable range.
- alpha grid is discrete; "calibrated alpha" is the smallest grid value meeting
  the target, not a continuous optimum.
- Bit order: QSHIELD uses MSB keys; Aer counts keys are already big-endian
  clbit strings (leftmost = highest clbit), so with the i -> n-1-i qubit
  remap they coincide with our MSB keys and are NOT reversed (a reversal
  permutation would corrupt asymmetric circuits; it cancels only in
  sample-vs-sample comparisons).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import numpy as np

from qshield.core.parsers.qasm_parser import parse_qasm
from qshield.dynamic.statistical_tests import chi_squared_test
from qshield.runtime.validation import ideal_probabilities

# ---------------------------------------------------------------------------
# Benign reference workloads (full measurement, m == n). Small by design:
# density-matrix exactness caps at ~8 qubits on commodity RAM.
# ---------------------------------------------------------------------------

BELL = "OPENQASM 2.0;\nqreg q[2];\ncreg c[2];\nh q[0];\ncx q[0], q[1];\nmeasure q -> c;\n"
GHZ3 = ("OPENQASM 2.0;\nqreg q[3];\ncreg c[3];\nh q[0];\ncx q[0], q[1];\ncx q[1], q[2];\n"
        "measure q -> c;\n")
GHZ4 = ("OPENQASM 2.0;\nqreg q[4];\ncreg c[4];\nh q[0];\ncx q[0], q[1];\ncx q[1], q[2];"
        "\ncx q[2], q[3];\nmeasure q -> c;\n")
ROT = ("OPENQASM 2.0;\nqreg q[2];\ncreg c[2];\nh q[0];\nrz(0.7) q[1];\ncx q[0], q[1];\n"
       "ry(0.4) q[1];\ncx q[1], q[0];\nmeasure q -> c;\n")
CL4 = ("OPENQASM 2.0;\nqreg q[4];\ncreg c[4];\nx q[0];\nh q[1];\ncx q[1], q[2];\n"
       "cz q[2], q[3];\ncx q[0], q[3];\nh q[2];\nmeasure q -> c;\n")
HEIS = ("OPENQASM 2.0;\nqreg q[3];\ncreg c[3];\nh q[0];\ncx q[0], q[1];\ncx q[1], q[2];\n"
        "rz(0.3) q[0];\nh q[1];\ncx q[1], q[2];\nmeasure q -> c;\n")

BENIGN: list[tuple[str, str]] = [
    ("bell", BELL),
    ("ghz3", GHZ3),
    ("ghz4", GHZ4),
    ("rot2", ROT),
    ("cliff4", CL4),
    ("heisenberg3", HEIS),
]

# Illustrative twins (NOT live calibration snapshots).
TWINS: dict[str, dict[str, Any]] = {
    "ibm-twin": {"p1": 5e-4, "p2": 7e-3, "readout": 1.5e-2,
                 "note": "illustrative of current IBM superconducting medians; no T1/T2, crosstalk or leakage"},
    "ionq-twin": {"p1": 1e-4, "p2": 3e-3, "readout": 1e-2,
                  "note": "illustrative of current trapped-ion medians; all-to-all ignored, no scattering"},
    "rigetti-twin": {"p1": 2e-3, "p2": 1.5e-2, "readout": 3e-2,
                     "note": "illustrative of current superconducting medians; no parametric-gate crosstalk"},
}

ALPHA_GRID = (0.001, 0.01, 0.05, 0.1)
SHOT_LEVELS = (1024, 4096, 16384)
ATTACK_DELTAS = (0.05, 0.1, 0.2)
ATTACK_SHOTS = (1024, 4096)


@dataclass
class TwinSpec:
    name: str
    p1: float
    p2: float
    readout: float
    note: str


# ---------------------------------------------------------------------------
# Twin machinery
# ---------------------------------------------------------------------------

def _build_qiskit(ir):
    from qiskit import QuantumCircuit

    from qshield.dynamic.differential_tester import _apply_qiskit_gate

    n = ir.num_qubits
    qc = QuantumCircuit(n)
    for gate in ir.gates:
        qs = [n - 1 - q for q in gate.qubits]
        _apply_qiskit_gate(qc, gate, qs)
    return qc


def _noise_model(twin: TwinSpec):
    from qiskit_aer.noise import NoiseModel, ReadoutError, depolarizing_error

    nm = NoiseModel()
    nm.add_all_qubit_quantum_error(depolarizing_error(twin.p1, 1),
                                   ["h", "x", "y", "z", "s", "sdg", "t", "tdg", "rx", "ry", "rz"])
    nm.add_all_qubit_quantum_error(depolarizing_error(twin.p2, 2), ["cx", "cz", "swap"])
    if twin.readout > 0:
        nm.add_all_qubit_readout_error(ReadoutError([[1 - twin.readout, twin.readout],
                                                     [twin.readout, 1 - twin.readout]]))
    return nm


def exact_born_probs(ir, twin: TwinSpec) -> dict[str, float] | None:
    """Exact noisy Born distribution over clbit strings (MSB keys), incl. readout confusion."""
    try:
        from qiskit_aer import AerSimulator
    except ImportError:
        return None
    qc = _build_qiskit(ir)
    nm = _noise_model(twin)
    qc.save_density_matrix()
    rho = AerSimulator(method="density_matrix", noise_model=nm).run(qc).result().data()["density_matrix"]
    diag = np.real(np.asarray(rho, dtype=complex)).reshape(1 << ir.num_qubits, 1 << ir.num_qubits).diagonal()

    # marginalise full basis onto the measured clbits (pre-readout distribution)
    n = ir.num_qubits
    num_clbits = int(ir.num_classical_bits)
    pre: dict[str, float] = {}
    for basis, p in enumerate(diag):
        if p <= 0.0:
            continue
        chars = ["0"] * num_clbits
        for qubit, clbit in ir.measurements:
            if clbit >= num_clbits:
                return None
            chars[clbit] = str((basis >> (n - 1 - qubit)) & 1)
        key = "".join(chars)
        pre[key] = pre.get(key, 0.0) + float(p)

    # apply symmetric-flip readout confusion analytically — every 2^m outcome
    # string receives leaked mass, not just the pre-readout support
    eps = twin.readout
    if eps <= 0.0:
        return pre
    m = num_clbits
    all_keys = [format(i, f"0{m}b") for i in range(1 << m)]

    def confuse(y: str, x: str) -> float:
        factor = 1.0
        for a, b in zip(y, x, strict=True):
            factor *= eps if a != b else (1 - eps)
        return factor

    out: dict[str, float] = {}
    for y in all_keys:
        acc = 0.0
        for x, p in pre.items():
            c = confuse(y, x)
            if c:
                acc += p * c
        if acc > 0.0:
            out[y] = acc
    return out


def sample_counts(ir, twin: TwinSpec, shots: int, seed: int) -> dict[str, int]:
    """Sample counts under the twin (MSB keys)."""
    from qiskit_aer import AerSimulator

    qc = _build_qiskit(ir)
    nm = _noise_model(twin)
    qc.measure_all()
    job = AerSimulator(noise_model=nm).run(qc, shots=shots, seed_simulator=seed)
    raw = job.result().get_counts()
    # Aer counts keys are big-endian clbit strings (leftmost = highest clbit);
    # with our i -> n-1-i qubit remap the leftmost char is already our
    # qubit-0 MSB key — do NOT reverse.
    return {k: int(v) for k, v in raw.items()}


def rigged_counts(ir, twin: TwinSpec, shots: int, delta: float, seed: int) -> dict[str, int]:
    """M2.2 mixture model: (1-delta) honest noisy shots + delta shots of the rig outcome."""
    twin_probs = exact_born_probs(ir, twin)
    if twin_probs is None:
        return {}
    rig = min(twin_probs, key=lambda k: twin_probs[k])
    honest = round(shots * (1 - delta))
    counts = sample_counts(ir, twin, honest, seed=seed)
    counts[rig] = counts.get(rig, 0) + (shots - honest)
    return counts


def _p_ideal(ir, counts) -> float | None:
    from qshield.runtime.validation import validate_counts

    verdict = validate_counts(ir, counts, max_qubits=12, significance=0.0)
    return verdict.p_value


def _p_twin(counts, twin_probs) -> float | None:
    try:
        _, p = chi_squared_test(counts, twin_probs)
    except ValueError:
        return None
    return float(p)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def run_twin(name: str, spec: dict, *, reps: int, seed_base: int,
             results: dict) -> None:
    twin = TwinSpec(name=name, **spec)
    twin_probs = {}
    irs = {}
    for cname, qasm in BENIGN:
        ir = parse_qasm(qasm)
        irs[cname] = ir
        twin_probs[cname] = exact_born_probs(ir, twin)

    clean: dict[str, dict[str, list[float | None]]] = {m: {str(s): [] for s in SHOT_LEVELS} for m in ("ideal", "twin")}
    attack: dict[str, dict[str, dict[str, list[float | None]]]] = {
        m: {str(d): {str(s): [] for s in ATTACK_SHOTS} for d in ATTACK_DELTAS} for m in ("ideal", "twin")
    }

    for ci, (cname, _) in enumerate(BENIGN):
        ir = irs[cname]
        tp = twin_probs[cname]
        if tp is None:
            results["warnings"].append(f"{name}/{cname}: twin probabilities unavailable (qiskit missing?)")
            continue
        for shots in SHOT_LEVELS:
            for rep in range(reps):
                counts = sample_counts(ir, twin, shots, seed=seed_base + 100_000 * ci + 1_000 * SHOT_LEVELS.index(shots) + rep)
                clean["ideal"][str(shots)].append(_p_ideal(ir, counts))
                clean["twin"][str(shots)].append(_p_twin(counts, tp))
        for shots in ATTACK_SHOTS:
            for delta in ATTACK_DELTAS:
                for rep in range(reps):
                    counts = rigged_counts(ir, twin, shots, delta,
                                           seed=seed_base + 900_000 + 100_000 * ci + 10_000 * ATTACK_DELTAS.index(delta) + 1_000 * ATTACK_SHOTS.index(shots) + rep)
                    attack["ideal"][str(delta)][str(shots)].append(_p_ideal(ir, counts))
                    attack["twin"][str(delta)][str(shots)].append(_p_twin(counts, tp))

    def fpr(pvals, alpha):
        flags = [p for p in pvals if p is not None and p < alpha]
        return len(flags) / max(len(pvals), 1)

    def tpr(pvals, alpha):
        return fpr(pvals, alpha)

    for method in ("ideal", "twin"):
        for shots in SHOT_LEVELS:
            pv = clean[method][str(shots)]
            results["fpr"][name][method][str(shots)] = {
                str(a): fpr(pv, a) for a in ALPHA_GRID
            } | {"n": len(pv), "p_values": pv}
        for delta in ATTACK_DELTAS:
            for shots in ATTACK_SHOTS:
                pv = attack[method][str(delta)][str(shots)]
                results["tpr"][name][method][str(delta)][str(shots)] = {
                    str(a): tpr(pv, a) for a in ALPHA_GRID
                } | {"n": len(pv), "p_values": pv}

    # calibrated alpha: smallest grid alpha with empirical FPR <= 5 % (per shot level)
    for method in ("ideal", "twin"):
        for shots in SHOT_LEVELS:
            achieved = None
            for a in ALPHA_GRID:
                if fpr(clean[method][str(shots)], a) <= 0.05:
                    achieved = a
                    break
            results["calibrated_alpha"][name][method][str(shots)] = achieved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reps", type=int, default=25)
    parser.add_argument("--seed", type=int, default=20261112)
    parser.add_argument("--out", type=Path, default=Path("benchmarks/hardware_validation_results.json"))
    parser.add_argument("--mode", choices=["twin", "hardware"], default="twin")
    parser.add_argument("--self-check", action="store_true",
                        help="Verify exact_born_probs against ideal_probabilities at zero noise")
    args = parser.parse_args()

    if args.mode == "hardware":
        print("M4.2 hardware mode requires physical/cloud device access, which this")
        print("environment does not have (user confirmed no credentials).")
        print("To complete M4.2 on real hardware, install provider extras and run the")
        print("same protocol with Qiskit Runtime (IBM), qiskit-ionq, or AWS Braket")
        print("(Rigetti) backends, then record results in this file's output schema.")
        print("See docs/case_studies/quantum_cloud_audit.md § 'Completing on real hardware'.")
        return 77

    if args.self_check:
        # zero-noise twin must reproduce the ideal Born distribution exactly
        zero = TwinSpec(name="zero", p1=0.0, p2=0.0, readout=0.0, note="self-check")
        for cname, qasm in BENIGN:
            ir = parse_qasm(qasm)
            twin = exact_born_probs(ir, zero)
            ideal = ideal_probabilities(ir)
            assert twin is not None and ideal is not None
            keys = set(twin) | set(ideal)
            max_dev = max(abs(twin.get(k, 0.0) - ideal.get(k, 0.0)) for k in keys)
            assert max_dev < 1e-9, f"{cname}: twin/ideal divergence {max_dev}"
        print("self-check OK: zero-noise twin reproduces ideal Born distribution (max dev < 1e-9)")
        return 0

    t0 = time.time()
    results: dict[str, Any] = {
        "meta": {
            "date": "2026-11-12",
            "mode": "twin",
            "reps": args.reps,
            "seed": args.seed,
            "shot_levels": list(SHOT_LEVELS),
            "attack_deltas": list(ATTACK_DELTAS),
            "attack_shots": list(ATTACK_SHOTS),
            "alpha_grid": list(ALPHA_GRID),
            "circuits": [c for c, _ in BENIGN],
            "honesty": ("synthetic digital-twin evaluation; NOT real-hardware validation; "
                        "M4.2 acceptance criterion 'Validated on IBM Quantum, IonQ, and Rigetti "
                        "hardware' is NOT met. Twins ignore T1/T2, crosstalk, leakage, drift, "
                        "and correlated errors. Twin-Born validation uses the true noise model "
                        "(oracle calibration) — a ceiling, not a floor."),
        },
        "twins": TWINS,
        "warnings": [],
        "fpr": {name: {"ideal": {}, "twin": {}} for name in TWINS},
        "tpr": {name: {"ideal": {str(d): {} for d in ATTACK_DELTAS},
                       "twin": {str(d): {} for d in ATTACK_DELTAS}} for name in TWINS},
        "calibrated_alpha": {name: {"ideal": {}, "twin": {}} for name in TWINS},
    }

    seed_base = args.seed
    for ti, (name, spec) in enumerate(TWINS.items()):
        print(f"[twin] {name} (p1={spec['p1']}, p2={spec['p2']}, readout={spec['readout']})")
        run_twin(name, spec, reps=args.reps, seed_base=seed_base + 10_000_000 * ti, results=results)

    results["wall_time_seconds"] = round(time.time() - t0, 1)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=1), encoding="utf-8")

    print(f"\nwrote {args.out}  ({results['wall_time_seconds']}s)\n")
    hdr = f"{'twin':<12}{'method':<7}" + "".join(f"FPR@{a:<7}" for a in ALPHA_GRID) + "  shots"
    print(hdr)
    for name in TWINS:
        for method in ("ideal", "twin"):
            for shots in SHOT_LEVELS:
                row = results["fpr"][name][method][str(shots)]
                line = f"{name:<12}{method:<7}" + "".join(f"{row[str(a)]:<10.3f}" for a in ALPHA_GRID) + f"  {shots}"
                print(line)
    print("\ncalibrated alpha (smallest grid alpha with FPR<=0.05):")
    for name in TWINS:
        for method in ("ideal", "twin"):
            row = results["calibrated_alpha"][name][method]
            print(f"  {name:<12}{method:<7}" + "  ".join(f"{s}:{a}" for s, a in row.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
