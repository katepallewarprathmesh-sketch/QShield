"""Dynamic-detection benchmark (spec M2.2 acceptance criteria).

Simulates the *result-manipulation* threat: a compromised backend that
biases its outcome distribution.  Trusted reference is the ideal numpy
statevector (qshield SandboxExecutor); the untrusted backend is modelled
as either an honest noisy twin (Aer depolarizing noise) or a trojaned
sampler that mixes in a rigged outcome.

Scenarios measured (shots=10_000):
  A. ideal vs ideal            — FPR on two honest ideal backends
  B1. ideal vs Aer noise (depolarizing eps in {0.001, 0.01, 0.05})
      — informational: at 10k shots honest noise IS detectable as drift;
      not an FPR scenario (a true difference is a true difference)
  B2. Aer twin (eps, noise type) vs Aer twin (same model, different seed)
      for depolarizing AND amplitude damping at eps in {0.001, 0.01, 0.05}
      — FPR "across noise models", the M2.2 criterion
  C. ideal vs trojaned         — rigging mixture delta in {0.05..0.3}; TPR
  D. noisy Aer twin vs noisy Aer + trojan (same noise model) — can the
     trojan hide under honest noise? (informational)

Exit code 0 if: TPR(delta >= 0.2) >= 0.90 and FPR(A) < 0.05 and
FPR(B2 across all noise models) < 0.05; else 1.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from qshield.core.parsers import parse_any  # noqa: E402
from qshield.dynamic.sandbox_executor import SandboxExecutor  # noqa: E402
from qshield.dynamic.statistical_tests import (  # noqa: E402
    compare_distributions,
    sample_counts_from_probabilities,
)

SHOTS = 10_000
SEEDS = 60
MAX_CIRCUITS = 24

FIXTURES = sorted((ROOT / "tests" / "fixtures" / "clean_circuits").glob("*.qasm"))


def load_unitary_circuits():
    circuits = []
    for path in FIXTURES:
        try:
            ir = parse_any(str(path))
        except Exception as exc:
            print(f"skipping {path.name}: {exc}")
            continue
        if ir.num_qubits <= 4 and 2 <= len(ir.gates) <= 30:
            ir.measurements = []  # compare pre-measurement distributions
            circuits.append(ir)
        if len(circuits) >= MAX_CIRCUITS:
            break
    return circuits


def ideal_probs(ir):
    result = SandboxExecutor().run(ir)
    return result.probabilities


def aer_counts(ir, shots, noise_rate=0.0, noise_type="depolarizing", seed=0):
    """Sample counts from Qiskit Aer, optionally with a noise model."""
    from qiskit import QuantumCircuit
    from qiskit_aer import AerSimulator
    from qiskit_aer.noise import NoiseModel, amplitude_damping_error, depolarizing_error

    from qshield.dynamic.differential_tester import _apply_qiskit_gate

    n = ir.num_qubits
    qc = QuantumCircuit(n)
    for gate in ir.gates:
        qs = [n - 1 - q for q in gate.qubits]
        _apply_qiskit_gate(qc, gate, qs)

    if noise_rate > 0:
        nm = NoiseModel()
        if noise_type == "depolarizing":
            def err(p, nd):
                return depolarizing_error(p, nd)
        elif noise_type == "amplitude_damping":
            def err(p, nd):
                one = amplitude_damping_error(min(p, 1.0))
                return one if nd == 1 else one.tensor(amplitude_damping_error(min(p, 1.0)))
        else:
            raise ValueError(f"unknown noise_type {noise_type!r}")
        p1, p2 = noise_rate, noise_rate * 2
        nm.add_all_qubit_quantum_error(err(p1, 1), ["h", "x", "y", "z", "s", "t", "rx", "ry", "rz"])
        nm.add_all_qubit_quantum_error(err(p2, 2), ["cx", "cz", "swap"])
        qc.measure_all()
        sim = AerSimulator(noise_model=nm)
    else:
        qc.measure_all()
        sim = AerSimulator()
    job = sim.run(qc, shots=shots, seed_simulator=seed)
    raw = job.result().get_counts()
    # little-endian -> our MSB bitstrings
    return {k[::-1]: int(v) for k, v in raw.items()}


def trojan_counts(probs, shots, delta, seed, rig=None):
    """Mixture model of result rigging: with probability ``delta`` the backend
    answers with a fixed rigged outcome (default: all-ones, the canonical
    "the answer is always A" backdoor), otherwise it samples honestly."""
    rng = np.random.default_rng(seed)
    outcomes = sorted(probs)
    if rig is None:
        # least-probable outcome: the rig outcome honest sampling essentially
        # never produces — the canonical stealthy-but-visible backdoor
        rig = min(outcomes, key=lambda o: probs[o])
    honest_shots = round(shots * (1 - delta))
    out = sample_counts_from_probabilities(probs, honest_shots, rng=rng)
    out[rig] = out.get(rig, 0) + (shots - honest_shots)
    return out


def rate(flags):
    return sum(flags) / len(flags) if flags else 0.0


def main():
    circuits = load_unitary_circuits()
    print(f"loaded {len(circuits)} unitary circuits (<=4 qubits, <=30 gates)\n")

    report = {"shots": SHOTS, "seeds": SEEDS, "circuits": len(circuits), "scenarios": {}}

    # pre-compute ideal probabilities once per circuit
    ideal = {id(c): ideal_probs(c) for c in circuits}

    # ---- Scenario A: ideal vs ideal (FPR) -----------------------------
    flags = []
    for ir in circuits:
        p = ideal[id(ir)]
        for seed in range(SEEDS):
            a = sample_counts_from_probabilities(p, SHOTS, rng=np.random.default_rng(10_000 + seed))
            b = sample_counts_from_probabilities(p, SHOTS, rng=np.random.default_rng(20_000 + seed))
            flags.append(compare_distributions(a, b).suspicious)
    report["scenarios"]["A_ideal_vs_ideal_fpr"] = rate(flags)
    print(f"A  ideal vs ideal        FPR = {rate(flags):.3f}  ({len(flags)} comparisons)")

    # ---- Scenario B1: ideal vs Aer noise (informational drift detection)
    for eps in (0.001, 0.01, 0.05):
        flags = []
        for ir in circuits:
            p = ideal[id(ir)]
            for seed in range(5):  # Aer sampling is the expensive part
                ideal_counts = sample_counts_from_probabilities(p, SHOTS, rng=np.random.default_rng(30_000 + seed))
                noisy = aer_counts(ir, SHOTS, noise_rate=eps, noise_type="depolarizing", seed=seed)
                flags.append(compare_distributions(ideal_counts, noisy).suspicious)
        report["scenarios"][f"B1_ideal_vs_noise_{eps}_flag_rate"] = rate(flags)
        print(f"B1 ideal vs Aer depolarizing eps={eps:<5} flag rate = {rate(flags):.3f}  (n={len(flags)})")

    # ---- Scenario B2: Aer twin vs Aer twin (M2.2 FPR across noise models)
    b2_all = []
    for noise_type in ("depolarizing", "amplitude_damping"):
        for eps in (0.001, 0.01, 0.05):
            flags = []
            for ir in circuits:
                for seed in range(5):
                    a = aer_counts(ir, SHOTS, noise_rate=eps, noise_type=noise_type, seed=100 + seed)
                    b = aer_counts(ir, SHOTS, noise_rate=eps, noise_type=noise_type, seed=200 + seed)
                    flags.append(compare_distributions(a, b).suspicious)
            report["scenarios"][f"B2_twins_{noise_type}_{eps}_fpr"] = rate(flags)
            b2_all.append(rate(flags))
            print(f"B2 Aer twins {noise_type:<18} eps={eps:<5} FPR = {rate(flags):.3f}  (n={len(flags)})")
    report["scenarios"]["B2_worst_fpr_across_noise_models"] = max(b2_all)

    # ---- Scenario C: ideal vs trojaned sampler (TPR) -------------------
    for delta in (0.05, 0.1, 0.2, 0.3):
        flags = []
        for ir in circuits:
            p = ideal[id(ir)]
            honest = sample_counts_from_probabilities(p, SHOTS, rng=np.random.default_rng(40_000))
            for seed in range(10):
                rigged = trojan_counts(p, SHOTS, delta, seed=50_000 + seed)
                flags.append(compare_distributions(honest, rigged).suspicious)
        report["scenarios"][f"C_trojan_delta_{delta}_tpr"] = rate(flags)
        print(f"C  ideal vs trojan δ={delta:<4} TPR = {rate(flags):.3f}  (n={len(flags)})")

    # ---- Scenario D: trojan under honest noise (informational) ---------
    flags = []
    for ir in circuits:
        p = ideal[id(ir)]
        for seed in range(5):
            noisy = aer_counts(ir, SHOTS, noise_rate=0.01, noise_type="depolarizing", seed=300 + seed)
            rigged = trojan_counts(p, SHOTS, 0.2, seed=60_000 + seed)
            flags.append(
                compare_distributions(
                    noisy,
                    rigged,
                    tv_threshold=0.1 + 2 * 0.01 * len(ir.gates),
                    js_threshold=0.05 + 1.5 * 0.01 * len(ir.gates),
                    noise_aware=True,
                ).suspicious
            )
    report["scenarios"]["D_trojan_under_noise_tpr_noise_aware"] = rate(flags)
    print(f"D  trojan δ=0.2 vs noisy(1%) TPR (noise-aware) = {rate(flags):.3f}  (n={len(flags)})")

    # ---- Verdicts -------------------------------------------------------
    fpr_a = report["scenarios"]["A_ideal_vs_ideal_fpr"]
    fpr_b2 = report["scenarios"]["B2_worst_fpr_across_noise_models"]
    tpr_hi = min(report["scenarios"]["C_trojan_delta_0.2_tpr"],
                 report["scenarios"]["C_trojan_delta_0.3_tpr"])
    ok = tpr_hi >= 0.90 and fpr_a < 0.05 and fpr_b2 < 0.05
    report["verdict"] = {
        "tpr_min_delta_ge_0.2": tpr_hi,
        "fpr_ideal": fpr_a,
        "fpr_aer_twins_worst_across_noise_models": fpr_b2,
        "pass": ok,
    }
    print()
    print("=" * 64)
    print(f"TPR (δ>=0.2)                : {tpr_hi:.3f}   (target >= 0.90)")
    print(f"FPR ideal                   : {fpr_a:.3f}   (target < 0.05)")
    print(f"FPR Aer twins (noise models): {fpr_b2:.3f}   (target < 0.05)")
    print(f"OVERALL                     : {'PASS' if ok else 'FAIL'}")
    print("=" * 64)

    out = ROOT / "benchmarks" / "dynamic_results.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(f"results -> {out}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
