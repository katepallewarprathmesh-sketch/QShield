"""Evasion-resistance benchmark (spec M3.3, acceptance: resist >= 80% of
adversarial evasion attempts).

Red team: the five semantics-preserving attacks in qshield.evasion.attacks
(camouflage, synonyms, rotation_split, dead_code, qubit_relabel), applied
to held-out malicious fixtures.

Blue team, measured per fold (stratified CV):
  1. ``static``   — QSHIELD static analyzer (strict config), single pass over
                    the full corpus (no per-fold training involved)
  2. ``gnn``      — baseline supervised GNN (as in M3.2)
  3. ``gnn_hardened`` — same GNN adversarially trained with augmented
                    attacked copies of every training circuit (labels
                    preserved); calibrated on the same held-out clean slice

Metrics, per attack and overall:
  * detection-under-attack rate (fraction of attacked malicious fixtures
    still flagged) — the "resistance" metric
  * attacked-clean false-positive rate (do the attacks fool the blue team
    into flagging clean circuits?)

``overall_resistance`` = total resisted attacks / total attempts across all
attack classes and folds.  Exit code 0 if the hardened GNN resists >= 80%
overall, else 1 (per spec M3.3 acceptance criterion).

Notes: 3-fold CV is used here (the hardened model trains on ~6x the data);
M3.2's 5-fold numbers remain the reference for accuracy.  torch required.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sklearn.model_selection import StratifiedKFold, train_test_split

from qshield import Scanner
from qshield.evasion import ATTACK_NAMES, apply_attack, train_hardened_classifier
from qshield.ml import (
    ClassifierConfig,
    GraphGNNClassifier,
    build_vocab,
    load_fixture_dataset,
    torch_available,
)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "benchmarks" / "evasion_results.json"

STATIC_ATTACK_KW = {
    "camouflage": {"k": 2},
    "synonyms": {"rate": 0.5},
    "rotation_split": {"rate": 0.5},
    "dead_code": {"depth": 8},
    "qubit_relabel": {},
}


def static_flags(ir) -> bool:
    scanner = Scanner(config="strict")
    scanner.add_circuit(ir, name="attacked")
    findings = scanner.run().findings
    return any(f.severity_rank >= 3 for f in findings)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--folds", type=int, default=3)
    parser.add_argument("--epochs", type=int, default=40, help="baseline GNN epochs")
    parser.add_argument("--hardened-epochs", type=int, default=40)
    parser.add_argument("--hidden", type=int, default=64)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--skip-static", action="store_true")
    parser.add_argument("--static-max-qubits", type=int, default=10,
                        help="resource cap for the static pass; larger fixtures are "
                             "reported as skipped_resource_cap (dense-unitary blow-up)")
    parser.add_argument("--static-only", action="store_true",
                        help="run only the static-scanner pass and merge into the existing report")
    args = parser.parse_args()

    if not torch_available():
        print("torch is not installed; pip install 'qshield[ml]'")
        return 2

    items, stats = load_fixture_dataset()
    print(f"loaded {stats.total} fixtures: {stats.clean} clean, {stats.malicious} malicious")

    # ---------------- static baseline (single pass, no training) ----------
    static_report = {}
    if not args.skip_static or args.static_only:
        cap = args.static_max_qubits
        eligible = [it for it in items if it.ir.num_qubits <= cap]
        n_mal = sum(1 for it in eligible if it.label == 1)
        n_clean = len(eligible) - n_mal
        for atk in ATTACK_NAMES:
            kw = STATIC_ATTACK_KW[atk]
            mal_flagged = sum(static_flags(apply_attack(it.ir, atk, seed=123, **kw))
                              for it in eligible if it.label == 1)
            clean_flagged = sum(static_flags(apply_attack(it.ir, atk, seed=123, **kw))
                                for it in eligible if it.label == 0)
            static_report[atk] = {
                "malicious_detected": mal_flagged,
                "malicious_total": n_mal,
                "clean_flagged": clean_flagged,
                "clean_total": n_clean,
                "skipped_resource_cap": stats.total - len(eligible),
                "max_qubits": cap,
                "detection_under_attack": round(mal_flagged / n_mal, 4) if n_mal else 0.0,
                "attacked_clean_fpr": round(clean_flagged / n_clean, 4) if n_clean else 0.0,
            }
            print(f"static/{atk:14s} detection={static_report[atk]['detection_under_attack']:.3f} "
                  f"clean_fpr={static_report[atk]['attacked_clean_fpr']:.3f} "
                  f"(n={n_mal}+{n_clean}, cap {cap}q)")

        # unattacked reference pass — an attack cannot reduce detection below this
        mal_flagged = sum(static_flags(it.ir) for it in eligible if it.label == 1)
        clean_flagged = sum(static_flags(it.ir) for it in eligible if it.label == 0)
        static_report["unattacked"] = {
            "malicious_detected": mal_flagged,
            "malicious_total": n_mal,
            "clean_flagged": clean_flagged,
            "clean_total": n_clean,
            "detection_under_attack": round(mal_flagged / n_mal, 4) if n_mal else 0.0,
            "attacked_clean_fpr": round(clean_flagged / n_clean, 4) if n_clean else 0.0,
        }
        print(f"static/{'unattacked':14s} detection={static_report['unattacked']['detection_under_attack']:.3f} "
              f"clean_fpr={static_report['unattacked']['attacked_clean_fpr']:.3f}")

    if args.static_only:
        existing = {}
        if OUT.exists():
            try:
                existing = json.loads(OUT.read_text())
            except Exception:
                existing = {}
        report = {
            "dataset": {"total": stats.total, "clean": stats.clean, "malicious": stats.malicious},
            "config": {"folds": None, "epochs": None, "hardened_epochs": None,
                       "hidden": None, "seed": args.seed, "threshold_target_fpr": 0.05},
            "static": static_report,
            "folds": existing.get("folds", []),
            "mean": existing.get("mean", {}),
        }
        OUT.write_text(json.dumps(report, indent=2))
        avg = sum(v["detection_under_attack"] for v in static_report.values()) / max(len(static_report), 1)
        print(f"\nstatic overall detection-under-attack (unweighted mean over classes) = {avg:.3f}")
        print(f"wrote {OUT}")
        return 0

    # ---------------- learned detectors: stratified CV --------------------
    X = list(range(len(items)))
    y = [it.label for it in items]
    skf = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=args.seed)

    blue_names = ("gnn", "gnn_hardened")
    per_fold = []
    totals = {b: {a: [0, 0] for a in ATTACK_NAMES} for b in blue_names}  # [resisted, attempts]
    clean_fpr_acc = {b: {a: [0, 0] for a in ATTACK_NAMES} for b in blue_names}

    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y)):
        train = [items[i] for i in train_idx]
        test = [items[i] for i in test_idx]
        sub_train, calib = train_test_split(train, test_size=0.25,
                                            random_state=args.seed + fold,
                                            stratify=[it.label for it in train])

        vocab = build_vocab([it.ir for it in train])
        gnn = GraphGNNClassifier(vocab, ClassifierConfig(epochs=args.epochs,
                                                         seed=args.seed + fold,
                                                         hidden=args.hidden))
        gnn.fit(sub_train)
        gnn_thr = gnn.calibrate_threshold(calib, target_fpr=0.05)

        print(f"fold {fold}: training hardened model on augmented data...")
        hardened = train_hardened_classifier(sub_train, seed=args.seed + fold,
                                             epochs=args.hardened_epochs,
                                             hidden=args.hidden, latent=32)
        hard_thr = hardened.calibrate_threshold(calib, target_fpr=0.05)

        fold_report = {"fold": fold, "gnn_threshold": round(gnn_thr, 4),
                       "gnn_hardened_threshold": round(hard_thr, 4), "attacks": {}}
        test_mal = [it for it in test if it.label == 1]
        test_clean = [it for it in test if it.label == 0]
        for atk in ATTACK_NAMES:
            kw = STATIC_ATTACK_KW[atk]
            atk_mal = [apply_attack(it.ir, atk, seed=1000 * fold + 7, **kw) for it in test_mal]
            atk_clean = [apply_attack(it.ir, atk, seed=1000 * fold + 8, **kw) for it in test_clean]
            per_blue = {}
            for blue_name, model, thr in (("gnn", gnn, gnn_thr),
                                          ("gnn_hardened", hardened, hard_thr)):
                detected = sum(model.score(a) > thr for a in atk_mal)
                false_pos = sum(model.score(a) > thr for a in atk_clean)
                rate = detected / len(atk_mal) if atk_mal else 0.0
                fpr = false_pos / len(atk_clean) if atk_clean else 0.0
                per_blue[blue_name] = {"detection_under_attack": round(rate, 4),
                                       "attacked_clean_fpr": round(fpr, 4),
                                       "resisted": detected, "attempts": len(atk_mal)}
                totals[blue_name][atk][0] += detected
                totals[blue_name][atk][1] += len(atk_mal)
                clean_fpr_acc[blue_name][atk][0] += false_pos
                clean_fpr_acc[blue_name][atk][1] += len(atk_clean)
            fold_report["attacks"][atk] = per_blue
            print(f"fold {fold} / {atk:14s} "
                  f"gnn={per_blue['gnn']['detection_under_attack']:.3f} "
                  f"hardened={per_blue['gnn_hardened']['detection_under_attack']:.3f} "
                  f"(fpr {per_blue['gnn']['attacked_clean_fpr']:.3f}/{per_blue['gnn_hardened']['attacked_clean_fpr']:.3f})")
        per_fold.append(fold_report)

    def summarize(blue: str) -> dict:
        per_attack = {a: {"detection_under_attack": round(totals[blue][a][0] / totals[blue][a][1], 4),
                          "resisted": totals[blue][a][0], "attempts": totals[blue][a][1],
                          "attacked_clean_fpr": round(clean_fpr_acc[blue][a][0] / max(clean_fpr_acc[blue][a][1], 1), 4)}
                      for a in ATTACK_NAMES}
        tot_res = sum(v["resisted"] for v in per_attack.values())
        tot_att = sum(v["attempts"] for v in per_attack.values())
        return {"per_attack": per_attack,
                "overall_resistance": round(tot_res / tot_att, 4) if tot_att else 0.0,
                "resisted": tot_res, "attempts": tot_att}

    if args.skip_static and OUT.exists():
        try:
            prior = json.loads(OUT.read_text()).get("static", {})
            if prior:
                static_report = prior
        except Exception as exc:
            print(f"note: could not reuse prior static block ({exc}); rerun --static-only")
    report = {
        "dataset": {"total": stats.total, "clean": stats.clean, "malicious": stats.malicious},
        "config": {"folds": args.folds, "epochs": args.epochs,
                   "hardened_epochs": args.hardened_epochs, "hidden": args.hidden,
                   "seed": args.seed, "threshold_target_fpr": 0.05},
        "static": static_report,
        "folds": per_fold,
        "mean": {b: summarize(b) for b in blue_names},
    }
    OUT.write_text(json.dumps(report, indent=2))
    print(f"\nwrote {OUT}")
    for blue in blue_names:
        m = report["mean"][blue]
        print(f"{blue:14s} overall resistance = {m['overall_resistance']:.3f} "
              f"({m['resisted']}/{m['attempts']} attempts resisted)")
    hardened_overall = report["mean"]["gnn_hardened"]["overall_resistance"]
    if hardened_overall >= 0.80:
        print("OK: hardened GNN meets the M3.3 acceptance criterion (>= 0.80).")
        return 0
    print(f"MISS: hardened GNN resists {hardened_overall:.3f} < 0.80 — see per-attack breakdown.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
