"""GNN anomaly-detector benchmark (spec M3.2, Phase 3).

Stratified 5-fold cross-validation over the labeled fixture corpus
(clean = label 0, malicious = label 1).  Per fold:

1. train the GNN autoencoder on *train-clean* circuits only;
2. calibrate the decision threshold on *train-clean* scores (95th
   percentile) — never on malicious data;
3. measure TPR / FPR / AUROC / AUPRC on the held-out fold;
4. camouflage probe: re-insert 1/2/3 semantics-preserving identity pairs
   into held-out malicious circuits and re-measure detection at the same
   threshold (the M2.3 camouflage family, applied to the learned model).

Notes / honesty:
* the corpus is small (417 fixtures) and largely template-generated, so
  absolute numbers here are a smoke signal for the pipeline, not a claim
  of generalisation to unseen trojan families;
* scores are dataset-dependent — thresholds must be recalibrated per
  deployment corpus, exactly as done per fold here.

Requires torch (pip install 'qshield[ml]'). Exit code 0 on success.
"""

from __future__ import annotations

import argparse
import copy
import json
import random
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import StratifiedKFold, train_test_split

from qshield.core.circuit_ir import GateNode, GateType
from qshield.ml import (
    ClassifierConfig,
    GraphAnomalyDetector,
    GraphGNNClassifier,
    TrainConfig,
    build_vocab,
    load_fixture_dataset,
    torch_available,
)

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "benchmarks" / "ml_results.json"


def camouflage(ir, insertions: int, seed: int):
    """Insert semantics-preserving identity pairs (s/sdg, t/tdg, h/h)."""
    rng = random.Random(seed)  # noqa: S311 - deterministic benchmark, not crypto
    gates = list(ir.gates)
    for k in range(insertions):
        q = rng.randrange(ir.num_qubits)
        pos = rng.randrange(len(gates) + 1)
        pair = rng.choice([("s", "sdg"), ("t", "tdg"), ("h", "h")])
        g1 = GateNode(f"mlcam{k}a", pair[0], GateType.STANDARD, [q], [], None)
        g2 = GateNode(f"mlcam{k}b", pair[1], GateType.STANDARD, [q], [], None)
        gates[pos:pos] = [g1, g2]
    new = copy.copy(ir)
    new.gates = gates
    return new


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--clf-epochs", type=int, default=60)
    parser.add_argument("--hidden", type=int, default=64)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=0)
    args = parser.parse_args()

    if not torch_available():
        print("torch is not installed; pip install 'qshield[ml]'")
        return 2

    items, stats = load_fixture_dataset()
    print(f"loaded {stats.total} fixtures: {stats.clean} clean, "
          f"{stats.malicious} malicious, {len(stats.skipped)} skipped")
    if stats.skipped:
        for name, err in stats.skipped:
            print(f"  skipped {name}: {err}")

    X = list(range(len(items)))
    y = [it.label for it in items]
    skf = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=args.seed)

    fold_reports = []
    for fold, (train_idx, test_idx) in enumerate(skf.split(X, y)):
        train = [items[i] for i in train_idx]
        test = [items[i] for i in test_idx]

        # nested split: fit on sub-train, calibrate the decision threshold
        # on a held-out calibration slice — never on malicious data, and
        # never on the data being calibrated for
        sub_train, calib = train_test_split(train, test_size=0.25,
                                            random_state=args.seed + fold,
                                            stratify=[it.label for it in train])
        calib_clean = [it for it in calib if it.label == 0]
        sub_train_clean = [it for it in sub_train if it.label == 0]

        vocab = build_vocab([it.ir for it in train])
        det = GraphAnomalyDetector(vocab, TrainConfig(epochs=args.epochs, seed=args.seed + fold,
                                                      hidden=args.hidden))
        det.fit([it.ir for it in sub_train_clean])
        threshold = det.calibrate_threshold([it.ir for it in calib_clean], quantile=0.95)

        clf = GraphGNNClassifier(vocab, ClassifierConfig(epochs=args.clf_epochs,
                                                         seed=args.seed + fold,
                                                         hidden=args.hidden))
        clf.fit(sub_train)
        clf_threshold = clf.calibrate_threshold(calib, target_fpr=0.05)

        n_mal = sum(1 for it in test if it.label == 1)
        n_cl = len(test) - n_mal

        def evaluate(score_fn, thr, test=test, n_mal=n_mal, n_cl=n_cl):
            scores, labels, tp, fp = [], [], 0, 0
            for it in test:
                s = score_fn(it.ir)
                scores.append(s)
                labels.append(it.label)
                if s > (thr if thr is not None else 0.5):
                    if it.label == 1:
                        tp += 1
                    else:
                        fp += 1
            tpr = tp / n_mal if n_mal else 0.0
            fpr = fp / n_cl if n_cl else 0.0
            auroc = roc_auc_score(labels, scores)
            auprc = average_precision_score(labels, scores)
            return {"threshold": round(thr, 4) if thr is not None else None,
                    "tpr": round(tpr, 4), "fpr": round(fpr, 4),
                    "auroc": round(float(auroc), 4), "auprc": round(float(auprc), 4)}

        def camouflage_probe(score_fn, thr, test=test, n_mal=n_mal):
            cam = {}
            for k in (1, 2, 3):
                detected = 0
                for it in test:
                    if it.label != 1:
                        continue
                    if score_fn(camouflage(it.ir, k, seed=zlib.crc32(f"{it.name}:{k}".encode()))) > thr:
                        detected += 1
                cam[f"camouflage_{k}"] = round(detected / n_mal, 4) if n_mal else 0.0
            return cam

        ae_eval = evaluate(det.score, threshold)
        ae_cam = camouflage_probe(det.score, threshold)
        gnn_eval = evaluate(clf.score, clf_threshold)
        gnn_cam = camouflage_probe(clf.score, clf_threshold)

        curve = det._train_loss_curve
        fold_reports.append({
            "fold": fold,
            "autoencoder": {**ae_eval, "camouflage_detection": ae_cam},
            "supervised_gnn": {**gnn_eval, "camouflage_detection": gnn_cam},
            "train_loss_first": round(curve[0], 4) if curve else None,
            "train_loss_last": round(curve[-1], 4) if curve else None,
        })
        print(f"fold {fold}: AE TPR={ae_eval['tpr']:.3f} FPR={ae_eval['fpr']:.3f} "
              f"AUROC={ae_eval['auroc']:.3f} | GNN TPR={gnn_eval['tpr']:.3f} "
              f"FPR={gnn_eval['fpr']:.3f} AUROC={gnn_eval['auroc']:.3f} | camouflage GNN={gnn_cam}")

    def mean_block(mode: str) -> dict:
        blocks = [r[mode] for r in fold_reports]
        out = {key: round(sum(b[key] for b in blocks) / len(blocks), 4)
               for key in ("tpr", "fpr", "auroc", "auprc")}
        out["camouflage_detection"] = {
            k: round(sum(b["camouflage_detection"][k] for b in blocks) / len(blocks), 4)
            for k in ("camouflage_1", "camouflage_2", "camouflage_3")}
        return out

    report = {
        "dataset": {"total": stats.total, "clean": stats.clean,
                    "malicious": stats.malicious, "skipped": stats.skipped},
        "config": {"epochs": args.epochs, "clf_epochs": args.clf_epochs,
                   "hidden": args.hidden,
                   "folds": args.folds, "seed": args.seed,
                   "threshold_quantile": 0.95, "supervised_target_fpr": 0.05},
        "folds": fold_reports,
        "mean": {"autoencoder": mean_block("autoencoder"),
                 "supervised_gnn": mean_block("supervised_gnn")},
    }
    OUT.write_text(json.dumps(report, indent=2))
    for mode in ("autoencoder", "supervised_gnn"):
        m = report["mean"][mode]
        print(f"mean[{mode}]: TPR={m['tpr']:.3f} FPR={m['fpr']:.3f} "
              f"AUROC={m['auroc']:.3f} AUPRC={m['auprc']:.3f} "
              f"camouflage={m['camouflage_detection']}")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
