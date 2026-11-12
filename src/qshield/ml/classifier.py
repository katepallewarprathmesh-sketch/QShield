"""Supervised GNN classifier (spec M3.2: "training pipeline on
clean/malicious circuit dataset").

Same wire-graph encoder as the autoencoder, plus a binary head trained
with BCEWithLogitsLoss (pos_weight balancing the classes).  Decision
threshold defaults to 0.5; AUROC/AUPRC are threshold-free and reported
alongside TPR/FPR so the exact operating point is the deployer's choice.

Explainability is leave-one-out (LOO): removing gate *i* changes the
predicted malicious probability by Δᵢ — a model-agnostic, faithful
saliency measure.  O(|circuit|) forward passes; fine for fixtures-sized
circuits.

Requires torch (the ``ml`` extra).
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path

from qshield.core.circuit_ir import CircuitIR
from qshield.ml.graph import build_vocab, circuit_to_graph


@dataclass
class ClassifierConfig:
    epochs: int = 60
    lr: float = 1e-4
    weight_decay: float = 1e-4
    hidden: int = 64
    latent: int = 32
    embed_dim: int = 16
    layers: int = 3
    dropout: float = 0.1
    seed: int = 0


@dataclass
class NodeSaliency:
    gate_id: str
    gate_name: str
    qubits: list[int]
    # positive == removing the gate *lowers* the malicious probability
    delta: float
    direction: str  # "toward malicious" | "toward benign"


def _seed_all(seed: int) -> None:
    import torch
    torch.manual_seed(seed)


class GraphGNNClassifier:
    def __init__(self, vocab: dict[str, int], config: ClassifierConfig | None = None) -> None:
        from qshield.ml.gnn import GNNClassifier

        self.config = config or ClassifierConfig()
        self.vocab = dict(vocab)
        self.threshold: float | None = None
        self.threshold_quantile: float | None = None
        self._model = GNNClassifier(
            vocab_size=len(self.vocab),
            embed_dim=self.config.embed_dim,
            hidden=self.config.hidden,
            latent=self.config.latent,
            layers=self.config.layers,
            dropout=self.config.dropout,
        )

    # ------------------------------------------------------------------
    def _tensors(self, ir: CircuitIR):
        from qshield.ml.gnn import graph_to_tensors
        return graph_to_tensors(circuit_to_graph(ir), self.vocab)

    def fit(self, items) -> GraphGNNClassifier:
        """``items`` are LabeledCircuit-like objects with .ir and .is_malicious."""
        import torch
        from torch import nn

        labeled = [it for it in items]
        if not labeled:
            raise ValueError("fit() requires labeled items")
        n_mal = sum(1 for it in labeled if it.is_malicious)
        n_clean = len(labeled) - n_mal
        if n_mal == 0 or n_clean == 0:
            raise ValueError("fit() requires both clean and malicious examples")

        _seed_all(self.config.seed)
        pos_weight = torch.tensor([n_clean / n_mal], dtype=torch.float32)
        criterion = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
        opt = torch.optim.Adam(self._model.parameters(), lr=self.config.lr,
                               weight_decay=self.config.weight_decay)
        self._model.train()
        for _epoch in range(self.config.epochs):
            for it in labeled:
                batch = self._tensors(it.ir)
                if batch["gate_idx"].shape[0] == 0:
                    continue
                logit = self._model(batch["gate_idx"], batch["cont"], batch["edge_index"])
                target = torch.tensor([1.0 if it.is_malicious else 0.0])
                loss = criterion(logit.unsqueeze(0), target)
                opt.zero_grad()
                loss.backward()
                nn.utils.clip_grad_norm_(self._model.parameters(), max_norm=1.0)
                opt.step()
        self._model.eval()
        return self

    # ------------------------------------------------------------------
    def score(self, ir: CircuitIR) -> float:
        """Probability that ``ir`` is malicious (0-1)."""
        import torch
        batch = self._tensors(ir)
        if batch["gate_idx"].shape[0] == 0:
            return 0.0
        self._model.eval()
        with torch.no_grad():
            logit = self._model(batch["gate_idx"], batch["cont"], batch["edge_index"])
        return float(torch.sigmoid(logit).item())

    def calibrate_threshold(self, items, target_fpr: float = 0.05) -> float:
        """Pick the operating threshold from *train-clean* scores.

        threshold = the (1 - target_fpr) quantile of clean training
        scores, so roughly ``target_fpr`` of train-clean circuits would be
        flagged.  Must not see malicious data (mirrors the autoencoder
        calibration, so both modes are calibrated identically).
        """
        import math
        clean_scores = sorted(self.score(it.ir) for it in items if not it.is_malicious)
        if not clean_scores:
            raise ValueError("calibrate_threshold() requires clean items")
        idx = min(len(clean_scores) - 1,
                  max(0, math.ceil((1.0 - target_fpr) * len(clean_scores)) - 1))
        self.threshold = clean_scores[idx]
        self.threshold_quantile = 1.0 - target_fpr
        return self.threshold

    def predict(self, ir: CircuitIR, threshold: float | None = None) -> bool:
        thr = self.threshold if threshold is None else threshold
        if thr is None:
            thr = 0.5
        return self.score(ir) >= thr

    # ------------------------------------------------------------------
    def explain(self, ir: CircuitIR, top_k: int = 5) -> list[NodeSaliency]:
        """Leave-one-out saliency per gate."""
        p_full = self.score(ir)
        base = circuit_to_graph(ir)
        out: list[NodeSaliency] = []
        for i, gate in enumerate(ir.gates):
            reduced = copy.copy(ir)
            reduced.gates = [g for j, g in enumerate(ir.gates) if j != i]
            p_without = self.score(reduced)
            delta = p_full - p_without
            out.append(NodeSaliency(
                gate_id=base.gate_ids[i],
                gate_name=gate.gate_name,
                qubits=list(gate.qubits),
                delta=delta,
                direction="toward malicious" if delta >= 0 else "toward benign",
            ))
        out.sort(key=lambda s: abs(s.delta), reverse=True)
        return out[:top_k]

    # ------------------------------------------------------------------
    def save(self, path) -> None:
        import torch

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save({"model_state": self._model.state_dict(),
                    "vocab": self.vocab,
                    "config": self.config.__dict__,
                    "threshold": getattr(self, "threshold", None),
                    "threshold_quantile": getattr(self, "threshold_quantile", None)}, path)

    @classmethod
    def load(cls, path) -> GraphGNNClassifier:
        import torch

        blob = torch.load(Path(path), map_location="cpu", weights_only=False)
        clf = cls(vocab=blob["vocab"], config=ClassifierConfig(**blob["config"]))
        clf._model.load_state_dict(blob["model_state"])
        clf._model.eval()
        clf.threshold = blob.get("threshold")
        clf.threshold_quantile = blob.get("threshold_quantile")
        return clf


def build_classifier_from_items(items, *, epochs: int = 60, seed: int = 0,
                                hidden: int = 64, latent: int = 32) -> GraphGNNClassifier:
    vocab = build_vocab([it.ir for it in items])
    clf = GraphGNNClassifier(vocab, ClassifierConfig(epochs=epochs, seed=seed,
                                                     hidden=hidden, latent=latent))
    clf.fit(items)
    return clf
