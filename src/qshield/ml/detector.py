"""Training pipeline + inference for the graph anomaly detector (M3.2).

Honest-by-construction details:

* trained on *clean* circuits only (semi-supervised anomaly detection);
* the anomaly score is mean per-node reconstruction loss;
* the decision threshold is calibrated on a held-out clean split at a
  configurable quantile — never on malicious data;
* explainability reports per-gate reconstruction-loss contributions.

Requires torch (the ``ml`` extra).
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

from qshield.core.circuit_ir import CircuitIR
from qshield.ml.graph import CircuitGraph, build_vocab, circuit_to_graph


@dataclass
class GateExplanation:
    gate_id: str
    gate_name: str
    qubits: list[int]
    loss: float                  # raw per-node reconstruction loss
    share: float                 # contribution share of total loss (0-1)
    dominant: str                # "gate identity" | "parameters/arity"

    def reason(self) -> str:
        if self.dominant == "gate identity":
            return (f"gate {self.gate_name!r} on qubits {self.qubits} is poorly predicted "
                    f"in this neighbourhood (gate-identity mis-prediction)")
        return (f"parameters/arity pattern of {self.gate_name!r} on qubits {self.qubits} "
                f"is unusual for this circuit's structure")


def torch_available() -> bool:
    try:
        import torch  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass
class TrainConfig:
    epochs: int = 40
    lr: float = 1e-2
    weight_decay: float = 1e-5
    hidden: int = 64
    latent: int = 32
    embed_dim: int = 16
    layers: int = 3
    seed: int = 0


def _seed_all(seed: int) -> None:
    import torch
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(False)


class GraphAnomalyDetector:
    """Semi-supervised GNN autoencoder; higher score == more anomalous."""

    def __init__(self, vocab: dict[str, int], config: TrainConfig | None = None) -> None:
        from qshield.ml.gnn import GNNAutoencoder

        self.config = config or TrainConfig()
        self.vocab = dict(vocab)
        self.threshold: float | None = None
        self.threshold_quantile: float | None = None
        self._model = GNNAutoencoder(
            vocab_size=len(self.vocab),
            embed_dim=self.config.embed_dim,
            hidden=self.config.hidden,
            latent=self.config.latent,
            layers=self.config.layers,
        )
        self._train_loss_curve: list[float] = []

    # ------------------------------------------------------------------
    # data plumbing
    # ------------------------------------------------------------------
    def _graphs(self, irs) -> list[CircuitGraph]:
        return [circuit_to_graph(ir) for ir in irs]

    def _tensors(self, graph: CircuitGraph):
        from qshield.ml.gnn import graph_to_tensors
        return graph_to_tensors(graph, self.vocab)

    # ------------------------------------------------------------------
    # training
    # ------------------------------------------------------------------
    def fit(self, clean_irs: list[CircuitIR]) -> GraphAnomalyDetector:
        import torch

        graphs = self._graphs(clean_irs)
        if not graphs:
            raise ValueError("fit() requires at least one clean circuit")
        _seed_all(self.config.seed)
        opt = torch.optim.Adam(self._model.parameters(), lr=self.config.lr,
                               weight_decay=self.config.weight_decay)
        self._model.train()
        self._train_loss_curve = []
        for _epoch in range(self.config.epochs):
            total = 0.0
            count = 0
            for g in graphs:
                if g.num_nodes == 0:
                    continue
                batch = self._tensors(g)
                loss = self._model.per_node_loss(batch["gate_idx"], batch["cont"],
                                                 batch["edge_index"]).mean()
                opt.zero_grad()
                loss.backward()
                opt.step()
                total += float(loss.item()) * g.num_nodes
                count += g.num_nodes
            self._train_loss_curve.append(total / max(count, 1))
        self._model.eval()
        return self

    # ------------------------------------------------------------------
    # scoring
    # ------------------------------------------------------------------
    def _per_node_losses(self, ir: CircuitIR):
        import torch
        g = circuit_to_graph(ir)
        if g.num_nodes == 0:
            return g, torch.zeros(0)
        batch = self._tensors(g)
        self._model.eval()
        with torch.no_grad():
            losses = self._model.per_node_loss(batch["gate_idx"], batch["cont"],
                                               batch["edge_index"])
        return g, losses

    def score(self, ir: CircuitIR) -> float:
        g, losses = self._per_node_losses(ir)
        if g.num_nodes == 0:
            return 0.0
        return float(losses.mean().item())

    def calibrate_threshold(self, clean_irs: list[CircuitIR], quantile: float = 0.95) -> float:
        scores = sorted(self.score(ir) for ir in clean_irs)
        if not scores:
            raise ValueError("calibrate_threshold() requires at least one clean circuit")
        idx = min(len(scores) - 1, max(0, math.ceil(quantile * len(scores)) - 1))
        self.threshold = scores[idx]
        self.threshold_quantile = quantile
        return self.threshold

    def predict(self, ir: CircuitIR) -> bool:
        if self.threshold is None:
            raise RuntimeError("call calibrate_threshold() before predict()")
        return self.score(ir) > self.threshold

    # ------------------------------------------------------------------
    # explainability
    # ------------------------------------------------------------------
    def explain(self, ir: CircuitIR, top_k: int = 5) -> list[GateExplanation]:
        g, losses = self._per_node_losses(ir)
        if g.num_nodes == 0:
            return []
        total = float(losses.sum().item()) or 1e-12
        order = losses.argsort(descending=True).tolist()
        out: list[GateExplanation] = []
        for i in order[:top_k]:
            dominant = self._dominant_term(ir, i)
            out.append(GateExplanation(
                gate_id=g.gate_ids[i],
                gate_name=g.gate_names[i],
                qubits=list(g.node_qubits[i]),
                loss=float(losses[i].item()),
                share=float(losses[i].item()) / total,
                dominant=dominant,
            ))
        return out

    def _dominant_term(self, ir: CircuitIR, node_index: int) -> str:
        import torch
        from torch import nn

        g = circuit_to_graph(ir)
        batch = self._tensors(g)
        with torch.no_grad():
            logits, cont_pred = self._model.forward(
                batch["gate_idx"], batch["cont"], batch["edge_index"])[:2]
            ce = nn.functional.cross_entropy(logits[node_index:node_index + 1],
                                             batch["gate_idx"][node_index:node_index + 1])
            mse = ((cont_pred[node_index] - batch["cont"][node_index]) ** 2).mean()
        return "gate identity" if float(ce) >= float(mse) else "parameters/arity"

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------
    def save(self, path) -> None:
        import torch

        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "model_state": self._model.state_dict(),
            "vocab": self.vocab,
            "config": self.config.__dict__,
            "threshold": self.threshold,
            "threshold_quantile": self.threshold_quantile,
        }, path)

    @classmethod
    def load(cls, path) -> GraphAnomalyDetector:
        import torch

        blob = torch.load(Path(path), map_location="cpu", weights_only=False)
        config = TrainConfig(**blob["config"])
        det = cls(vocab=blob["vocab"], config=config)
        det._model.load_state_dict(blob["model_state"])
        det._model.eval()
        det.threshold = blob.get("threshold")
        det.threshold_quantile = blob.get("threshold_quantile")
        return det


def train_from_items(items, *, epochs: int = 40, seed: int = 0,
                     hidden: int = 64, latent: int = 32) -> GraphAnomalyDetector:
    """Convenience helper used by benchmarks/tests: fit on the clean subset."""
    clean = [it.ir for it in items if not it.is_malicious]
    if not clean:
        raise ValueError("no clean circuits in items")
    vocab = build_vocab([it.ir for it in items])
    det = GraphAnomalyDetector(vocab, TrainConfig(epochs=epochs, seed=seed,
                                                  hidden=hidden, latent=latent))
    det.fit(clean)
    return det
