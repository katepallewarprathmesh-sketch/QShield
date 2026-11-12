"""GNN encoder shared by the autoencoder and the supervised classifier.

Architecture (small enough for CPU training on the 417-fixture corpus):

* gate names -> embedding; continuous node features -> linear projection
* node encoder MLP -> N message-passing layers (sum aggregation over the
  wire graph, residual connections)
* graph readout: concat(mean pool, max pool) -> latent vector z

Heads:

* :class:`GNNAutoencoder` — node decoder reconstructs gate identity and
  continuous features; anomaly score = mean per-node reconstruction loss
  (trained on clean circuits only)
* :class:`GNNClassifier` — MLP head on z, binary cross-entropy against
  {clean, malicious} (trained on the labeled dataset; spec M3.2's
  "training pipeline on clean/malicious circuit dataset")

Requires torch (the ``ml`` extra).  Import guarded everywhere higher-level.
"""

from __future__ import annotations

import torch
from torch import nn

from qshield.ml.graph import CONTINUOUS_DIM, UNK_GATE, CircuitGraph


def graph_to_tensors(graph: CircuitGraph, vocab: dict[str, int]) -> dict[str, torch.Tensor]:
    unk = vocab[UNK_GATE]
    gate_idx = torch.tensor([vocab.get(name, unk) for name in graph.gate_names],
                            dtype=torch.long)
    cont = torch.tensor(graph.node_continuous, dtype=torch.float32) \
        if graph.node_continuous else torch.zeros((0, CONTINUOUS_DIM), dtype=torch.float32)
    edges = torch.tensor(graph.edges, dtype=torch.long).t().contiguous() \
        if graph.edges else torch.zeros((2, 0), dtype=torch.long)
    return {"gate_idx": gate_idx, "cont": cont, "edge_index": edges}


class GNNEncoder(nn.Module):
    def __init__(self, vocab_size: int, embed_dim: int = 16, cont_dim: int = CONTINUOUS_DIM,
                 hidden: int = 64, latent: int = 32, layers: int = 3) -> None:
        super().__init__()
        self.vocab_size = vocab_size
        self.hidden = hidden
        self.latent = latent
        self.cont_dim = cont_dim

        self.gate_embed = nn.Embedding(vocab_size, embed_dim)
        self.cont_proj = nn.Linear(cont_dim, embed_dim)
        self.node_in = nn.Linear(2 * embed_dim, hidden)
        self.mp_layers = nn.ModuleList([nn.Linear(2 * hidden, hidden) for _ in range(layers)])
        self.z_proj = nn.Linear(2 * hidden, latent)

    def forward(self, gate_idx: torch.Tensor, cont: torch.Tensor,
                edge_index: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        feats = torch.cat([self.gate_embed(gate_idx), torch.relu(self.cont_proj(cont))], dim=1)
        h = torch.relu(self.node_in(feats))
        for layer in self.mp_layers:
            if edge_index.shape[1] > 0:
                agg = torch.zeros_like(h)
                src, dst = edge_index[0], edge_index[1]
                agg.index_add_(0, dst, h[src])
            else:
                agg = torch.zeros_like(h)
            h = torch.relu(layer(torch.cat([h, agg], dim=1))) + h
        node_h = h
        mean_pool = node_h.mean(dim=0)
        max_pool = node_h.max(dim=0).values
        z = torch.relu(self.z_proj(torch.cat([mean_pool, max_pool], dim=0)))
        return node_h, z


class GNNAutoencoder(nn.Module):
    """Encoder + node decoder; trained on clean circuits only."""

    def __init__(self, vocab_size: int, embed_dim: int = 16, cont_dim: int = CONTINUOUS_DIM,
                 hidden: int = 64, latent: int = 32, layers: int = 3) -> None:
        super().__init__()
        self.vocab_size = vocab_size
        self.hidden = hidden
        self.latent = latent
        self.cont_dim = cont_dim

        self.encoder = GNNEncoder(vocab_size, embed_dim, cont_dim, hidden, latent, layers)
        self.dec_node = nn.Linear(hidden + latent, hidden)
        self.dec_gate = nn.Linear(hidden, vocab_size)
        self.dec_cont = nn.Linear(hidden, cont_dim)

    def forward(self, gate_idx: torch.Tensor, cont: torch.Tensor, edge_index: torch.Tensor):
        node_h, z = self.encoder(gate_idx, cont, edge_index)
        zc = z.unsqueeze(0).expand(node_h.shape[0], -1)
        d = torch.relu(self.dec_node(torch.cat([node_h, zc], dim=1)))
        return self.dec_gate(d), self.dec_cont(d), z

    def per_node_loss(self, gate_idx: torch.Tensor, cont: torch.Tensor,
                      edge_index: torch.Tensor) -> torch.Tensor:
        gate_logits, cont_pred = self.forward(gate_idx, cont, edge_index)[:2]
        ce = nn.functional.cross_entropy(gate_logits, gate_idx, reduction="none")
        mse = ((cont_pred - cont) ** 2).mean(dim=1)
        return ce + mse


class GNNClassifier(nn.Module):
    """Encoder + binary head on z; trained on the labeled dataset."""

    def __init__(self, vocab_size: int, embed_dim: int = 16, cont_dim: int = CONTINUOUS_DIM,
                 hidden: int = 64, latent: int = 32, layers: int = 3,
                 dropout: float = 0.1) -> None:
        super().__init__()
        self.vocab_size = vocab_size
        self.hidden = hidden
        self.latent = latent
        self.cont_dim = cont_dim

        self.encoder = GNNEncoder(vocab_size, embed_dim, cont_dim, hidden, latent, layers)
        self.head = nn.Sequential(
            nn.Linear(latent, hidden),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, 1),
        )

    def forward(self, gate_idx: torch.Tensor, cont: torch.Tensor,
                edge_index: torch.Tensor) -> torch.Tensor:
        """Returns the logit for 'malicious'."""
        _node_h, z = self.encoder(gate_idx, cont, edge_index)
        return self.head(z).squeeze(0)
