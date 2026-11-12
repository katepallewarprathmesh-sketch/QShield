"""CircuitIR -> plain-Python graph representation for the GNN.

Kept torch-free so the dataset/graph layer can be imported and tested
without the optional ``ml`` extra installed.  ``qshield.ml.gnn`` converts
these structures into tensors.

Nodes are gates in IR order.  Edges connect gates that act on the same
qubit and are adjacent on that qubit (the "wire graph") — undirected for
message passing (both directions are emitted).  An empty circuit yields an
empty graph and every scorer must treat it as maximally benign (score 0.0).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from qshield.core.circuit_ir import CircuitIR

UNK_GATE = "<unk>"

CONTINUOUS_DIM = 5  # mean_qubit_norm, t_norm, arity/3, n_params/3, has_params


@dataclass
class CircuitGraph:
    num_nodes: int
    num_qubits: int
    depth: int
    gate_names: list[str]            # per node
    node_continuous: list[list[float]]  # per node, length CONTINUOUS_DIM
    node_qubits: list[list[int]]     # per node, for explainability
    edges: list[tuple[int, int]]     # undirected, both directions present
    gate_ids: list[str] = field(default_factory=list)


def circuit_to_graph(ir: CircuitIR) -> CircuitGraph:
    depth = max(ir.get_depth(), 1)
    n_gates = max(len(ir.gates), 1)
    denom = max(ir.num_qubits - 1, 1)

    gate_names: list[str] = []
    node_continuous: list[list[float]] = []
    node_qubits: list[list[int]] = []
    gate_ids: list[str] = []
    for t, gate in enumerate(ir.gates):
        qs = list(gate.qubits)
        mean_q = (sum(qs) / len(qs)) / denom if qs else 0.0
        node_continuous.append([
            mean_q,
            t / max(n_gates - 1, 1),
            min(len(qs), 3) / 3.0,
            min(len(gate.parameters), 3) / 3.0,
            1.0 if gate.parameters else 0.0,
        ])
        gate_names.append(gate.gate_name)
        node_qubits.append(qs)
        gate_ids.append(gate.gate_id)

    # wire graph: per qubit, chain gates acting on it in IR order
    last_on_qubit: dict[int, int] = {}
    edge_set: set[tuple[int, int]] = set()
    for idx, gate in enumerate(ir.gates):
        for q in gate.qubits:
            prev = last_on_qubit.get(q)
            if prev is not None and prev != idx:
                edge_set.add((prev, idx))
                edge_set.add((idx, prev))
            last_on_qubit[q] = idx

    return CircuitGraph(
        num_nodes=len(ir.gates),
        num_qubits=ir.num_qubits,
        depth=depth,
        gate_names=gate_names,
        node_continuous=node_continuous,
        node_qubits=node_qubits,
        edges=sorted(edge_set),
        gate_ids=gate_ids,
    )


def build_vocab(irs) -> dict[str, int]:
    """Vocabulary from gate names seen in ``irs``; 0 is reserved for UNK."""
    names = sorted({g.gate_name for ir in irs for g in ir.gates})
    vocab = {UNK_GATE: 0}
    for i, name in enumerate(names, start=1):
        vocab[name] = i
    return vocab
