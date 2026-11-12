"""ML-based circuit anomaly detection (spec M3.2, Phase 3).

torch is an optional dependency (``pip install 'qshield[ml]'``).  All
torch-importing modules degrade gracefully: :func:`torch_available` lets
callers feature-detect, and dataset/graph helpers work without it.
"""

from qshield.ml.classifier import (
    ClassifierConfig,
    GraphGNNClassifier,
    NodeSaliency,
    build_classifier_from_items,
)
from qshield.ml.dataset import (
    LABEL_CLEAN,
    LABEL_MALICIOUS,
    DatasetStats,
    LabeledCircuit,
    load_fixture_dataset,
)
from qshield.ml.detector import (
    GateExplanation,
    GraphAnomalyDetector,
    TrainConfig,
    torch_available,
    train_from_items,
)
from qshield.ml.graph import CONTINUOUS_DIM, CircuitGraph, build_vocab, circuit_to_graph

__all__ = [
    "CONTINUOUS_DIM",
    "LABEL_CLEAN",
    "LABEL_MALICIOUS",
    "CircuitGraph",
    "ClassifierConfig",
    "DatasetStats",
    "GateExplanation",
    "GraphAnomalyDetector",
    "GraphGNNClassifier",
    "LabeledCircuit",
    "NodeSaliency",
    "TrainConfig",
    "build_classifier_from_items",
    "build_vocab",
    "circuit_to_graph",
    "load_fixture_dataset",
    "torch_available",
    "train_from_items",
]
