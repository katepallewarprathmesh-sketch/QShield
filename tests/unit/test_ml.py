"""Unit tests for the ML anomaly detector (spec M3.2).

Skipped entirely when torch is unavailable (the ``ml`` extra).
"""

import math

import pytest

from qshield.core.parsers import parse_qasm
from qshield.ml import (
    ClassifierConfig,
    GraphAnomalyDetector,
    GraphGNNClassifier,
    TrainConfig,
    build_vocab,
    circuit_to_graph,
    load_fixture_dataset,
    torch_available,
)

pytestmark = pytest.mark.skipif(not torch_available(), reason="torch not installed (qshield[ml])")

BELL = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n"
BELL_TAMPERED = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\nrz(0.5) q[0];\n"
GHZ3 = "OPENQASM 2.0;\nqreg q[3];\nh q[0];\ncx q[0], q[1];\ncx q[1], q[2];\n"
GHZ3_TAMPERED = "OPENQASM 2.0;\nqreg q[3];\nh q[0];\ncx q[0], q[1];\nrz(0.7) q[1];\ncx q[1], q[2];\n"


def _tiny_detector(items_for_vocab, epochs=3, hidden=16, latent=8):
    vocab = build_vocab([it for it in items_for_vocab])
    return GraphAnomalyDetector(vocab, TrainConfig(epochs=epochs, seed=0,
                                                   hidden=hidden, latent=latent, layers=1))


def _tiny_classifier(items, epochs=5, hidden=16, latent=8):
    vocab = build_vocab([it.ir for it in items])
    return GraphGNNClassifier(vocab, ClassifierConfig(epochs=epochs, seed=0,
                                                      hidden=hidden, latent=latent, layers=1))


# ---------------------------------------------------------------- dataset
def test_fixture_dataset_loads_both_labels():
    items, stats = load_fixture_dataset()
    assert stats.total >= 400
    assert stats.clean >= 190
    assert stats.malicious >= 200
    assert stats.skipped == []
    assert len(items) == stats.total


# ---------------------------------------------------------------- graph
def test_graph_nodes_edges_and_features():
    ir = parse_qasm(BELL)
    g = circuit_to_graph(ir)
    assert g.num_nodes == 2
    assert g.gate_names == ["h", "cx"]
    # two consecutive gates share qubit 0 -> one undirected edge (both dirs)
    assert (0, 1) in g.edges and (1, 0) in g.edges
    assert len(g.node_continuous[0]) == 5
    assert g.node_qubits == [[0], [0, 1]]


def test_empty_circuit_graph_is_safe():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\n")
    g = circuit_to_graph(ir)
    assert g.num_nodes == 0 and g.edges == []


def test_vocab_reserves_zero_for_unknown():
    ir = parse_qasm(BELL)
    vocab = build_vocab([ir])
    assert vocab["<unk>"] == 0
    assert vocab["h"] > 0 and vocab["cx"] > 0


def test_unseen_gate_falls_back_to_unk():
    train_ir = parse_qasm(BELL)
    test_ir = parse_qasm(BELL_TAMPERED)  # rz unseen in BELL-only vocab
    det = _tiny_detector([train_ir], epochs=2)
    det.fit([train_ir, parse_qasm(GHZ3)])
    # must not raise; rz maps to UNK
    assert math.isfinite(det.score(test_ir))


# ---------------------------------------------------------------- detector
def test_autoencoder_score_is_finite_and_nonnegative():
    clean = [parse_qasm(BELL), parse_qasm(GHZ3), parse_qasm(GHZ3)]
    det = _tiny_detector(clean, epochs=3)
    det.fit(clean)
    s = det.score(parse_qasm(BELL_TAMPERED))
    assert math.isfinite(s) and s >= 0.0


def test_autoencoder_empty_circuit_scores_zero():
    clean = [parse_qasm(BELL)]
    det = _tiny_detector(clean, epochs=1)
    det.fit(clean)
    assert det.score(parse_qasm("OPENQASM 2.0;\nqreg q[1];\n")) == 0.0


def test_calibrate_and_predict_threshold():
    clean = [parse_qasm(BELL), parse_qasm(GHZ3), parse_qasm(GHZ3)]
    det = _tiny_detector(clean, epochs=2)
    det.fit(clean)
    thr = det.calibrate_threshold(clean, quantile=0.95)
    assert det.threshold == thr and det.threshold_quantile == 0.95
    assert isinstance(det.predict(parse_qasm(BELL_TAMPERED)), bool)


def test_explain_reports_top_gates():
    clean = [parse_qasm(BELL), parse_qasm(GHZ3)]
    det = _tiny_detector(clean, epochs=2)
    det.fit(clean)
    explanations = det.explain(parse_qasm(BELL_TAMPERED), top_k=2)
    assert len(explanations) == 2
    assert all(e.loss > 0 for e in explanations)
    assert abs(sum(e.share for e in explanations)) <= 1.0
    assert all(e.dominant in ("gate identity", "parameters/arity") for e in explanations)


def test_detector_save_load_roundtrip(tmp_path):
    clean = [parse_qasm(BELL), parse_qasm(GHZ3)]
    det = _tiny_detector(clean, epochs=2)
    det.fit(clean)
    det.calibrate_threshold(clean)
    before = det.score(parse_qasm(BELL_TAMPERED))
    path = tmp_path / "ae.pt"
    det.save(path)
    loaded = GraphAnomalyDetector.load(path)
    assert loaded.threshold == pytest.approx(det.threshold)
    assert loaded.score(parse_qasm(BELL_TAMPERED)) == pytest.approx(before, abs=1e-6)


# ---------------------------------------------------------------- classifier
def _labeled_items():
    class Item:
        def __init__(self, qasm, label):
            self.ir = parse_qasm(qasm)
            self.is_malicious = label == 1
    return [Item(BELL, 0), Item(GHZ3, 0), Item(BELL_TAMPERED, 1), Item(GHZ3_TAMPERED, 1)]


def test_classifier_score_in_unit_interval():
    items = _labeled_items()
    clf = _tiny_classifier(items, epochs=2)
    clf.fit(items)
    s = clf.score(parse_qasm(BELL_TAMPERED))
    assert 0.0 <= s <= 1.0


def test_classifier_calibrate_uses_clean_only():
    items = _labeled_items()
    clf = _tiny_classifier(items, epochs=2)
    clf.fit(items)
    thr = clf.calibrate_threshold(items, target_fpr=0.5)  # small set: loose quantile
    assert 0.0 <= thr <= 1.0
    assert isinstance(clf.predict(parse_qasm(BELL)), bool)


def test_classifier_explain_loo_saliency():
    items = _labeled_items()
    clf = _tiny_classifier(items, epochs=2)
    clf.fit(items)
    explanations = clf.explain(parse_qasm(GHZ3_TAMPERED), top_k=2)
    assert len(explanations) == 2
    assert all(e.direction in ("toward malicious", "toward benign") for e in explanations)
    assert explanations[0].gate_name  # some gate named


def test_classifier_save_load_roundtrip(tmp_path):
    items = _labeled_items()
    clf = _tiny_classifier(items, epochs=2)
    clf.fit(items)
    before = clf.score(parse_qasm(BELL_TAMPERED))
    path = tmp_path / "clf.pt"
    clf.save(path)
    loaded = GraphGNNClassifier.load(path)
    assert loaded.score(parse_qasm(BELL_TAMPERED)) == pytest.approx(before, abs=1e-6)
