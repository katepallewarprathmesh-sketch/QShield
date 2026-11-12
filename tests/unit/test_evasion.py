"""Unit tests for the M3.3 evasion-resistance tooling."""

import numpy as np
import pytest

from qshield.core.parsers import parse_qasm
from qshield.evasion import (
    ATTACK_NAMES,
    ATTACKS,
    apply_attack,
    attack_camouflage,
    attack_dead_code,
    attack_qubit_relabel,
    attack_rotation_split,
    attack_synonyms,
    augment_items,
)
from qshield.ml import torch_available
from qshield.static.randomized_equivalence import randomized_equivalence

SWAPY = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\nswap q[0], q[1];\nrz(0.7) q[0];\n"


def _gates(ir):
    return [(g.gate_name, tuple(g.qubits), tuple(round(p, 9) for p in g.parameters))
            for g in ir.gates]


# ---------------------------------------------------------------- suite
def test_attack_registry_consistent():
    assert set(ATTACK_NAMES) == set(ATTACKS)
    assert "qubit_relabel" in ATTACKS


def test_apply_attack_unknown_raises():
    ir = parse_qasm(SWAPY)
    with pytest.raises(KeyError, match="unknown attack"):
        apply_attack(ir, "mind_control")


def test_attacks_are_deterministic():
    ir = parse_qasm(SWAPY)
    for name in ATTACK_NAMES:
        a, b = apply_attack(ir, name, seed=11), apply_attack(ir, name, seed=11)
        assert _gates(a) == _gates(b), name


# ------------------------------------- semantics preservation (exact)
@pytest.mark.parametrize("name", ["camouflage", "synonyms", "rotation_split", "dead_code"])
def test_attack_preserves_semantics(name):
    base = parse_qasm(SWAPY)
    attacked = apply_attack(base, name, seed=4)
    report = randomized_equivalence(base, attacked, num_samples=4, seed=3)
    assert report.equivalent, f"{name} changed circuit semantics"


def test_relabel_is_graph_isomorphism_via_unitary_conjugation():
    base = parse_qasm(SWAPY)
    attacked = attack_qubit_relabel(base, seed=5)
    # derive the permutation by matching gates (same order, gate names)
    pi = {}
    for gb, ga in zip(base.gates, attacked.gates, strict=True):
        assert gb.gate_name == ga.gate_name
        for qb, qa in zip(gb.qubits, ga.qubits, strict=True):
            if qb in pi:
                assert pi[qb] == qa
            pi[qb] = qa
    n = base.num_qubits
    dim = 2**n
    assert set(pi) == set(range(n))  # test circuit touches every qubit

    def perm_matrix(msb_first: bool) -> np.ndarray:
        P = np.zeros((dim, dim), dtype=complex)
        for x in range(dim):
            y = 0
            for qb, qa in pi.items():
                if msb_first:
                    bit = (x >> (n - 1 - qb)) & 1
                    y |= bit << (n - 1 - qa)
                else:
                    bit = (x >> qb) & 1
                    y |= bit << qa
            P[y, x] = 1
        return P

    U, Uatk = base.to_unitary(), attacked.to_unitary()
    assert any(np.allclose(Uatk, P @ U @ P.conj().T) for P in
               (perm_matrix(True), perm_matrix(False)))


# ---------------------------------------------------------------- camouflage
def test_camouflage_inserts_exact_pairs():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nh q[0];\n")
    out = attack_camouflage(ir, k=3, seed=0)
    assert len(out.gates) == 1 + 2 * 3


# ---------------------------------------------------------------- synonyms
def test_synonyms_rate_one_rewrites_everything():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nswap q[0], q[1];\nx q[0];\n")
    out = attack_synonyms(ir, rate=1.0, seed=0)
    names = [g.gate_name for g in out.gates]
    assert names.count("cx") == 3          # swap -> 3 cx
    assert names[-3:] == ["h", "z", "h"]    # x -> h z h
    assert "swap" not in names and "x" not in names


def test_synonyms_cx_becomes_h_cz_h():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[2];\ncx q[0], q[1];\n")
    out = attack_synonyms(ir, rate=1.0, seed=0)
    assert [g.gate_name for g in out.gates] == ["h", "cz", "h"]
    assert out.gates[0].qubits == [1] and out.gates[1].qubits == [0, 1]


def test_rotation_split_halves_angle():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nrz(0.8) q[0];\n")
    out = attack_rotation_split(ir, rate=1.0, seed=0)
    assert [g.gate_name for g in out.gates] == ["rz", "rz"]
    assert all(g.parameters[0] == pytest.approx(0.4) for g in out.gates)


# ---------------------------------------------------------------- dead_code
def test_dead_code_appends_identity_block():
    ir = parse_qasm(SWAPY)
    out = attack_dead_code(ir, depth=6, seed=0)
    assert len(out.gates) == len(ir.gates) + 12
    # tail block is self-inverse: last 6 gates invert the previous 6
    block, inverse = out.gates[len(ir.gates):len(ir.gates) + 6], out.gates[-6:]
    inv = {"h": "h", "s": "sdg", "sdg": "s", "t": "tdg", "tdg": "t",
           "x": "x", "y": "y", "z": "z", "cx": "cx"}
    for g_fwd, g_inv in zip(block, reversed(inverse), strict=True):
        assert inv[g_fwd.gate_name] == g_inv.gate_name
        assert g_fwd.qubits == g_inv.qubits


# ---------------------------------------------------------------- augment
def test_augment_items_multiplies_and_preserves_labels():
    class Item:
        def __init__(self, qasm, label):
            self.ir = parse_qasm(qasm)
            self.is_malicious = label == 1
            self.name = f"item{label}"

    items = [Item(SWAPY, 0), Item(SWAPY, 1)]
    aug = augment_items(items, seed=0)
    assert len(aug) == len(items) * (1 + len(ATTACK_NAMES))
    labels = [a.is_malicious for a in aug]
    assert sum(labels) == (1 + len(ATTACK_NAMES))  # one malicious label in each copy


# ------------------------------------------------------- hardening smoke
@pytest.mark.skipif(not torch_available(), reason="torch not installed (qshield[ml])")
def test_hardened_classifier_trains_on_augmented():
    from qshield.evasion import train_hardened_classifier

    class Item:
        def __init__(self, qasm, label):
            self.ir = parse_qasm(qasm)
            self.is_malicious = label == 1
            self.name = f"item{label}"

    good = Item(SWAPY, 0)
    bad = Item("OPENQASM 2.0;\nqreg q[2];\nh q[0];\nswap q[0], q[1];\nrz(0.7) q[0];\nrz(0.001) q[0];\n", 1)
    clf = train_hardened_classifier([good, bad], seed=0, epochs=1, hidden=8, latent=4)
    s = clf.score(bad.ir)
    assert 0.0 <= s <= 1.0
