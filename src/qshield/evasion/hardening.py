"""Blue-team hardening: adversarial training for the GNN detector.

Trains a :class:`qshield.ml.classifier.GraphGNNClassifier` on the labeled
dataset *augmented* with attacked copies of every circuit (same label).
Hardening uses the same attack suite the red team will try, so the gain is
a genuine robustness measurement, not a parlor trick.

Calibration is unaffected: the threshold is still derived from a held-out
clean slice *without* attack augmentation — the FPR number remains an
honest clean-data estimate, while the TPR-under-attack number shows the
hardening effect.
"""

from __future__ import annotations

from dataclasses import dataclass

from qshield.evasion.attacks import ATTACK_NAMES, apply_attack
from qshield.ml.classifier import ClassifierConfig, GraphGNNClassifier
from qshield.ml.graph import build_vocab

# per-attack overrides for augmentation (kept small so training stays fast)
_ATTACK_KW = {
    "camouflage": {"k": 2},
    "synonyms": {"rate": 0.5},
    "rotation_split": {"rate": 0.5},
    "dead_code": {"depth": 8},
    "qubit_relabel": {},
}


@dataclass
class _AugItem:
    ir: object
    is_malicious: bool
    name: str

    @property
    def label(self) -> int:  # compatibility with dataset helpers
        return 1 if self.is_malicious else 0


def augment_items(items, *, seed: int = 0,
                  attacks: tuple[str, ...] = ATTACK_NAMES) -> list[_AugItem]:
    """Original items plus one attacked copy per attack, labels preserved."""
    out: list[_AugItem] = []
    for i, it in enumerate(items):
        mal = bool(it.is_malicious)
        name = getattr(it, "name", f"item{i}")
        out.append(_AugItem(it.ir, mal, name))
        for j, atk in enumerate(attacks):
            kw = dict(_ATTACK_KW.get(atk, {}))
            attacked = apply_attack(it.ir, atk, seed=seed * 1000 + i * 10 + j, **kw)
            out.append(_AugItem(attacked, mal, f"{name}::{atk}"))
    return out


def train_hardened_classifier(items, *, seed: int = 0, epochs: int = 60,
                              hidden: int = 64, latent: int = 32) -> GraphGNNClassifier:
    """Adversarially-trained GNN: fit on original + attacked copies."""
    aug = augment_items(items, seed=seed)
    vocab = build_vocab([it.ir for it in aug])
    clf = GraphGNNClassifier(vocab, ClassifierConfig(epochs=epochs, seed=seed,
                                                     hidden=hidden, latent=latent))
    clf.fit(aug)
    return clf
