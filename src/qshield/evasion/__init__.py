"""Evasion-resistance tooling (spec M3.3): adversarial attack suite and
hardening via adversarial training."""

from qshield.evasion.attacks import (
    ATTACK_NAMES,
    ATTACKS,
    apply_attack,
    attack_camouflage,
    attack_dead_code,
    attack_qubit_relabel,
    attack_rotation_split,
    attack_synonyms,
)
from qshield.evasion.hardening import augment_items, train_hardened_classifier

__all__ = [
    "ATTACKS",
    "ATTACK_NAMES",
    "apply_attack",
    "attack_camouflage",
    "attack_dead_code",
    "attack_qubit_relabel",
    "attack_rotation_split",
    "attack_synonyms",
    "augment_items",
    "train_hardened_classifier",
]
