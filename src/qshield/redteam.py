"""Robustness Probe — do a scan's findings survive semantics-preserving rewrites?

A malicious-circuit author will not submit the textbook pattern; they will
rewrite it into an equivalent shape.  This module answers the question any
auditor asks next: *if the circuit had been camouflaged, would the finding
still have fired?*

For a flagged circuit we apply each of the five semantics-preserving attack
classes from :mod:`qshield.evasion.attacks` (k seeded variants each),
re-run the static analyzer + builtin signature matcher, and report, per
base finding, how many variants preserved it:

* ``robust``  — finding fires in every camouflaged variant
* ``fragile`` — fires in some variants (suggests a rewrite class to harden against)
* ``evaded``  — fires in none (a finding that vanishes under trivial rewrites)

Honest scope: this measures *evidence stability under known rewrites*, not
security.  It cannot tell you a clean circuit is clean, and it only probes
the five implemented transform classes.  Publication-era evaluations of the
same transforms live in ``benchmarks/evasion_results.json``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from qshield.core.circuit_ir import CircuitIR
from qshield.evasion.attacks import ATTACK_NAMES, apply_attack


@dataclass
class _Probe:
    threat_type: str
    title: str
    per_attack: dict[str, dict[str, int]] = field(default_factory=dict)


def _finding_key(f: Any) -> tuple[str, str]:
    return (str(getattr(f, "threat_type", "unknown")), str(getattr(f, "title", "untitled")))


def _analyze_all(ir: CircuitIR) -> list:
    """Full static pipeline on a CircuitIR (structural + signatures + ancilla independence)."""
    from qshield.scanner import Scanner

    scanner = Scanner(config="default", parallel=False)
    scanner.add_circuit(ir)
    return list(scanner.run(analyses=["static"]).findings)


def probe_finding_robustness(ir: CircuitIR, *, variants_per_attack: int = 2) -> dict[str, Any]:
    """Probe how stable each base finding is under semantics-preserving rewrites."""
    if variants_per_attack < 1:
        raise ValueError("variants_per_attack must be >= 1")
    base = _analyze_all(ir)
    base_keys = list(dict.fromkeys(_finding_key(f) for f in base))  # de-dupe, keep order

    probes: dict[tuple[str, str], _Probe] = {key: _Probe(key[0], key[1]) for key in base_keys}
    total = len(ATTACK_NAMES) * variants_per_attack

    for attack in ATTACK_NAMES:
        survived = dict.fromkeys(base_keys, 0)
        fired_variants = 0
        for seed in range(variants_per_attack):
            try:
                variant = apply_attack(ir, attack, seed=seed)
            except Exception:  # noqa: S112 - a non-applying variant variant counts as not-survived, by design
                continue
            fired_variants += 1
            variant_keys = {_finding_key(f) for f in _analyze_all(variant)}
            for key in base_keys:
                if key in variant_keys:
                    survived[key] += 1
        for key in base_keys:
            probes[key].per_attack[attack] = {
                "survived": survived[key],
                "variants": fired_variants,
            }

    out_probes = []
    for _key, probe in probes.items():
        survived_total = sum(v["survived"] for v in probe.per_attack.values())
        if survived_total == 0:
            verdict = "evaded"
        elif survived_total == total:
            verdict = "robust"
        else:
            verdict = "fragile"
        out_probes.append(
            {
                "threat_type": probe.threat_type,
                "title": probe.title,
                "robustness": verdict,
                "survived": survived_total,
                "total": total,
                "per_attack": probe.per_attack,
            }
        )

    return {
        "base_findings": len(base),
        "probes": out_probes,
        "variants_per_attack": variants_per_attack,
        "attacks": list(ATTACK_NAMES),
        "limitations": [
            "Probes only the five implemented semantics-preserving rewrites; evasions outside this set are not measured.",
            "A 'robust' verdict means the evidence survived these rewrites — not that the circuit is safe or malicious.",
            "Fixture-corpus calibration lives in benchmarks/evasion_results.json; this probe runs your circuit as given.",
        ],
    }
