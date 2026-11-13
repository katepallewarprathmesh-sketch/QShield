"""Robustness Probe: base-finding survival under semantics-preserving rewrites."""

from __future__ import annotations

from pathlib import Path

import pytest

from qshield.core.parsers.qasm_parser import parse_qasm
from qshield.redteam import probe_finding_robustness

REPO = Path(__file__).resolve().parents[2]
ANCILLA = REPO / "tests" / "fixtures" / "malicious_circuits" / "ancilla_leakage.qasm"


@pytest.mark.skipif(not ANCILLA.exists(), reason="fixture not present")
def test_probe_reports_per_finding_survival():
    ir = parse_qasm(ANCILLA.read_text(), name="ancilla_leakage")
    out = probe_finding_robustness(ir, variants_per_attack=2)
    assert out["variants_per_attack"] == 2
    assert len(out["attacks"]) == 5
    assert out["base_findings"] >= 1
    for probe in out["probes"]:
        assert probe["robustness"] in ("robust", "fragile", "evaded")
        assert probe["survived"] <= probe["total"]
        assert set(probe["per_attack"]) == set(out["attacks"])
        for per in probe["per_attack"].values():
            assert per["survived"] <= per["variants"]
    assert out["limitations"]


def test_probe_on_clean_circuit_has_no_probes():
    bell = 'OPENQASM 2.0; include "qelib1.inc"; qreg q[2]; creg c[2];\nh q[0]; cx q[0],q[1]; measure q -> c;'
    out = probe_finding_robustness(parse_qasm(bell, name="bell"), variants_per_attack=1)
    assert out["probes"] == [] or all(not p["title"] for p in out["probes"])


def test_variants_per_attack_validated():
    ir = parse_qasm('OPENQASM 2.0; include "qelib1.inc"; qreg q[1]; h q[0];', name="t")
    with pytest.raises(ValueError):
        probe_finding_robustness(ir, variants_per_attack=0)
