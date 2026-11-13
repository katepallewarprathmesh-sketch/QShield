"""Policy Studio: rule correctness, spec validation, corpus scoring."""

from __future__ import annotations

from pathlib import Path

import pytest

from qshield.core.parsers.qasm_parser import parse_qasm
from qshield.policy import (
    BUILTIN_POLICIES,
    PolicyEngine,
    PolicyError,
    builtin_policies,
    check_policy,
    evaluate_corpus,
)

REPO = Path(__file__).resolve().parents[2]
CLEAN = REPO / "tests" / "fixtures" / "clean_circuits"
MAL = REPO / "tests" / "fixtures" / "malicious_circuits"


def _spec(rule_kind, params, *, pid="T-1", sev="low"):
    return {"id": pid, "name": "t", "description": "t", "severity": sev, "rule": {"kind": rule_kind, "params": params}}


def test_builtin_pack_is_valid_and_nonempty():
    specs = builtin_policies()
    assert len(specs) == len(BUILTIN_POLICIES) >= 6
    ids = [s.id for s in specs]
    assert len(set(ids)) == len(ids)
    for s in specs:
        assert s.severity in ("critical", "high", "medium", "low", "info")


def test_forbidden_gate_fires_and_names_indices():
    ir = parse_qasm(
        'OPENQASM 2.0; include "qelib1.inc"; qreg q[2];\nu3(0.1,0.2,0.3) q[0]; h q[1];',
        name="t",
    )
    spec = _spec_helper = _spec("forbidden_gate", {"gates": ["u3"]})
    engine = PolicyEngine.from_dicts([spec])
    findings = engine.check(ir)
    assert len(findings) == 1
    assert findings[0].gate_indices == [0]


def test_max_depth_and_width():
    shallow = parse_qasm('OPENQASM 2.0; include "qelib1.inc"; qreg q[2]; creg c[2]; h q[0]; measure q -> c;', name="t")
    assert check_policy(shallow, PolicyEngine.from_dicts([_spec("max_depth", {"max": 4})]).specs[0]) == []
    assert check_policy(shallow, PolicyEngine.from_dicts([_spec("max_width", {"max": 1})]).specs[0]) != []


def test_max_measurements_counts_qasm_measurements():
    qasm = (
        'OPENQASM 2.0; include "qelib1.inc"; qreg q[3]; creg c[3];\n'
        "h q[0]; cx q[0],q[1]; measure q -> c;"
    )
    ir = parse_qasm(qasm, name="t")
    specs = PolicyEngine.from_dicts([_spec("max_measurements", {"max": 2})]).specs
    assert check_policy(ir, specs[0]) != []  # 3 measurements > 2
    specs_ok = PolicyEngine.from_dicts([_spec("max_measurements", {"max": 3})]).specs
    assert check_policy(ir, specs_ok[0]) == []


def test_density_rule_counts_two_qubit_ratio():
    qasm = 'OPENQASM 2.0; include "qelib1.inc"; qreg q[3];\nh q[0]; cx q[0],q[1]; cx q[1],q[2]; cx q[2],q[0];'
    ir = parse_qasm(qasm, name="t")
    specs = PolicyEngine.from_dicts([_spec("max_two_qubit_density", {"max": 0.5})]).specs
    assert check_policy(ir, specs[0]) != []


def test_spec_validation_rejects_garbage():
    with pytest.raises(PolicyError):
        PolicyEngine.from_dicts([{"id": "X"}])  # missing rule/name
    with pytest.raises(PolicyError):
        PolicyEngine.from_dicts([_spec("not_a_rule", {})])
    with pytest.raises(PolicyError):
        PolicyEngine.from_dicts([_spec("forbidden_gate", {"gates": "oops"})])
    with pytest.raises(PolicyError):
        PolicyEngine.from_dicts([_spec("max_depth", {"max": 0})])
    with pytest.raises(PolicyError):
        PolicyEngine.from_dicts([_spec("max_two_qubit_density", {"max": 1.5})])
    with pytest.raises(PolicyError):
        PolicyEngine.from_dicts([_spec("max_depth", {"max": 3}, sev="catastrophic")])


def test_duplicate_ids_rejected():
    with pytest.raises(PolicyError):
        PolicyEngine.from_dicts([_spec("max_depth", {"max": 3}, pid="DUP"), _spec("max_width", {"max": 3}, pid="DUP")])


@pytest.mark.skipif(not (CLEAN.exists() and MAL.exists()), reason="fixture corpus not present")
def test_evaluate_corpus_small_sample_shapes_and_bounds():
    engine = PolicyEngine(builtin_policies())
    out = evaluate_corpus(engine, CLEAN, MAL, sample=10)
    assert out["corpus"]["clean"] == 10 and out["corpus"]["malicious"] == 10
    assert len(out["per_policy"]) == len(engine.specs)
    for row in out["per_policy"]:
        assert 0.0 <= row["tpr"] <= 1.0 and 0.0 <= row["fpr"] <= 1.0
        assert row["tp"] + row["fn"] + row["fp"] + row["tn"] > 0
    assert 0.0 <= out["any_policy"]["tpr"] <= 1.0
    assert "not field rates" in out["note"]
