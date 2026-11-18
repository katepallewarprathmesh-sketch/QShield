"""Golden-vector and behavioral tests for canonicalization spec v1."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from qshield.core import CANONICALIZATION_SPEC, canonical_circuit_hash_v1, canonical_circuit_payload
from qshield.core.circuit_ir import CircuitIR, GateNode, GateType
from qshield.core.parsers.qasm_parser import parse_qasm

REPO = Path(__file__).resolve().parents[2]
VECTORS = REPO / "tests" / "vectors" / "canonicalization-v1.json"


def test_public_golden_vectors():
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert vectors["spec"] == CANONICALIZATION_SPEC
    for case in vectors["cases"]:
        ir = parse_qasm(case["source"])
        payload = canonical_circuit_payload(ir)
        assert payload.decode("utf-8") == case["canonical_utf8_json"]
        assert canonical_circuit_hash_v1(ir) == case["sha256"]


def test_non_semantic_metadata_does_not_change_structural_hash():
    original = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nh q[0];\n")
    changed = copy.deepcopy(original)
    changed.name = "renamed"
    changed.source_framework = "different-framework"
    changed.source_hash = "f" * 64
    changed.metadata["annotation"] = "not part of circuit identity"
    changed.gates[0].gate_id = "another-id"
    assert canonical_circuit_hash_v1(original) == canonical_circuit_hash_v1(changed)


def test_gate_order_measurements_and_classical_width_are_identity():
    first = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\nx q[1];\n")
    reordered = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nx q[1];\nh q[0];\n")
    assert canonical_circuit_hash_v1(first) != canonical_circuit_hash_v1(reordered)

    one_bit = parse_qasm("OPENQASM 2.0;\nqreg q[1];\ncreg c[1];\nmeasure q[0] -> c[0];\n")
    two_bits = parse_qasm("OPENQASM 2.0;\nqreg q[1];\ncreg c[2];\nmeasure q[0] -> c[0];\n")
    assert canonical_circuit_hash_v1(one_bit) != canonical_circuit_hash_v1(two_bits)


def test_parameters_are_quantized_to_nine_decimal_places():
    low = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nrz(0.12345678941) q[0];\n")
    same_bucket = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nrz(0.12345678949) q[0];\n")
    next_bucket = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nrz(0.12345678951) q[0];\n")
    assert canonical_circuit_hash_v1(low) == canonical_circuit_hash_v1(same_bucket)
    assert canonical_circuit_hash_v1(low) != canonical_circuit_hash_v1(next_bucket)


def test_non_finite_parameters_and_out_of_range_operands_fail_closed():
    ir = CircuitIR(
        circuit_id="test",
        name="test",
        num_qubits=1,
        num_classical_bits=0,
        gates=[GateNode(gate_id="g0", gate_name="rz", gate_type=GateType.PARAMETERIZED,
                        qubits=[0], parameters=[float("nan")])],
    )
    with pytest.raises(ValueError, match="not finite"):
        canonical_circuit_hash_v1(ir)

    ir.gates[0].parameters = []
    ir.gates[0].qubits = [1]
    with pytest.raises(ValueError, match="outside num_qubits"):
        canonical_circuit_hash_v1(ir)
