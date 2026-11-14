"""Synthetic unsupported-construct battery (implementation plan Task 2.2).

Pins the parser's actual, documented behaviour on constructs QShield does not
support, and the emitter's refusal contract. Two failure modes exist by design
— neither may silently change semantics:

**Hard failures** raise :class:`QASMParseError` (never a raw traceback):
malformed sources, resource-cap violations, unsupported OpenQASM 3.0 blocks,
bad expressions, out-of-bounds references.

**Tolerated constructs** parse successfully but are flagged in the IR metadata
so downstream layers can reject or downgrade them honestly:

* ``reset`` → ``metadata["resets"]`` > 0 + warning (circuit is not unitary);
  :func:`emit_qasm` refuses it loudly.
* ``if`` (classical feedback) → ``metadata["conditional_ops"]`` > 0 + warning;
  :func:`emit_qasm` refuses it loudly.
* ``barrier`` → ``metadata["barriers"]`` > 0 (scheduling hint, no unitary
  semantics, not re-emittable).
* Unknown gate name → kept as an opaque ``CUSTOM`` node with no unitary;
  structure round-trips, unitary does not.
* Unrecognised statement → recorded in ``metadata["warnings"]``.

This file is a characterization suite: it pins *actual* behaviour. If the
parser is deliberately tightened in the future, update the expectation here in
the same change — do not let the two drift apart.
"""

import math

import numpy as np
import pytest

from qshield.core.circuit_ir import GateNode, GateType
from qshield.core.parsers import parse_qasm
from qshield.core.parsers.qasm_parser import QASMParseError
from qshield.core.qasm_emitter import QASMEmitError, emit_qasm

# ------------------------------------------------------- hard failures


@pytest.mark.parametrize(
    ("label", "source"),
    [
        ("qasm3_def_block",
         "OPENQASM 3.0;\ndef f() {\n  h $0;\n}\nf();\n"),
        ("duplicate_qreg",
         "OPENQASM 2.0;\nqreg q[1];\nqreg q[2];\n"),
        ("duplicate_creg",
         "OPENQASM 2.0;\ncreg c[1];\ncreg c[2];\n"),
        ("measure_size_mismatch",
         "OPENQASM 2.0;\nqreg q[2];\ncreg c[1];\nmeasure q -> c;\n"),
        ("unknown_expression_name",
         "OPENQASM 2.0;\nqreg q[1];\nrz(bogus) q[0];\n"),
        ("unterminated_gate_block",
         "OPENQASM 2.0;\ngate foo q {\n  h q;\n"),
        ("qubit_out_of_bounds",
         "OPENQASM 2.0;\nqreg q[1];\nh q[9];\n"),
        ("unknown_register_in_measure",
         "OPENQASM 2.0;\ncreg c[1];\nmeasure q -> c;\n"),
        ("arity_mismatch",
         "OPENQASM 2.0;\nqreg q[1];\ncx q[0];\n"),
        ("param_count_mismatch",
         "OPENQASM 2.0;\nqreg q[1];\nrx q[0];\n"),
        ("recursive_gate_definition",
         "OPENQASM 2.0;\n"
         "gate foo q {\n  foo q;\n}\n"
         "qreg q[1];\n"
         "foo q[0];\n"),
    ],
)
def test_hard_failures_raise_qasm_parse_error(label, source):
    with pytest.raises(QASMParseError):
        parse_qasm(source)


def test_source_size_cap_raises():
    source = "OPENQASM 2.0;\nqreg q[1];\n" + "h q[0];\n" * 200_000
    with pytest.raises(QASMParseError, match="size cap"):
        parse_qasm(source, max_source_bytes=1_000)


def test_qubit_cap_raises():
    source = "OPENQASM 2.0;\nqreg q[64];\n"
    with pytest.raises(QASMParseError, match="cap"):
        parse_qasm(source, max_qubits=8)


def test_gate_count_cap_raises():
    source = "OPENQASM 2.0;\nqreg q[1];\n" + "h q[0];\n" * 20
    with pytest.raises(QASMParseError, match="cap"):
        parse_qasm(source, max_gates=4)


def test_time_budget_is_enforced_or_completes():
    # Budget of zero must not hang; tiny inputs may still complete before the
    # clock is checked, so only assert the documented outcome set.
    source = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n"
    try:
        parse_qasm(source, time_budget_s=0.0)
    except QASMParseError as exc:
        assert "time budget" in str(exc)


def test_naive_memory_bomb_is_refused_not_performed():
    # A gate definition expanding to ~2^12 nodes is fine; 2^17 is refused by
    # the expansion cap well before memory is exhausted.
    body = "  h q;\n" * 40
    source = (
        "OPENQASM 2.0;\n"
        f"gate l1 q {{\n{body}}}\n"
        "gate l2 q {\n  l1 q;\n  l1 q;\n}\n"
        "gate l3 q {\n  l2 q;\n  l2 q;\n}\n"
        "gate l4 q {\n  l3 q;\n  l3 q;\n}\n"
        "gate l5 q {\n  l4 q;\n  l4 q;\n}\n"
        "gate l6 q {\n  l5 q;\n  l5 q;\n}\n"
        "qreg q[1];\n"
        "l6 q[0];\n"
    )
    with pytest.raises(QASMParseError, match="cap of"):
        parse_qasm(source, max_gates=1_000)


# ------------------------------------------------- tolerated constructs

def test_reset_is_tolerated_and_flagged():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nreset q[0];\n")
    assert ir.metadata["resets"] == 1
    assert any("not unitary" in w for w in ir.metadata["warnings"])
    with pytest.raises(QASMEmitError, match="reset"):
        emit_qasm(ir)


def test_classical_feedback_is_tolerated_and_flagged():
    ir = parse_qasm(
        "OPENQASM 2.0;\nqreg q[1];\ncreg c[1];\nif (c == 1) x q[0];\n"
    )
    assert ir.metadata["conditional_ops"] == 1
    assert any("conditional" in w for w in ir.metadata["warnings"])
    with pytest.raises(QASMEmitError, match="classical-feedback"):
        emit_qasm(ir)


def test_barrier_is_counted_but_not_emitted():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nbarrier q[0];\nh q[0];\n")
    assert ir.metadata["barriers"] == 1
    text = emit_qasm(ir)
    assert "barrier" not in text
    assert "h q[0];" in text


def test_unknown_gate_becomes_opaque_node():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nfrobnicate q[0];\n")
    assert len(ir.gates) == 1
    assert ir.gates[0].gate_name == "frobnicate"
    assert ir.gates[0].unitary is None
    assert ir.gates[0].gate_type is GateType.CUSTOM
    # structure round-trips; the opaque gate has no unitary to compare
    text = emit_qasm(ir)
    ir2 = parse_qasm(text)
    assert [g.gate_name for g in ir2.gates] == ["frobnicate"]


def test_gate_modifiers_require_known_unitary():
    # Modifiers on gates with no database unitary must fail loudly.
    with pytest.raises(QASMParseError, match="unitary"):
        parse_qasm(
            "OPENQASM 2.0;\n"
            'include "qelib1.inc";\n'
            "qreg q[2];\n"
            "ctrl @ frobnicate q[0], q[1];\n"
        )


def test_unrecognised_statement_is_warned_not_crashed():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nh q[0];\n@@@\n")
    # '@@@' is not a gate call: it is skipped with a warning, not a failure.
    assert any("Unrecognised statement skipped" in w for w in ir.metadata["warnings"])
    assert [g.gate_name for g in ir.gates] == ["h"]


def test_symbolic_parameters_are_a_hard_failure():
    # Parameter expressions with unknown names are a hard failure; symbolic
    # params are not supported anywhere in QShield.
    with pytest.raises(QASMParseError):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\nmygate(a_param) q[0];\n")


# --------------------------------- emitter <-> parser refusal symmetry

def test_emitter_and_parser_agree_on_non_unitary_content():
    source = "OPENQASM 2.0;\nqreg q[1];\nreset q[0];\n"
    ir = parse_qasm(source)
    assert ir.metadata["resets"] == 1
    with pytest.raises(QASMEmitError):
        emit_qasm(ir)


def test_emitter_rejects_non_finite_params_from_modified_ir():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nrz(0.5) q[0];\n")
    ir.gates[0] = GateNode(
        gate_id="g1",
        gate_name="rz",
        gate_type=GateType.PARAMETERIZED,
        qubits=[0],
        parameters=[math.nan],
        unitary=np.eye(2, dtype=complex),
    )
    with pytest.raises(QASMEmitError, match="Non-finite"):
        emit_qasm(ir)


# ------------------------------------- scan pipeline surfaces parser notes

def test_scan_surfaces_non_unitary_parser_notes(tmp_path):
    """A circuit with reset/if must not scan as 'clean with no explanation'."""
    from qshield.scanner import Scanner

    source = (
        "OPENQASM 2.0;\n"
        "qreg q[1];\n"
        "creg c[1];\n"
        "reset q[0];\n"
        "h q[0];\n"
        "if (c == 1) x q[0];\n"
    )
    path = tmp_path / "non_unitary.qasm"
    path.write_text(source)
    scanner = Scanner()
    scanner.add_circuit(str(path))
    results = scanner.run()
    joined = " ".join(results.warnings)
    assert "not unitary" in joined
    assert "classical-feedback" in joined or "conditional" in joined
