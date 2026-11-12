"""Adversarial/robustness tests for the OpenQASM parser (error paths)."""

import pytest

from qshield.core.parsers.qasm_parser import QASMParseError, parse_qasm

BELL = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n"


def test_unterminated_gate_definition():
    with pytest.raises(QASMParseError, match=r"[Uu]nterminated"):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\ngate mygate(p0) q {\n  x q;\n")


def test_gate_definition_with_params_and_indexed_formals():
    ir = parse_qasm(
        "OPENQASM 2.0;\nqreg q[2];\ngate pair(p0, p1) a, b {\n  rz(p0) a;\n  rz(p1) b;\n}\n"
        "pair(0.5, 0.25) q[0], q[1];\n"
    )
    names = [g.gate_name for g in ir.gates]
    assert names == ["rz", "rz"]


def test_gate_definition_invalid_qubit_arg():
    # the regex requires word-like formal args; invalid names don't match the gate-block regex
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\ngate g(p0) 1bad {\n  x q;\n}\n")
    assert ir.gates == []


def test_duplicate_qreg():
    with pytest.raises(QASMParseError, match="Duplicate qreg"):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\nqreg q[2];\n")


def test_duplicate_creg():
    with pytest.raises(QASMParseError, match="Duplicate creg"):
        parse_qasm("OPENQASM 2.0;\ncreg c[1];\ncreg c[2];\n")


def test_qubit_index_out_of_bounds():
    with pytest.raises(QASMParseError, match="out of bounds"):
        parse_qasm("OPENQASM 2.0;\nqreg q[2];\nx q[2];\n")


def test_formal_parameter_indexed():
    with pytest.raises(QASMParseError):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\ngate g(p0) q {\n  x p0[0];\n}\ng q[0];\n")


def test_measure_malformed():
    with pytest.raises(QASMParseError, match="Malformed measure"):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\nmeasure q[0];\n")


def test_unknown_register():
    with pytest.raises(QASMParseError, match="Unknown register"):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\nx r[0];\n")


def test_gate_call_no_arguments():
    # 'h();' has empty args — parser either errors or ignores; must not crash with anything else
    import contextlib

    with contextlib.suppress(QASMParseError):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\nh();\n")


def test_reset_and_conditional_and_barrier_and_opaque():
    ir = parse_qasm(
        "OPENQASM 2.0;\ninclude \"qelib1.inc\";\nqreg q[2];\nbarrier q;\n"
        "reset q[0];\ncreg c[1];\nif (c == 0) x q[1];\n"
    )
    assert ir.metadata["barriers"] == 1
    assert ir.metadata["resets"] == 1
    assert ir.metadata["conditional_ops"] == 1
    assert "qelib1.inc" in ir.metadata["includes"]


def test_if_open_paren_variant():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\ncreg c[1];\nif(c==1) x q[0];\n")
    assert ir.metadata["conditional_ops"] == 1


def test_gate_with_parameters_and_call_by_name():
    ir = parse_qasm(
        "OPENQASM 2.0;\nqreg q[1];\ngate ent(p0) a {\n  h a;\n  rz(p0) a;\n}\nent(0.5) q[0];\n"
    )
    assert any(g.gate_name == "rz" for g in ir.gates)


def test_opaque_gate_skipped_or_opaque():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nopaque mygate(p0) q;\n")
    assert ir.gates == []


def test_measure_register_to_register():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[2];\ncreg c[2];\nmeasure q -> c;\n")
    assert len(ir.measurements) == 2


def test_measure_indexed_both():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[2];\ncreg c[2];\nmeasure q[0] -> c[1];\n")
    assert ir.measurements[0][0] == 0


def test_comment_and_line_continuations():
    ir = parse_qasm("// hello\nOPENQASM 2.0; /* block\ncomment */ qreg q[1];\nx q[0];\n")
    assert any(g.gate_name == "x" for g in ir.gates)


def test_empty_source():
    ir = parse_qasm("")
    assert ir.gates == []


def test_unknown_top_level_statement_raises_or_ignored():
    import contextlib

    with contextlib.suppress(QASMParseError):
        ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\nfoo bar baz;\nx q[0];\n")
        assert any(g.gate_name == "x" for g in ir.gates)


def test_gate_call_out_of_formal_args():
    with pytest.raises(QASMParseError):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\ngate g(p0) q {\n  rx(p0+p1) q;\n}\ng(1.0) q[0];\n")
