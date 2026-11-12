"""OpenQASM 3.0 subset: normalization, $ addressing, gate modifiers."""

import numpy as np
import pytest

from qshield.core.circuit_ir import embed_gate_matrix
from qshield.core.parsers import parse_qasm
from qshield.core.parsers.qasm_parser import QASMParseError

Q3 = "PLACEHOLDER"


def unitary(circuit):
    u = np.eye(2 ** circuit.num_qubits, dtype=complex)
    for g in circuit.gates:
        u = embed_gate_matrix(g.unitary, g.qubits, circuit.num_qubits) @ u
    return u


def test_basic_qasm3_circuit():
    src = """OPENQASM 3.0;
include "stdgates.inc";
qubit[2] q;
bit[2] c;
h q[0];
cx q[0], q[1];
c[0] = measure q[0];
measure q[1] -> c[1];
"""
    cir = parse_qasm(src)
    assert cir.source_framework == "qasm3.0"
    assert [g.gate_name for g in cir.gates] == ["h", "cx"]
    assert cir.measurements == [(0, 0), (1, 1)]


def test_whole_register_assignment_measure():
    src = """OPENQASM 3.0;
qubit[2] q;
bit[2] c;
h q[0];
c = measure q;
"""
    cir = parse_qasm(src)
    assert cir.measurements == [(0, 0), (1, 1)]


def test_dollar_addressing_single_register():
    cir = parse_qasm("OPENQASM 3.0;\nqubit[3] q;\nh $0;\ncx $0, $2;\n")
    assert [g.qubits for g in cir.gates] == [[0], [0, 2]]


def test_dollar_addressing_multiple_registers_rejected():
    with pytest.raises(QASMParseError, match="\$i"):
        parse_qasm("OPENQASM 3.0;\nqubit[1] q;\nqubit[1] r;\nh $0;\n")


def test_qasm3_gate_equivalent_to_qasm2():
    q2 = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\ns q[1];\nt q[0];\n")
    q3 = parse_qasm("OPENQASM 3.0;\nqubit[2] q;\nh q[0];\ncx q[0], q[1];\ns q[1];\nt q[0];\n")
    assert np.allclose(unitary(q2), unitary(q3))


def test_ctrl_modifier_matches_controlled_gate():
    mod = parse_qasm("OPENQASM 3.0;\nqubit[2] q;\nctrl @ rz(0.5) q[0], q[1];\n")
    ref = parse_qasm("OPENQASM 3.0;\nqubit[2] q;\ncrz(0.5) q[0], q[1];\n")
    assert np.allclose(mod.gates[0].unitary, ref.gates[0].unitary)


def test_inv_modifier_matches_inverse_gate():
    mod = parse_qasm("OPENQASM 3.0;\nqubit[1] q;\ninv @ s q[0];\n")
    ref = parse_qasm("OPENQASM 3.0;\nqubit[1] q;\nsdg q[0];\n")
    assert np.allclose(mod.gates[0].unitary, ref.gates[0].unitary)


def test_stacked_modifiers():
    mod = parse_qasm("OPENQASM 3.0;\nqubit[2] q;\nctrl @ inv @ z q[0], q[1];\n")
    ref = parse_qasm("OPENQASM 3.0;\nqubit[2] q;\ncz q[0], q[1];\n")
    assert np.allclose(mod.gates[0].unitary, ref.gates[0].unitary)


def test_modifier_arity_validation():
    with pytest.raises(QASMParseError, match="acts on 3"):
        parse_qasm("OPENQASM 3.0;\nqubit[2] q;\nctrl @ cx q[0], q[1];\n")


def test_modifier_on_unknown_gate_rejected():
    with pytest.raises(QASMParseError, match="gate-database unitary"):
        parse_qasm("OPENQASM 3.0;\nqubit[1] q;\ninv @ notagate_xyz q[0];\n")


def test_def_block_rejected_with_clear_error():
    with pytest.raises(QASMParseError, match="def"):
        parse_qasm("OPENQASM 3.0;\nqubit[1] q;\ndef mygate(a) (qubit q) { x q; }\n")


def test_const_and_classical_decls_skipped_with_warning():
    cir = parse_qasm("OPENQASM 3.0;\nqubit[1] q;\nconst int N = 3;\nh q[0];\n")
    assert [g.gate_name for g in cir.gates] == ["h"]
    assert any("const" in w for w in cir.metadata["warnings"])


def test_pi_expression_in_modifier():
    cir = parse_qasm("OPENQASM 3.0;\nqubit[2] q;\nctrl @ rz(pi/2) q[0], q[1];\n")
    assert cir.gates[0].parameters[0] == pytest.approx(np.pi / 2)


def test_qasm3_file_round_trip(tmp_path):
    p = tmp_path / "demo.qasm3"
    p.write_text('OPENQASM 3.0;\nqubit[1] q;\nh q[0];\n')
    from qshield.core.parsers import parse_file

    cir = parse_file(p)
    assert [g.gate_name for g in cir.gates] == ["h"]
