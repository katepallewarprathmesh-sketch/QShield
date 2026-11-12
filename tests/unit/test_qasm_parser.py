import numpy as np
import pytest

from qshield.core.parsers import parse_qasm
from qshield.core.parsers.qasm_parser import QASMParseError


def test_parse_bell():
    circuit = parse_qasm("""OPENQASM 2.0;
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
measure q -> c;
""")
    assert circuit.num_qubits == 2
    assert circuit.num_classical_bits == 2
    assert [g.gate_name for g in circuit.gates] == ["h", "cx"]
    assert circuit.measurements == [(0, 0), (1, 1)]


def test_parameter_expressions():
    circuit = parse_qasm("""OPENQASM 2.0;
qreg q[1];
rz(pi/4) q[0];
rx(2*pi) q[0];
""")
    assert circuit.gates[0].parameters[0] == pytest.approx(np.pi / 4)
    assert circuit.gates[1].parameters[0] == pytest.approx(2 * np.pi)


def test_whole_register_measure():
    circuit = parse_qasm("""OPENQASM 2.0;
qreg q[3];
creg c[3];
x q[0];
measure q -> c;
""")
    assert circuit.measurements == [(0, 0), (1, 1), (2, 2)]


def test_custom_gate_expansion():
    circuit = parse_qasm("""OPENQASM 2.0;
qreg q[2];
gate bell a, b {
    h a;
    cx a, b;
}
bell q[0], q[1];
""")
    assert [g.gate_name for g in circuit.gates] == ["h", "cx"]
    assert circuit.gates[0].qubits == [0]
    assert circuit.gates[1].qubits == [0, 1]


def test_custom_gate_with_params():
    circuit = parse_qasm("""OPENQASM 2.0;
qreg q[1];
gate doubler(theta) a {
    rz(theta) a;
    rz(theta) a;
}
doubler(0.25) q[0];
""")
    assert [g.parameters[0] for g in circuit.gates] == [0.25, 0.25]


def test_comments_and_includes():
    circuit = parse_qasm("""OPENQASM 2.0;
// a comment
include "qelib1.inc";
/* not supported but harmless? no - unsupported statements are warnings */
qreg q[1];
x q[0]; // trailing comment
""")
    assert circuit.num_qubits == 1
    assert "qelib1.inc" in circuit.metadata.get("includes", [])


def test_invalid_qubit_index():
    with pytest.raises(QASMParseError):
        parse_qasm("""OPENQASM 2.0;
qreg q[1];
x q[5];
""")


def test_measure_size_mismatch():
    with pytest.raises(QASMParseError):
        parse_qasm("""OPENQASM 2.0;
qreg q[2];
creg c[1];
measure q -> c;
""")


def test_empty_parameters():
    with pytest.raises(QASMParseError):
        parse_qasm("""OPENQASM 2.0;
qreg q[1];
rz() q[0];
""")


def test_unknown_gate_kept_without_unitary():
    circuit = parse_qasm("""OPENQASM 2.0;
qreg q[2];
frobnicate q[0], q[1];
""")
    assert circuit.gates[0].gate_name == "frobnicate"
    assert circuit.gates[0].unitary is None
    assert circuit.to_unitary() is None
