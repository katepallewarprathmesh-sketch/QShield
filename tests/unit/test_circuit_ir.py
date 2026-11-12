import numpy as np

from qshield.core.circuit_ir import embed_gate_matrix
from qshield.core.parsers import parse_qasm

BELL = """OPENQASM 2.0;
qreg q[2];
creg c[2];
h q[0];
cx q[0], q[1];
measure q -> c;
"""


def test_embed_single_qubit_msb():
    h = (1 / np.sqrt(2)) * np.array([[1, 1], [1, -1]], dtype=complex)
    full = embed_gate_matrix(h, [1], 2)
    assert np.allclose(full, np.kron(np.eye(2), h))  # qubit 1 = LSB
    full0 = embed_gate_matrix(h, [0], 2)
    assert np.allclose(full0, np.kron(h, np.eye(2)))  # qubit 0 = MSB


def test_embed_cnot():
    from qshield.core.gate_database import GATE_DB
    cnot = GATE_DB.matrix("cx")
    full = embed_gate_matrix(cnot, [0, 1], 2)
    assert np.allclose(full, cnot)
    # reversed direction: control on q[1], target on q[0]
    full_rev = embed_gate_matrix(cnot, [1, 0], 2)
    expected = np.array([[1, 0, 0, 0], [0, 0, 0, 1], [0, 0, 1, 0], [0, 1, 0, 0]], dtype=complex)
    assert np.allclose(full_rev, expected)


def test_bell_unitary_is_bell_matrix():
    circuit = parse_qasm(BELL.replace("measure q -> c;", ""))
    u = circuit.to_unitary()
    h = (1 / np.sqrt(2)) * np.array([[1, 1], [1, -1]], dtype=complex)
    cnot = np.array([[1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 0, 1], [0, 0, 1, 0]], dtype=complex)
    expected = cnot @ np.kron(h, np.eye(2))
    assert np.allclose(u, expected)
    # and it really builds |00> + |11>
    out = u @ np.array([1, 0, 0, 0], dtype=complex)
    assert np.allclose(out, np.array([1, 0, 0, 1]) / np.sqrt(2))


def test_gate_count_and_usage():
    circuit = parse_qasm(BELL)
    counts = circuit.get_gate_count()
    assert counts == {"h": 1, "cx": 1}
    usage = circuit.get_qubit_usage()
    assert usage == {0: 2, 1: 1}


def test_depth():
    circuit = parse_qasm(BELL)
    assert circuit.get_depth() == 2


def test_measurements_parsed():
    circuit = parse_qasm(BELL)
    assert circuit.measurements == [(0, 0), (1, 1)]


def test_entanglement_map():
    circuit = parse_qasm(BELL)
    assert circuit.get_entanglement_map() == {(0, 1): 1}


def test_source_hash_stable():
    a = parse_qasm(BELL)
    b = parse_qasm(BELL)
    assert a.source_hash == b.source_hash


def test_to_dict_keys():
    circuit = parse_qasm(BELL)
    d = circuit.to_dict()
    for key in ("circuit_id", "num_qubits", "gate_counts", "depth", "measurements", "source_hash"):
        assert key in d
