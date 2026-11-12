import numpy as np
import pytest

from qshield.core.gate_database import GATE_DB


@pytest.mark.parametrize("name", ["id", "x", "y", "z", "h", "s", "t", "sx", "cx", "cz", "swap", "ccx"])
def test_fixed_gates_are_unitary(name):
    assert GATE_DB.is_unitary(name)


@pytest.mark.parametrize("name,params", [
    ("rx", [0.3]), ("ry", [1.1]), ("rz", [0.785]), ("p", [2.7]),
    ("u1", [1.0]), ("u2", [0.5, 1.5]), ("u3", [0.3, 0.1, 0.2]), ("u", [0.3, 0.1, 0.2]),
    ("crz", [0.4]), ("cp", [1.2]), ("crx", [0.9]), ("cry", [0.7]),
    ("cu3", [0.3, 0.1, 0.2]), ("rxx", [0.8]), ("ryy", [0.8]), ("rzz", [0.8]),
])
def test_parameterized_gates_are_unitary(name, params):
    assert GATE_DB.is_unitary(name, params)


def test_aliases_resolve():
    assert GATE_DB.canon("cnot") == "cx" or GATE_DB.get_spec("cnot") is not None
    assert GATE_DB.get_spec("toffoli") is not None
    assert GATE_DB.get_spec("CNOT") is not None  # case-insensitive


def test_unknown_gate_returns_none():
    assert GATE_DB.matrix("definitely-not-a-gate") is None


def test_bell_matrix_values():
    h = GATE_DB.matrix("h")
    assert np.allclose(h @ h, np.eye(2))
    cx = GATE_DB.matrix("cx")
    assert np.allclose(cx @ cx, np.eye(4))
