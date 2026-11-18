"""pytket importer tests use small API-shaped fakes; pytket stays optional."""

import sys
from dataclasses import dataclass
from types import ModuleType, SimpleNamespace

import numpy as np
import pytest

from qshield.core.parsers import parse_any, parse_pytket, parse_qasm


@dataclass(frozen=True)
class _UnitId:
    register: str
    index: tuple[int, ...]

    def __str__(self):
        return f"{self.register}[{','.join(map(str, self.index))}]"


@dataclass
class _Operation:
    type: SimpleNamespace
    params: list[float]


@dataclass
class _Command:
    op: _Operation
    qubits: list[_UnitId]
    bits: list[_UnitId]


class _FakePytketCircuit:
    __module__ = "pytket.circuit"

    def __init__(self, commands):
        self.qubits = [_UnitId("data", (4,)), _UnitId("data", (9,))]
        self.bits = [_UnitId("readout", (0,)), _UnitId("readout", (1,))]
        self.name = "fake"
        self._commands = commands

    def get_commands(self):
        return list(self._commands)

    def __repr__(self):
        return "FakePytketCircuit"


def _op(name, params=()):
    return _Operation(SimpleNamespace(name=name), list(params))


def _install_fake_pytket(monkeypatch):
    package = ModuleType("pytket")
    package.__path__ = []
    circuit = ModuleType("pytket.circuit")
    circuit.Circuit = _FakePytketCircuit
    monkeypatch.setitem(sys.modules, "pytket", package)
    monkeypatch.setitem(sys.modules, "pytket.circuit", circuit)


def test_pytket_angle_units_register_order_and_parse_any(monkeypatch):
    _install_fake_pytket(monkeypatch)
    circuit = _FakePytketCircuit([
        _Command(_op("H"), [ _UnitId("data", (4,)) ], []),
        _Command(_op("Rx", [0.5]), [_UnitId("data", (4,))], []),
        _Command(_op("CX"), [_UnitId("data", (4,)), _UnitId("data", (9,))], []),
        _Command(_op("Measure"), [_UnitId("data", (9,))], [_UnitId("readout", (1,))]),
    ])

    ir = parse_any(circuit)
    reference = parse_qasm(
        "OPENQASM 2.0; qreg q[2]; h q[0]; rx(1.5707963267948966) q[0]; cx q[0], q[1];"
    )
    assert ir.source_framework == "pytket"
    assert [gate.gate_name for gate in ir.gates] == ["h", "rx", "cx"]
    assert ir.gates[1].parameters == pytest.approx([np.pi / 2])
    assert ir.measurements == [(1, 1)]
    assert ir.metadata["qubit_labels"] == ["data[4]", "data[9]"]
    assert ir.metadata["bit_labels"] == ["readout[0]", "readout[1]"]
    assert np.allclose(ir.to_unitary(), reference.to_unitary(), atol=1e-9)


def test_pytket_v_gates_preserve_exact_matrix_not_only_global_phase(monkeypatch):
    _install_fake_pytket(monkeypatch)
    q0 = _UnitId("data", (4,))
    ir = parse_pytket(_FakePytketCircuit([
        _Command(_op("V"), [q0], []),
        _Command(_op("Vdg"), [q0], []),
    ]))
    assert [gate.gate_name for gate in ir.gates] == ["rx", "rx"]
    assert [gate.parameters[0] for gate in ir.gates] == pytest.approx([np.pi / 2, -np.pi / 2])
    reference = parse_qasm(
        "OPENQASM 2.0; qreg q[2]; rx(1.5707963267948966) q[0]; rx(-1.5707963267948966) q[0];"
    )
    assert np.allclose(ir.to_unitary(), reference.to_unitary(), atol=1e-9)


def test_pytket_reset_and_global_phase_are_not_silently_discarded(monkeypatch):
    _install_fake_pytket(monkeypatch)
    circuit = _FakePytketCircuit([
        _Command(_op("Reset"), [_UnitId("data", (4,))], []),
        _Command(_op("Phase", [0.25]), [], []),
    ])
    ir = parse_pytket(circuit)
    assert ir.metadata["resets"] == 1
    assert ir.metadata["global_phase_half_turns"] == ["0.25"]
    assert any("reset operations" in warning for warning in ir.metadata["warnings"])
    assert any("global phase" in warning for warning in ir.metadata["warnings"])


def test_pytket_unsupported_operations_and_bad_arity_fail_closed(monkeypatch):
    _install_fake_pytket(monkeypatch)
    q0 = _UnitId("data", (4,))
    with pytest.raises(ValueError, match="refusing to approximate"):
        parse_pytket(_FakePytketCircuit([_Command(_op("Conditional"), [q0], [])]))
    with pytest.raises(ValueError, match="arity"):
        parse_pytket(_FakePytketCircuit([_Command(_op("CX"), [q0], [])]))
    with pytest.raises(ValueError, match="parameters"):
        parse_pytket(_FakePytketCircuit([_Command(_op("Rx"), [q0], [])]))


def test_real_pytket_circuit_when_optional_extra_is_installed():
    pytket_circuit = pytest.importorskip("pytket.circuit")
    circuit = pytket_circuit.Circuit(2, 2)
    circuit.H(0)
    circuit.Rx(0.5, 0)
    circuit.CX(0, 1)
    circuit.Measure(1, 1)

    ir = parse_any(circuit)
    assert ir.source_framework == "pytket"
    assert [gate.gate_name for gate in ir.gates] == ["h", "rx", "cx"]
    assert ir.gates[1].parameters == pytest.approx([np.pi / 2])
    assert ir.measurements == [(1, 1)]


def test_pytket_import_dependency_error_is_actionable(monkeypatch):
    monkeypatch.setitem(sys.modules, "pytket", None)
    monkeypatch.setitem(sys.modules, "pytket.circuit", None)
    with pytest.raises(RuntimeError, match=r"pip install 'qshield\[pytket\]'"):
        parse_pytket(object())
