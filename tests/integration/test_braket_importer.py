from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest

braket = pytest.importorskip("braket.circuits")

from qshield.core.parsers import parse_any, parse_qasm  # noqa: E402
from qshield.core.parsers.framework_parsers import parse_braket  # noqa: E402


def test_braket_circuit_normalizes_labels_and_preserves_unitary():
    circuit = braket.Circuit().h(4).cnot(4, 6).rz(6, 0.5).measure([4, 6])

    ir = parse_any(circuit)

    assert ir.source_framework == "braket"
    assert ir.num_qubits == 2
    assert ir.metadata["qubit_labels"] == [4, 6]
    assert [gate.gate_name for gate in ir.gates] == ["h", "cx", "rz"]
    assert ir.measurements == [(0, 0), (1, 1)]
    qasm_ir = parse_qasm(
        "OPENQASM 2.0; qreg q[2]; h q[0]; cx q[0], q[1]; rz(0.5) q[1];"
    )
    assert np.allclose(ir.to_unitary(), qasm_ir.to_unitary(), atol=1e-9)


def test_parse_braket_rejects_non_circuit_objects():
    with pytest.raises(TypeError, match="Amazon Braket Circuit"):
        parse_braket(object())


def test_parse_braket_fails_closed_for_unmapped_operator():
    operator = SimpleNamespace(name="UnmappedGate", parameters=[])
    instruction = SimpleNamespace(operator=operator, target=[0])
    circuit = SimpleNamespace(instructions=[instruction])

    with pytest.raises(ValueError, match="refusing to approximate"):
        parse_braket(circuit)
