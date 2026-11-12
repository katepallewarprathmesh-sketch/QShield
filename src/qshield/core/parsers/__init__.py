"""Parsers converting quantum circuit sources into CircuitIR."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from qshield.core.circuit_ir import CircuitIR
from qshield.core.parsers.qasm_parser import QASMParseError, parse_qasm

__all__ = [
    "QASMParseError",
    "parse_any",
    "parse_cirq",
    "parse_file",
    "parse_pennylane",
    "parse_qasm",
    "parse_qiskit",
]


def parse_qiskit(*args, **kwargs):
    from qshield.core.parsers.framework_parsers import parse_qiskit as _p
    return _p(*args, **kwargs)


def parse_cirq(*args, **kwargs):
    from qshield.core.parsers.framework_parsers import parse_cirq as _p
    return _p(*args, **kwargs)


def parse_pennylane(*args, **kwargs):
    from qshield.core.parsers.framework_parsers import parse_pennylane as _p
    return _p(*args, **kwargs)


def parse_any(obj: Any, name: str | None = None) -> CircuitIR:
    """Best-effort conversion of a supported object into CircuitIR.

    Supported inputs: QASM source strings (starting with ``OPENQASM``),
    Qiskit ``QuantumCircuit``, Cirq ``Circuit``, PennyLane tapes.
    """
    if isinstance(obj, CircuitIR):
        return obj
    if isinstance(obj, str):
        if obj.lstrip().upper().startswith("OPENQASM"):
            return parse_qasm(obj, name=name or "string_circuit")
        # treat as a file path
        return parse_file(obj, name=name)
    module = type(obj).__module__.split(".")[0]
    if module == "qiskit":
        return parse_qiskit(obj, name=name)
    if module == "cirq":
        return parse_cirq(obj, name=name)
    if module == "pennylane":
        return parse_pennylane(obj, name=name)
    raise TypeError(
        f"Unsupported circuit object of type {type(obj)!r}. "
        "Pass an OpenQASM 2.0 string, a file path, or a Qiskit/Cirq/PennyLane circuit."
    )


def parse_file(path: str | Path, name: str | None = None) -> CircuitIR:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Circuit file not found: {path}")
    source = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    if suffix in (".qasm", ".qasm2", ".qasm3", ".q"):
        circuit = parse_qasm(source, name=name or path.stem)
        circuit.metadata["source_file"] = str(path)
        return circuit
    raise ValueError(
        f"Unsupported circuit file extension {suffix!r}. "
        "Expected .qasm (OpenQASM 2.0). For framework circuits, use the Python API: "
        "qshield.Scanner().add_circuit(circuit_object)"
    )
