"""Optional parsers for quantum framework circuit objects.

Each parser converts a framework-native circuit into the framework-agnostic
:class:`qshield.core.circuit_ir.CircuitIR`.  Frameworks are imported lazily so
QSHIELD works with any subset of them installed.
"""

from __future__ import annotations

import hashlib
import math
import uuid
from typing import Any

from qshield.core.circuit_ir import CircuitIR, GateNode, GateType
from qshield.core.gate_database import GATE_DB

# Framework gate name -> canonical qshield name
_QISKIT_NAME_MAP = {
    "id": "id", "iden": "id", "output": "id",
    "x": "x", "y": "y", "z": "z", "h": "h", "s": "s", "sdg": "sdg",
    "t": "t", "tdg": "tdg", "sx": "sx", "sxdg": "sxdg",
    "rx": "rx", "ry": "ry", "rz": "rz", "p": "p", "u": "u3", "u1": "u1",
    "u2": "u2", "u3": "u3",
    "cx": "cx", "cy": "cy", "cz": "cz", "ch": "ch", "swap": "swap",
    "crz": "crz", "cp": "cp", "cu1": "cu1", "crx": "crx", "cry": "cry",
    "cu3": "cu3", "cu": "cu3",
    "rxx": "rxx", "ryy": "ryy", "rzz": "rzz",
    "ccx": "ccx", "ccz": "ccz",
}

_CIRQ_CLASS_MAP = {
    "HPowGate": lambda g: "h" if g.exponent == 1 else None,
    "XPowGate": None,  # handled via global_shift logic below
    "YPowGate": None,
    "ZPowGate": None,
    "SGate": lambda g: "s",
    "TGate": lambda g: "t",
    "CNotPowGate": lambda g: "cx" if g.exponent == 1 else None,
    "CZPowGate": lambda g: "cz" if g.exponent == 1 else None,
    "SwapPowGate": lambda g: "swap" if g.exponent == 1 else None,
    "CCXPowGate": lambda g: "ccx" if g.exponent == 1 else None,
}


def _float_or_nan(value: Any) -> float:
    try:
        import numpy as np  # local import to keep module light
        if isinstance(value, np.ndarray):
            if value.size == 1:
                return float(value.reshape(-1)[0])
            return float("nan")
    except Exception:  # numpy unavailable or conversion failed; fall through to float()
        import warnings
        warnings.warn("qshield: numeric parameter could not be read as a float; treating as symbolic", stacklevel=2)
    try:
        return float(value)
    except Exception:
        return float("nan")


def _build_ir(
    name: str,
    source_framework: str,
    num_qubits: int,
    num_clbits: int,
    ops: list[tuple[str, list[float], list[int]]],
    measurements: list[tuple[int, int]],
    metadata: dict,
    source_repr: str,
) -> CircuitIR:
    gates: list[GateNode] = []
    for i, (gname, params, qubits) in enumerate(ops):
        canonical = GATE_DB.canon(_QISKIT_NAME_MAP.get(gname.lower(), gname.lower()))
        spec = GATE_DB.get_spec(canonical)
        if spec is not None:
            gtype = GateType.PARAMETERIZED if spec.is_parameterized else GateType.STANDARD
        else:
            gtype = GateType.CUSTOM
        gates.append(GateNode(
            gate_id=f"g{i + 1:05d}",
            gate_name=canonical,
            gate_type=gtype,
            qubits=list(qubits),
            parameters=list(params),
            unitary=GATE_DB.matrix(canonical, params),
            source_location=f"{name} gate[{i}]",
        ))
    dag: dict[str, list[str]] = {}
    last_on_qubit: dict[int, str] = {}
    for g in gates:
        preds = {last_on_qubit[q] for q in g.qubits if q in last_on_qubit}
        for p in preds:
            dag.setdefault(p, []).append(g.gate_id)
        for q in g.qubits:
            last_on_qubit[q] = g.gate_id
    return CircuitIR(
        circuit_id=f"circ-{uuid.uuid4().hex[:12]}",
        name=name,
        num_qubits=num_qubits,
        num_classical_bits=num_clbits,
        gates=gates,
        dag=dag,
        measurements=measurements,
        source_framework=source_framework,
        source_hash=hashlib.sha256(source_repr.encode("utf-8")).hexdigest(),
        metadata=metadata,
    )


# ----------------------------------------------------------------------
# Qiskit
# ----------------------------------------------------------------------

def parse_qiskit(circuit: Any, name: str | None = None) -> CircuitIR:
    try:
        from qiskit import QuantumCircuit  # noqa: F401
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            "qiskit is not installed. Install with: pip install 'qshield[qiskit]'"
        ) from exc

    name = name or getattr(circuit, "name", None) or "qiskit_circuit"
    ops: list[tuple[str, list[float], list[int]]] = []
    measurements: list[tuple[int, int]] = []
    symbolic: list[str] = []
    resets = 0

    for instr in circuit.data:
        op = instr.operation
        qargs = [circuit.find_bit(q).index for q in instr.qubits]
        cargs = [circuit.find_bit(c).index for c in instr.clbits]
        opname = op.name.lower()
        if opname in ("measure", "measure_all"):
            if opname == "measure" and qargs and cargs:
                measurements.append((qargs[0], cargs[0]))
            continue
        if opname in ("barrier",):
            continue
        if opname in ("reset", "store"):
            resets += 1
            continue
        params: list[float] = []
        for p in op.params:
            value = _float_or_nan(p)
            if math.isnan(value):  # NaN -> symbolic parameter
                symbolic.append(str(p))
            params.append(value)
        ops.append((opname, params, qargs))

    return _build_ir(
        name=name,
        source_framework="qiskit",
        num_qubits=circuit.num_qubits,
        num_clbits=circuit.num_clbits,
        ops=ops,
        measurements=measurements,
        metadata={"qshield_symbolic_params": symbolic, "source": "qiskit", "resets": resets},
        source_repr=repr(circuit),
    )


# ----------------------------------------------------------------------
# Cirq
# ----------------------------------------------------------------------

def parse_cirq(circuit: Any, name: str | None = None) -> CircuitIR:
    try:
        import cirq  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "cirq-core is not installed. Install with: pip install 'qshield[cirq]'"
        ) from exc

    name = name or "cirq_circuit"
    qubits = sorted(circuit.all_qubits())
    qubit_index = {q: i for i, q in enumerate(qubits)}
    ops: list[tuple[str, list[float], list[int]]] = []
    measurements: list[tuple[int, int]] = []

    for moment in circuit:
        for op in moment.operations:
            op_qubits = [qubit_index[q] for q in op.qubits]
            gate = op.gate
            cls = type(gate).__name__ if gate is not None else ""
            if cls == "" and op.gate is None:
                # measurement operation
                measurements.extend((qubit_index[q], i) for i, q in enumerate(op.qubits))
                continue
            if cls == "MeasurementGate":
                measurements.extend((qubit_index[q], i) for i, q in enumerate(op.qubits))
                continue
            gname, params = _cirq_gate_to_name(gate)
            if gname is None:
                gname = cls.replace("PowGate", "").lower() if cls else "unknown"
            ops.append((gname, params, op_qubits))

    return _build_ir(
        name=name,
        source_framework="cirq",
        num_qubits=len(qubits),
        num_clbits=len(measurements),
        ops=ops,
        measurements=measurements,
        metadata={"source": "cirq"},
        source_repr=repr(circuit),
    )


def _cirq_gate_to_name(gate: Any) -> tuple[str | None, list[float]]:
    import sympy

    cls = type(gate).__name__
    # Exponent-based rotation gates
    exp = getattr(gate, "exponent", None)
    gshift = getattr(gate, "global_shift", None)
    if cls in ("XPowGate", "YPowGate", "ZPowGate", "Rx", "Ry", "Rz"):
        axis = cls[-1].lower()
        exp_f = float(sympy.N(exp)) if exp is not None else 1.0
        shift_f = float(sympy.N(gshift)) if gshift is not None else 0.0
        if shift_f == -0.5:
            # RotationGate convention: exponent = theta / pi
            return f"r{axis}", [exp_f * 3.141592653589793]
        if axis == "x" and exp_f == 1.0:
            return "x", []
        if axis == "y" and exp_f == 1.0:
            return "y", []
        if axis == "z" and exp_f == 1.0:
            return "z", []
        if axis == "x" and exp_f == 0.5:
            return "sx", []
        return f"r{axis}", [exp_f * 3.141592653589793]
    if cls == "HPowGate":
        return (("h", []) if float(sympy.N(exp)) == 1.0 else (None, []))
    if cls == "SGate":
        return "s", []
    if cls == "TGate":
        return "t", []
    if cls in ("CNotPowGate", "CXPowGate"):
        return "cx", []
    if cls == "CZPowGate":
        return "cz", []
    if cls == "SwapPowGate":
        return "swap", []
    if cls == "CCXPowGate":
        return "ccx", []
    if hasattr(gate, "parameters_by_name"):
        # generic fallback: stringify class name
        return cls.lower().replace("gate", ""), [
            float(sympy.N(v)) for v in gate.parameters_by_name.values()
        ]
    return None, []


# ----------------------------------------------------------------------
# PennyLane
# ----------------------------------------------------------------------

_PENNYLANE_NAME_MAP = {
    "Hadamard": "h", "PauliX": "x", "PauliY": "y", "PauliZ": "z",
    "S": "s", "SWAP": "swap", "CNOT": "cx", "CZ": "cz", "Toffoli": "ccx",
    "RX": "rx", "RY": "ry", "RZ": "rz", "Rot": "u3", "PhaseShift": "p",
    "CRX": "crx", "CRY": "cry", "CRZ": "crz", "ControlledPhaseShift": "cp",
    "IsingXX": "rxx", "IsingYY": "ryy", "IsingZZ": "rzz",
    "Identity": "id",
}


def parse_pennylane(tape_or_qnode: Any, name: str | None = None) -> CircuitIR:
    """Parse a PennyLane ``QuantumScript`` (or compatible) into CircuitIR.

    QNodes are not executed; build a tape first, e.g.::

        tape = qml.tape.make_qscript(my_circuit)(params)
    """
    try:
        import pennylane as qml  # noqa: F401
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "pennylane is not installed. Install with: pip install 'qshield[pennylane]'"
        ) from exc

    tape = tape_or_qnode
    if not hasattr(tape, "operations"):
        raise TypeError(
            "parse_pennylane expects a PennyLane QuantumScript/tape. "
            "Build one with qml.tape.make_qscript(qnode)(*args)."
        )

    name = name or "pennylane_circuit"
    num_qubits = max(
        (int(w) + 1 for op in list(tape.operations) for w in getattr(op, "wires", [])),
        default=0,
    )
    ops: list[tuple[str, list[float], list[int]]] = []
    for op in tape.operations:
        oname = type(op).__name__
        canonical = _PENNYLANE_NAME_MAP.get(oname, oname.lower())
        params = [_float_or_nan(p) for p in getattr(op, "parameters", [])]
        qubits = [int(w) for w in getattr(op, "wires", [])]
        ops.append((canonical, params, qubits))

    measurements: list[tuple[int, int]] = [
        (int(w), i)
        for i, op in enumerate(getattr(tape, "measurements", []))
        for w in getattr(op, "wires", [])
    ]

    return _build_ir(
        name=name,
        source_framework="pennylane",
        num_qubits=num_qubits,
        num_clbits=len(measurements),
        ops=ops,
        measurements=measurements,
        metadata={"source": "pennylane"},
        source_repr=repr(tape),
    )
