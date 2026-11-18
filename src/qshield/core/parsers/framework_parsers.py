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
    # extended standard gates (identical canonical names)
    "r": "r", "rzx": "rzx",
    "cs": "cs", "csdg": "csdg", "csx": "csx", "csxdg": "csxdg",
    "iswap": "iswap", "iswapdg": "iswapdg", "sqrt_iswap": "sqrt_iswap",
    "sycamore": "sycamore", "fsim": "fsim",
    "c3x": "c3x", "c3z": "c3z", "c4x": "c4x", "c4z": "c4z",
    "cu2": "cu2", "cu2dg": "cu2dg", "cu3dg": "cu3dg", "u2dg": "u2dg",
    "u1dg": "u1dg", "u3dg": "u3dg", "rxdg": "rxdg", "rydg": "rydg",
    "rzdg": "rzdg", "pdg": "pdg", "cpdg": "cpdg", "crxdg": "crxdg",
    "crydg": "crydg", "crzdg": "crzdg",
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
                # mark unmapped powers as opaque: never impersonate a known gate
                gname = f"{cls.replace('PowGate', '').lower()}_pow" if cls else "unknown"
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
        axis = cls[0].lower() if cls in ("XPowGate", "YPowGate", "ZPowGate") else cls[-1].lower()
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
    if cls in ("_PauliX", "_PauliY", "_PauliZ"):
        return cls[-1].lower(), []
    if cls == "_PauliI":
        return "id", []
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


def parse_braket(circuit: Any, name: str | None = None) -> CircuitIR:
    """Parse an Amazon Braket ``Circuit`` into CircuitIR.

    Qubit labels are normalized to dense zero-based indices and retained in
    metadata. Unsupported operators raise rather than being approximated.
    """
    try:
        from braket.circuits import Circuit  # noqa: F401
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "amazon-braket-sdk is not installed. Install with: pip install 'qshield[braket]'"
        ) from exc

    if not hasattr(circuit, "instructions"):
        raise TypeError("parse_braket expects an Amazon Braket Circuit with instructions")

    name = name or getattr(circuit, "name", None) or "braket_circuit"
    instructions = list(circuit.instructions)
    qubit_labels: set[int] = set()
    for instruction in instructions:
        for target in _braket_targets(instruction):
            qubit_labels.add(_braket_qubit_label(target))
    ordered_labels = sorted(qubit_labels)
    qubit_map = {label: index for index, label in enumerate(ordered_labels)}
    ops: list[tuple[str, list[float], list[int]]] = []
    measurements: list[tuple[int, int]] = []
    next_classical = 0

    gate_names = {
        "i": "id", "identity": "id", "h": "h", "x": "x", "y": "y", "z": "z",
        "s": "s", "si": "sdg", "sdg": "sdg", "t": "t", "ti": "tdg", "tdg": "tdg",
        "v": "sx", "vi": "sxdg", "rx": "rx", "ry": "ry", "rz": "rz",
        "phaseshift": "p", "cnot": "cx", "cx": "cx", "cy": "cy", "cz": "cz",
        "swap": "swap", "iswap": "iswap", "cphaseshift": "cp",
        "xx": "rxx", "yy": "ryy", "zz": "rzz", "ccnot": "ccx", "toffoli": "ccx",
    }
    structural_ops = {"startverbatimbox", "endverbatimbox"}

    for instruction in instructions:
        operator = instruction.operator
        operator_name = str(getattr(operator, "name", type(operator).__name__))
        normalized = "".join(char for char in operator_name.lower() if char.isalnum())
        targets = [_braket_qubit_label(target) for target in _braket_targets(instruction)]
        if normalized in structural_ops:
            continue
        if normalized == "measure":
            for target in targets:
                measurements.append((qubit_map[target], next_classical))
                next_classical += 1
            continue
        canonical = gate_names.get(normalized)
        if canonical is None:
            raise ValueError(
                f"unsupported Amazon Braket operator {operator_name!r}; refusing to approximate it"
            )
        parameters = [_float_or_nan(value) for value in getattr(operator, "parameters", [])]
        ops.append((canonical, parameters, [qubit_map[target] for target in targets]))

    return _build_ir(
        name=name,
        source_framework="braket",
        num_qubits=len(ordered_labels),
        num_clbits=next_classical,
        ops=ops,
        measurements=measurements,
        metadata={"source": "amazon-braket", "qubit_labels": ordered_labels},
        source_repr=repr(circuit),
    )


def _braket_targets(instruction: Any) -> list[Any]:
    target = getattr(instruction, "target", ())
    try:
        return list(target)
    except TypeError:
        return [target]


def _braket_qubit_label(qubit: Any) -> int:
    label = getattr(qubit, "index", qubit)
    try:
        return int(label)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"unsupported Amazon Braket qubit label {qubit!r}") from exc


# ----------------------------------------------------------------------
# pytket
# ----------------------------------------------------------------------

_PYTKET_NAME_MAP = {
    "noop": "id", "i": "id", "x": "x", "y": "y", "z": "z", "h": "h",
    "s": "s", "sdg": "sdg", "t": "t", "tdg": "tdg", "v": "rx", "vdg": "rx",
    "sx": "sx", "sxdg": "sxdg", "rx": "rx", "ry": "ry", "rz": "rz",
    "u1": "u1", "u2": "u2", "u3": "u3", "u": "u3",
    "cx": "cx", "cnot": "cx", "cy": "cy", "cz": "cz", "ch": "ch", "swap": "swap",
    "crx": "crx", "cry": "cry", "crz": "crz", "cu1": "cu1", "cu3": "cu3",
    "cphase": "cp", "cp": "cp", "xxphase": "rxx", "yyphase": "ryy", "zzphase": "rzz",
    "fsim": "fsim", "sycamore": "sycamore",
    "ccx": "ccx", "ccnot": "ccx", "toffoli": "ccx", "ccz": "ccz",
    "c3x": "c3x", "c3z": "c3z", "c4x": "c4x", "c4z": "c4z",
    "cs": "cs", "csdg": "csdg", "csx": "csx", "csxdg": "csxdg",
    "iswap": "iswap", "iswapdg": "iswapdg", "sqrtiswap": "sqrt_iswap",
    "rzx": "rzx",
}


def parse_pytket(circuit: Any, name: str | None = None) -> CircuitIR:
    """Parse a pytket ``Circuit`` into CircuitIR without executing it.

    pytket rotation parameters use half-turns (multiples of pi), so numeric
    parameters are converted to radians. Measurements are preserved; reset
    and global-phase operations are omitted with explicit parser warnings.
    Unsupported/classically conditioned operations fail closed.
    """
    try:
        from pytket.circuit import Circuit  # noqa: F401
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "pytket is not installed. Install with: pip install 'qshield[pytket]'"
        ) from exc

    if not hasattr(circuit, "get_commands") or not hasattr(circuit, "qubits"):
        raise TypeError("parse_pytket expects a pytket Circuit with qubits and get_commands()")

    name = name or getattr(circuit, "name", None) or "pytket_circuit"
    qubits = list(circuit.qubits)
    bits = list(getattr(circuit, "bits", []))
    qubit_index = {qubit: index for index, qubit in enumerate(qubits)}
    bit_index = {bit: index for index, bit in enumerate(bits)}
    ops: list[tuple[str, list[float], list[int]]] = []
    measurements: list[tuple[int, int]] = []
    warnings: list[str] = []
    symbolic: list[str] = []
    resets = 0
    global_phase: list[str] = []

    for command_index, command in enumerate(circuit.get_commands()):
        op = command.op
        op_type = getattr(op.type, "name", None) or str(op.type).rsplit(".", 1)[-1]
        normalized = "".join(char for char in str(op_type).lower() if char.isalnum())
        command_qubits = list(getattr(command, "qubits", []))
        command_bits = list(getattr(command, "bits", []))

        if normalized in {"barrier", "noop"}:
            continue
        if normalized == "measure":
            if len(command_qubits) != 1 or len(command_bits) != 1:
                raise ValueError(f"unsupported pytket measurement arity in command {command_index}")
            measurements.append((qubit_index[command_qubits[0]], bit_index[command_bits[0]]))
            continue
        if normalized == "reset":
            resets += 1
            continue
        if normalized == "phase":
            global_phase.extend(str(param) for param in getattr(op, "params", []))
            continue

        canonical = _PYTKET_NAME_MAP.get(normalized)
        if normalized == "cnx":
            canonical = {4: "c3x", 5: "c4x"}.get(len(command_qubits))
        elif normalized == "cnz":
            canonical = {4: "c3z", 5: "c4z"}.get(len(command_qubits))
        spec = GATE_DB.get_spec(canonical) if canonical is not None else None
        if canonical is None or spec is None:
            raise ValueError(
                f"unsupported pytket operation {op_type!r} at command {command_index}; refusing to approximate"
            )
        if len(command_qubits) != spec.arity:
            raise ValueError(
                f"pytket operation {op_type!r} has arity {len(command_qubits)}, "
                f"expected {spec.arity}; refusing to approximate"
            )
        raw_params = list(getattr(op, "params", []))
        if normalized in {"v", "vdg"}:
            if raw_params:
                raise ValueError(f"pytket operation {op_type!r} unexpectedly has parameters")
            # V/Vdg are exactly Rx(+/-pi/2), whereas QSHIELD's SX includes
            # the conventional Qiskit global phase and is not matrix-identical.
            raw_params = [0.5 if normalized == "v" else -0.5]
        if len(raw_params) != spec.num_params:
            raise ValueError(
                f"pytket operation {op_type!r} has {len(raw_params)} parameters, "
                f"expected {spec.num_params}; refusing to approximate"
            )
        params: list[float] = []
        for param in raw_params:
            value = _float_or_nan(param)
            if math.isnan(value):
                symbolic.append(f"command[{command_index}]: {param}")
            params.append(value * math.pi if not math.isnan(value) else value)
        ops.append((canonical, params, [qubit_index[qubit] for qubit in command_qubits]))

    if resets:
        warnings.append(f"pytket reset operations are not represented in CircuitIR ({resets} omitted)")
    if global_phase:
        warnings.append("pytket global phase is not represented in CircuitIR")
    if symbolic:
        warnings.append("one or more pytket symbolic gate parameters could not be converted to radians")

    return _build_ir(
        name=name,
        source_framework="pytket",
        num_qubits=len(qubits),
        num_clbits=len(bits),
        ops=ops,
        measurements=measurements,
        metadata={
            "source": "pytket",
            "qubit_labels": [str(qubit) for qubit in qubits],
            "bit_labels": [str(bit) for bit in bits],
            "resets": resets,
            "global_phase_half_turns": global_phase,
            "qshield_symbolic_params": symbolic,
            "warnings": warnings,
        },
        source_repr=repr(circuit),
    )


# ----------------------------------------------------------------------
# PennyLane
# ----------------------------------------------------------------------


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
