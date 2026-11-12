"""QSHIELD → framework export: reconstruct native circuits from CircuitIR.

Used for the round-trip acceptance in the spec ("Qiskit → CircuitIR → Qiskit
preserves semantics") and for emitting replay/PoC payloads from findings.

Strategy: emit native Qiskit methods where they exist (and are exact matrix
identities); otherwise fall back to ``QuantumCircuit.unitary()`` with the
gate's known unitary, which is always semantics-preserving. Gates with no
known unitary and no native mapping cause :class:`UnsupportedGateError`.
"""

from __future__ import annotations

from typing import Any

import numpy as np

from qshield.core.circuit_ir import CircuitIR
from qshield.core.gate_database import ALIASES, GATE_DB

# canonical qshield name -> exact matrix identity lambda(qc, q, p) for emission
# using only natively supported qiskit methods. All rewrites below are *exact*
# matrix identities (no global phase introduced).
_NATIVE_UNARY = {
    "id": "id", "x": "x", "y": "y", "z": "z", "h": "h", "s": "s", "sdg": "sdg",
    "t": "t", "tdg": "tdg", "sx": "sx", "sxdg": "sxdg",
}
_NATIVE_BINARY = {
    "cx": "cx", "cy": "cy", "cz": "cz", "swap": "swap", "ch": "ch",
    "iswap": "iswap", "cs": "cs", "csdg": "csdg", "csx": "csx",
}
_NATIVE_UNIPARAM = {
    "rx": "rx", "ry": "ry", "rz": "rz", "p": "p",
    "crx": "crx", "cry": "cry", "crz": "crz", "cp": "cp",
    "rxx": "rxx", "ryy": "ryy", "rzz": "rzz", "rzx": "rzx",
}


class UnsupportedGateError(ValueError):
    """Raised when a gate cannot be emitted (no native form, no known unitary)."""


def _base_name(name: str) -> str:
    return ALIASES.get(name, name)


def to_qiskit(ir: CircuitIR):
    """Reconstruct a ``qiskit.QuantumCircuit`` from ``ir``.

    Exact on all supported gates: each emitted instruction has the same
    matrix as the source gate. Gates with neither a native Qiskit form nor
    a known unitary raise :class:`UnsupportedGateError`.
    """
    try:
        from qiskit import QuantumCircuit
    except ImportError as exc:  # pragma: no cover - depends on env
        raise RuntimeError(
            "qiskit is not installed. Install with: pip install 'qshield[qiskit]'"
        ) from exc

    qc = QuantumCircuit(ir.num_qubits, ir.num_classical_bits)

    def emit_native(method: str, qubits: list[int], *params: float) -> bool:
        fn = getattr(qc, method, None)
        if fn is None:
            return False
        fn(*params, *qubits)
        return True

    for gate in ir.gates:
        name = _base_name(gate.gate_name)
        p = list(gate.parameters)
        n = len(gate.qubits)

        if name in _NATIVE_UNARY and n == 1:
            emit_native(_NATIVE_UNARY[name], gate.qubits)
            continue
        if name == "ccx" and n == 3:
            qc.ccx(*gate.qubits)
            continue
        if name == "ccz" and n == 3:
            qc.ccz(*gate.qubits)
            continue
        if name in _NATIVE_BINARY and n == 2 and emit_native(_NATIVE_BINARY[name], gate.qubits):
            continue
        if name in _NATIVE_UNIPARAM and n == (1 if name in ("rx", "ry", "rz", "p") else 2) and emit_native(_NATIVE_UNIPARAM[name], gate.qubits, *p):
            continue
        # ---- exact identities expressed via supported gates -------------
        if name == "u1":
            qc.p(p[0], gate.qubits[0])
            continue
        if name == "u1dg":
            qc.p(-p[0], gate.qubits[0])
            continue
        if name == "u2":
            qc.u(np.pi / 2, p[0], p[1], gate.qubits[0])
            continue
        if name == "u2dg":
            qc.u(-np.pi / 2, -p[1], -p[0], gate.qubits[0])
            continue
        if name in ("u3", "u"):
            qc.u(p[0], p[1], p[2], gate.qubits[0])
            continue
        if name == "u3dg":
            qc.u(-p[0], -p[2], -p[1], gate.qubits[0])
            continue
        if name == "r":
            qc.r(p[0], p[1], gate.qubits[0])
            continue
        if name == "rxdg":
            qc.rx(-p[0], gate.qubits[0])
            continue
        if name == "rydg":
            qc.ry(-p[0], gate.qubits[0])
            continue
        if name == "rzdg":
            qc.rz(-p[0], gate.qubits[0])
            continue
        if name == "pdg":
            qc.p(-p[0], gate.qubits[0])
            continue
        if name == "cu1":
            qc.cp(p[0], *gate.qubits)
            continue
        if name in ("cu",):
            qc.cu(p[0], p[1], p[2], 0, *gate.qubits)
            continue
        if name == "cu2":
            qc.cu(np.pi / 2, p[0], p[1], 0, *gate.qubits)
            continue
        if name == "cu2dg":
            qc.cu(-np.pi / 2, -p[1], -p[0], 0, *gate.qubits)
            continue
        if name == "cu3":
            qc.cu(p[0], p[1], p[2], 0, *gate.qubits)
            continue
        if name == "cu3dg":
            qc.cu(-p[0], -p[2], -p[1], 0, *gate.qubits)
            continue
        if name == "cpdg":
            qc.cp(-p[0], *gate.qubits)
            continue
        if name == "crxdg":
            qc.crx(-p[0], *gate.qubits)
            continue
        if name == "crydg":
            qc.cry(-p[0], *gate.qubits)
            continue
        if name == "crzdg":
            qc.crz(-p[0], *gate.qubits)
            continue
        # multi-controlled via library, exact: c3z = h ccx h (control-phase)
        if name in ("c3z", "c4z"):
            target = gate.qubits[-1]
            controls = gate.qubits[:-1]
            qc.h(target)
            try:
                from qiskit.circuit.library import C3XGate, C4XGate

                qc.append(C3XGate() if len(controls) == 3 else C4XGate(), [*controls, target])
            except ImportError:  # pragma: no cover - very old qiskit
                _unitary_fallback(qc, gate)
            qc.h(target)
            continue
        if name in ("c3x", "c4x"):
            try:
                from qiskit.circuit.library import C3XGate, C4XGate

                qc.append(C3XGate() if len(gate.qubits) == 4 else C4XGate(), gate.qubits)
            except ImportError:  # pragma: no cover - very old qiskit
                _unitary_fallback(qc, gate)
            continue
        # ---- universal semantics-preserving fallback ---------------------
        _unitary_fallback(qc, gate)

    for qubit, cbit in ir.measurements:
        qc.measure(qubit, cbit)
    return qc


def _bit_reversal_perm(n: int) -> np.ndarray:
    """Permutation between QSHIELD MSB-first and Qiskit little-endian ordering."""
    P = np.zeros((1 << n, 1 << n), dtype=complex)
    for i in range(1 << n):
        j = int(format(i, f"0{n}b")[::-1], 2)
        P[i, j] = 1.0
    return P


def _unitary_fallback(qc: Any, gate: Any) -> None:
    mat = gate.unitary if gate.unitary is not None else GATE_DB.matrix(gate.gate_name, gate.parameters)
    if mat is None:
        raise UnsupportedGateError(
            f"Gate {gate.gate_name!r} has no native Qiskit emission and no known unitary; "
            "cannot export this circuit."
        )
    mat = np.asarray(mat, dtype=complex)
    # QSHIELD stores matrices MSB-first; qiskit's unitary() interprets them
    # little-endian. Emit the bit-reversed matrix so the exported circuit
    # acts on qubit labels exactly as the source circuit does.
    if mat.shape == (2 ** len(gate.qubits), 2 ** len(gate.qubits)):
        P = _bit_reversal_perm(len(gate.qubits))
        mat = P @ mat @ P
    qc.unitary(mat, list(gate.qubits))
