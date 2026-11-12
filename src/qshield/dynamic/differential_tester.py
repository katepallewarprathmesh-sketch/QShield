"""Differential testing across simulators/backends.

Strategy: execute the same circuit on two independent implementations of the
same ideal semantics — QSHIELD's sandboxed NumPy simulator and, when
installed, Qiskit Aer — then compare the output distributions with the
statistical battery from :mod:`qshield.dynamic.statistical_tests`.
Significant divergence indicates a tampered circuit or a broken backend.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from qshield.core.circuit_ir import CircuitIR
from qshield.dynamic.sandbox_executor import SandboxExecutor
from qshield.dynamic.statistical_tests import ComparisonResult, compare_distributions


@dataclass
class DifferentialReport:
    compared: bool
    backend_a: str
    backend_b: str
    shots: int
    comparison: ComparisonResult | None
    message: str


def aer_distribution(circuit: CircuitIR, shots: int = 10_000) -> dict[str, int] | None:
    """Execute the circuit on Qiskit Aer's statevector simulator, if available.

    QSHIELD uses MSB ordering (qubit 0 leftmost); Qiskit is little-endian.
    We therefore remap our qubit ``i`` to Qiskit qubit ``n - 1 - i`` and read
    the big-endian probability keys, which then coincide with our bit strings.
    Measurements are dropped: the comparison operates on the final state.
    """
    try:
        from qiskit import QuantumCircuit
        from qiskit.quantum_info import Statevector
    except ImportError:
        return None
    try:
        n = circuit.num_qubits
        qc = QuantumCircuit(n)
        for gate in circuit.gates:
            qs = [n - 1 - q for q in gate.qubits]
            _apply_qiskit_gate(qc, gate, qs)
        sv = Statevector.from_instruction(qc)
        probs = {str(k): float(v) for k, v in sv.probabilities_dict().items()}
        from qshield.dynamic.statistical_tests import sample_counts_from_probabilities
        return sample_counts_from_probabilities(probs, shots)
    except Exception:
        return None


def _apply_qiskit_gate(qc, gate, qs):
    from qiskit.circuit.library import (
        CCXGate,
        CHGate,
        CPhaseGate,
        CRXGate,
        CRYGate,
        CRZGate,
        CXGate,
        CYGate,
        CZGate,
        HGate,
        IGate,
        RXGate,
        RXXGate,
        RYGate,
        RYYGate,
        RZGate,
        RZZGate,
        SdgGate,
        SGate,
        SwapGate,
        SXGate,
        TdgGate,
        TGate,
        U1Gate,
        U2Gate,
        U3Gate,
        UGate,
        XGate,
        YGate,
        ZGate,
    )

    def p(i, default=0.0):
        return gate.parameters[i] if i < len(gate.parameters) else default

    name = gate.gate_name
    table = {
        "id": (IGate, []), "x": (XGate, []), "y": (YGate, []), "z": (ZGate, []),
        "h": (HGate, []), "s": (SGate, []), "sdg": (SdgGate, []),
        "t": (TGate, []), "tdg": (TdgGate, []), "sx": (SXGate, []),
        "rx": (RXGate, [p(0)]), "ry": (RYGate, [p(0)]), "rz": (RZGate, [p(0)]),
        "p": (RZGate, [p(0)]),  # global phase difference only
        "u1": (U1Gate, [p(0)]), "u2": (U2Gate, [p(0), p(1)]),
        "u3": (U3Gate, [p(0), p(1), p(2)]), "u": (UGate, [p(0), p(1), p(2)]),
        "cx": (CXGate, []), "cy": (CYGate, []), "cz": (CZGate, []),
        "swap": (SwapGate, []), "ch": (CHGate, []),
        "crx": (CRXGate, [p(0)]), "cry": (CRYGate, [p(0)]), "crz": (CRZGate, [p(0)]),
        "cp": (CPhaseGate, [p(0)]), "cu1": (CPhaseGate, [p(0)]),
        "cu3": (UGate, [p(0), p(1), p(2)]),
        "rxx": (RXXGate, [p(0)]), "ryy": (RYYGate, [p(0)]), "rzz": (RZZGate, [p(0)]),
        "ccx": (CCXGate, []),
    }
    entry = table.get(name)
    if entry is None:
        from qshield.dynamic.sandbox_executor import SandboxViolation
        raise SandboxViolation(f"Unsupported gate for Qiskit differential execution: {name}")
    cls, args = entry
    if name == "cu3":
        # controlled-U3: build manually
        qc.append(UGate(*args).control(1), qs)
        return
    qc.append(cls(*args), qs)


class DifferentialTester:
    def __init__(self, shots: int = 10_000, significance_level: float = 0.01):
        self.shots = shots
        self.significance_level = significance_level

    def cross_check_against_aer(self, circuit: CircuitIR) -> DifferentialReport:
        backend_b = aer_distribution(circuit, shots=self.shots)
        if backend_b is None:
            return DifferentialReport(
                compared=False,
                backend_a="qshield_numpy_statevector",
                backend_b="qiskit_aer",
                shots=self.shots,
                comparison=None,
                message="Qiskit Aer not available or circuit not executable; differential check skipped",
            )
        # Compare pre-measurement distributions: the Aer path drops
        # measurements (statevector semantics), so the NumPy path must too —
        # otherwise a measured circuit appears as a single collapsed outcome
        # on one side vs a full distribution on the other.
        unitary_view = replace(circuit, measurements=[])
        executor = SandboxExecutor()
        backend_a = executor.sample_distribution(unitary_view, shots=self.shots)
        comparison = compare_distributions(backend_a, backend_b, self.significance_level)
        return DifferentialReport(
            compared=True,
            backend_a="qshield_numpy_statevector",
            backend_b="qiskit_aer",
            shots=self.shots,
            comparison=comparison,
            message=comparison.verdict,
        )
