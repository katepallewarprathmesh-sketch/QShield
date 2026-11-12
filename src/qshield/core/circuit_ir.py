"""Core data structures for the QSHIELD framework.

Internal representation (CircuitIR): a flat gate list plus a
dependency DAG, with unitary annotations resolvable through the
gate database.

Bit-ordering convention
-----------------------
Qubit ``i`` corresponds to the ``(num_qubits - 1 - i)``-th bit, i.e.
qubit 0 is the *most significant* qubit in the basis index.  All
matrices produced here act on basis vectors indexed as
``|q_0 q_1 ... q_{n-1}>``.  This matches the natural reading order of
OpenQASM files and makes tensor contraction order explicit.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

#: Hard limit for exact unitary computation (matrix is 4^n complex entries).
MAX_EXACT_QUBITS = 12

#: Tolerance used when comparing unitaries to (near-)identity.
DEFAULT_TOLERANCE = 1e-8


class ThreatLevel(Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    LIKELY_MALICIOUS = "likely_malicious"
    CONFIRMED_MALICIOUS = "confirmed_malicious"


class GateType(Enum):
    STANDARD = "standard"            # H, X, Y, Z, CNOT, ...
    PARAMETERIZED = "parameterized"  # RX(theta), RZ(theta), U3(...), ...
    CUSTOM = "custom"                # user-defined unitaries / gates
    UNKNOWN = "unknown"              # cannot be identified


@dataclass
class GateNode:
    """Single gate in the circuit DAG."""

    gate_id: str                             # unique identifier
    gate_name: str                           # human-readable name (canonical)
    gate_type: GateType
    qubits: list[int]                        # target qubits (gate order)
    parameters: list[float] = field(default_factory=list)
    unitary: np.ndarray | None = None     # filled lazily via gate DB
    source_location: str | None = None    # file:line where defined
    package_origin: str | None = None     # which package provided this gate
    threat_annotations: list[str] = field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    metadata: dict = field(default_factory=dict)


@dataclass
class CircuitIR:
    """Internal representation of a quantum circuit."""

    circuit_id: str
    name: str
    num_qubits: int
    num_classical_bits: int
    gates: list[GateNode]
    dag: dict[str, list[str]] = field(default_factory=dict)
    measurements: list[tuple[int, int]] = field(default_factory=list)  # (qubit, clbit)
    ancilla_qubits: list[int] = field(default_factory=list)
    source_framework: str = "unknown"   # "qasm" | "qiskit" | "cirq" | "pennylane" | ...
    source_hash: str = ""               # sha256 of original source
    metadata: dict = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Basic statistics
    # ------------------------------------------------------------------
    def get_gate_count(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for gate in self.gates:
            counts[gate.gate_name] = counts.get(gate.gate_name, 0) + 1
        return counts

    def get_qubit_usage(self) -> dict[int, int]:
        usage = {q: 0 for q in range(self.num_qubits)}
        for gate in self.gates:
            for q in gate.qubits:
                usage[q] = usage.get(q, 0) + 1
        return usage

    def get_entanglement_map(self) -> dict[tuple[int, int], int]:
        emap: dict[tuple[int, int], int] = {}
        for gate in self.gates:
            if not self.is_entangling(gate):
                continue
            for i in range(len(gate.qubits)):
                for j in range(i + 1, len(gate.qubits)):
                    lo, hi = sorted((gate.qubits[i], gate.qubits[j]))
                    pair = (lo, hi)
                    emap[pair] = emap.get(pair, 0) + 1
        return emap

    @staticmethod
    def is_entangling(gate: GateNode) -> bool:
        if len(gate.qubits) < 2:
            return False
        if gate.unitary is not None:
            return _matrix_is_entangling(gate.unitary)
        return True  # assume multi-qubit named gates are entangling

    def get_depth(self) -> int:
        """Circuit depth via greedy list scheduling over the qubits."""
        depth = [0] * self.num_qubits
        max_depth = 0
        for gate in self.gates:
            start = max((depth[q] for q in gate.qubits), default=0)
            finish = start + 1
            for q in gate.qubits:
                depth[q] = finish
            max_depth = max(max_depth, finish)
        return max_depth

    def get_qubit_interaction_graph(self) -> dict[int, set[int]]:
        graph: dict[int, set[int]] = {q: set() for q in range(self.num_qubits)}
        for gate in self.gates:
            qs = gate.qubits
            for i in range(len(qs)):
                for j in range(i + 1, len(qs)):
                    graph[qs[i]].add(qs[j])
                    graph[qs[j]].add(qs[i])
        return graph

    # ------------------------------------------------------------------
    # Hashing
    # ------------------------------------------------------------------
    @staticmethod
    def hash_source(source: str) -> str:
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

    # ------------------------------------------------------------------
    # Unitary computation
    # ------------------------------------------------------------------
    def to_unitary(self, max_qubits: int = MAX_EXACT_QUBITS) -> np.ndarray | None:
        """Compute the total unitary matrix.

        Returns ``None`` when the circuit has more than ``max_qubits``
        qubits, when a non-unitary gate (measurement) is present, or when a
        gate has no resolvable unitary.
        """
        if self.num_qubits > max_qubits:
            return None
        if any(g.gate_name in ("measure",) for g in self.gates):
            return None
        dim = 1 << self.num_qubits
        total = np.eye(dim, dtype=complex)
        for gate in self.gates:
            mat = gate.unitary
            if mat is None:
                return None
            full = embed_gate_matrix(mat, gate.qubits, self.num_qubits)
            total = full @ total
        return total

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------
    def to_dict(self) -> dict:
        gate_counts = self.get_gate_count()
        usage = self.get_qubit_usage()
        return {
            "circuit_id": self.circuit_id,
            "name": self.name,
            "num_qubits": self.num_qubits,
            "num_classical_bits": self.num_classical_bits,
            "num_gates": len(self.gates),
            "gate_counts": gate_counts,
            "qubit_usage": usage,
            "measurements": list(self.measurements),
            "ancilla_qubits": list(self.ancilla_qubits),
            "depth": self.get_depth(),
            "source_framework": self.source_framework,
            "source_hash": self.source_hash,
            "entanglement_map": {f"{a}-{b}": v for (a, b), v in self.get_entanglement_map().items()},
            "metadata": self.metadata,
        }


_ENTANGLING_CACHE: dict[bytes, bool] = {}
_ENTANGLING_CACHE_MAX = 4096


def _matrix_is_entangling(matrix: np.ndarray) -> bool:
    """True when a 2-qubit unitary is not a product of local operators.

    Uses the operator Schmidt decomposition across the q0|q1 cut:
    reshape ``O[(a,b),(c,d)]`` to ``O'[(a,c),(b,d)]`` and take the SVD.
    A single nonzero Schmidt coefficient means the operator factorises as
    ``A \\otimes B``.  Non-2-qubit matrices are conservatively treated as
    entangling.  Results are cached by matrix bytes — the parser hands every
    gate a fresh array, but identical gates are byte-identical, and SVD
    dominates scans of large circuits.
    """
    m = np.ascontiguousarray(np.asarray(matrix, dtype=complex))
    if m.ndim != 2 or m.shape[0] != m.shape[1]:
        return False
    if m.shape == (2, 2):
        return False
    if m.shape != (4, 4):
        return True
    key = m.tobytes()
    cached = _ENTANGLING_CACHE.get(key)
    if cached is not None:
        return cached
    reshaped = m.reshape(2, 2, 2, 2).transpose(0, 2, 1, 3).reshape(4, 4)
    s = np.linalg.svd(reshaped, compute_uv=False)
    result = int(np.sum(s > 1e-9 * s.max(initial=1.0) + 1e-12)) > 1
    if len(_ENTANGLING_CACHE) >= _ENTANGLING_CACHE_MAX:
        _ENTANGLING_CACHE.clear()
    _ENTANGLING_CACHE[key] = result
    return result


def embed_gate_matrix(gate_matrix: np.ndarray, target_qubits: Iterable[int], num_qubits: int) -> np.ndarray:
    """Embed a k-qubit gate matrix into an n-qubit Hilbert space.

    ``target_qubits`` lists the qubits the gate acts on, in the same order
    as the gate matrix acts on its own subsystem (MSB first).
    """
    targets = list(target_qubits)
    k = len(targets)
    dim_gate = 1 << k
    dim_full = 1 << num_qubits
    gate_matrix = np.asarray(gate_matrix, dtype=complex)
    if gate_matrix.shape != (dim_gate, dim_gate):
        raise ValueError(
            f"Gate matrix shape {gate_matrix.shape} does not match {k} target qubit(s)"
        )
    rest = [q for q in range(num_qubits) if q not in targets]
    full = np.zeros((dim_full, dim_full), dtype=complex)

    # iterate over basis assignments to the spectator qubits
    for rest_bits in range(1 << len(rest)):
        # partial index: bits for spectator qubits fixed
        base_mask = 0
        base_bits: dict[int, int] = {}
        for j, q in enumerate(rest):
            bit = (rest_bits >> (len(rest) - 1 - j)) & 1
            base_bits[q] = bit
            base_mask |= bit << (num_qubits - 1 - q)

        # iterate over gate matrix row/col entries
        for gi in range(dim_gate):
            amp_row = [(gi >> (k - 1 - i)) & 1 for i in range(k)]
            row = base_mask
            for i, q in enumerate(targets):
                row |= amp_row[i] << (num_qubits - 1 - q)
            for gj in range(dim_gate):
                coeff = gate_matrix[gi, gj]
                if coeff == 0:
                    continue
                amp_col = [(gj >> (k - 1 - i)) & 1 for i in range(k)]
                col = base_mask
                for i, q in enumerate(targets):
                    col |= amp_col[i] << (num_qubits - 1 - q)
                full[row, col] = coeff
    return full
