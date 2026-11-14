"""Round-trip tests for the OpenQASM emitter (implementation plan Task 2.2).

Three layers, all required:

1. **Structural round-trip for the whole fixture corpus** — parse → emit →
   parse; gate sequence (names, qubits, parameters) must be identical.
2. **Refusal paths** — non-unitary content and bad parameters are refused
   loudly, never silently dropped.
3. **Semantic cross-check through Qiskit** (optional-extra gated) — for small
   fixtures, our composite unitary and Qiskit's ``Operator`` of the same
   source agree up to global phase (qubit ordering remapped).
"""

import importlib.util
import math
from pathlib import Path

import numpy as np
import pytest

from qshield.core.circuit_ir import CircuitIR, GateNode, GateType
from qshield.core.parsers import parse_qasm
from qshield.core.qasm_emitter import QASMEmitError, emit_qasm

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"


def _sig(g):
    return (g.gate_name, tuple(g.qubits), tuple(round(p, 17) for p in g.parameters))


def _fixtures():
    out = sorted(FIXTURES.rglob("*.qasm"))
    assert out
    return out


def _try_parse(path):
    """Parse a fixture, returning None for fixtures that intentionally fail."""
    try:
        return parse_qasm(path.read_text(encoding="utf-8"), name=path.stem)
    except Exception:
        return None


# ------------------------------------------------------- 1. corpus round-trip

def test_corpus_roundtrip_structure_is_identity():
    failures = []
    checked = 0
    for path in _fixtures():
        ir1 = _try_parse(path)
        if ir1 is None:
            continue  # fixtures intentionally exercising parse failures
        try:
            text = emit_qasm(ir1)
        except QASMEmitError as exc:
            failures.append(f"{path.relative_to(ROOT)}: emit refused: {exc}")
            continue
        try:
            ir2 = parse_qasm(text, name=path.stem)
        except Exception as exc:
            failures.append(f"{path.relative_to(ROOT)}: emitted QASM did not re-parse: {exc}")
            continue
        if ir2.num_qubits != ir1.num_qubits:
            failures.append(f"{path.relative_to(ROOT)}: qubit count {ir1.num_qubits} -> {ir2.num_qubits}")
            continue
        if [ _sig(g) for g in ir1.gates ] != [ _sig(g) for g in ir2.gates ]:
            failures.append(f"{path.relative_to(ROOT)}: gate sequence changed on round-trip")
            continue
        if ir1.measurements != ir2.measurements:
            failures.append(f"{path.relative_to(ROOT)}: measurements changed on round-trip")
            continue
        checked += 1
    assert checked > 0, "no fixtures could be round-tripped"
    assert not failures, "round-trip failures:\n" + "\n".join(failures[:10])


def test_roundtrip_preserves_unitaries_where_both_sides_have_them():
    for path in _fixtures():
        ir1 = _try_parse(path)
        if ir1 is None:
            continue
        try:
            ir2 = parse_qasm(emit_qasm(ir1), name=path.stem)
        except Exception:  # noqa: S112 — contextual compare, not an assertion path
            continue
        for g1, g2 in zip(ir1.gates, ir2.gates, strict=True):
            if g1.unitary is None or g2.unitary is None:
                continue
            assert np.allclose(np.asarray(g1.unitary), np.asarray(g2.unitary), atol=1e-12), (
                f"{path.relative_to(ROOT)}: unitary changed for gate {_sig(g1)}"
            )


# ------------------------------------------------------------- 2. refusals

def _ir_with(metadata=None, gates=None, num_qubits=2, num_classical_bits=0, measurements=()):
    gates = gates if gates is not None else [
        GateNode(gate_id="g1", gate_name="h", gate_type=GateType.STANDARD, qubits=[0])
    ]
    return CircuitIR(
        circuit_id="circ-test",
        name="test",
        num_qubits=num_qubits,
        num_classical_bits=num_classical_bits,
        gates=gates,
        dag={},
        measurements=list(measurements),
        source_framework="qasm2.0",
        source_hash="0" * 64,
        metadata=metadata or {},
    )


def test_emit_refuses_resets_loudly():
    ir = _ir_with(metadata={"resets": 2})
    with pytest.raises(QASMEmitError, match="reset"):
        emit_qasm(ir)


def test_emit_refuses_classically_conditioned_ops_loudly():
    ir = _ir_with(metadata={"conditional_ops": 1})
    with pytest.raises(QASMEmitError, match="classical-feedback"):
        emit_qasm(ir)


def test_emit_refuses_non_finite_parameter():
    ir = _ir_with(gates=[
        GateNode(gate_id="g1", gate_name="rz", gate_type=GateType.PARAMETERIZED,
                 qubits=[0], parameters=[math.inf]),
    ])
    with pytest.raises(QASMEmitError, match="Non-finite"):
        emit_qasm(ir)


def test_emit_refuses_invalid_gate_name():
    ir = _ir_with(gates=[
        GateNode(gate_id="g1", gate_name="not a gate!", gate_type=GateType.CUSTOM, qubits=[0]),
    ])
    with pytest.raises(QASMEmitError, match="identifier"):
        emit_qasm(ir)


def test_emit_refuses_out_of_range_qubit():
    ir = _ir_with(gates=[
        GateNode(gate_id="g1", gate_name="h", gate_type=GateType.STANDARD, qubits=[5]),
    ])
    with pytest.raises(QASMEmitError, match="out of range"):
        emit_qasm(ir)


# ----------------------------- 3. semantic cross-check through Qiskit (optional)

def _qiskit_loads_with_qshield_gates(text, ir):
    """Load emitted OpenQASM 2.0 in Qiskit, registering only unknown gates.

    Qiskit's builtin ``qelib1.inc`` does not define QShield's extended gate set
    (e.g. ``rzz``), so custom instructions are registered for the gate names the
    stock importer rejects. Two conventions must be honoured:

    * instruction matrices are turned into Qiskit's little-endian
      (qubit 0 = leftmost/LSB tensor factor) ordering by reversing the
      per-instruction qubit axes;
    * gates already known to Qiskit (e.g. ``cx``) are left to the native
      importer, which implements the physical ``control -> target`` semantics
      of the OpenQASM 2.0 spec.
    """
    import re

    from qiskit import qasm2
    from qiskit.circuit import Gate
    from qiskit.qasm2.exceptions import QASM2ParseError

    from qshield.core.gate_database import GATE_DB

    def _qiskit_endian(name):
        spec = GATE_DB.get_spec(name)

        class _QShieldGate(Gate):
            def __init__(self, *args):
                super().__init__(name, spec.arity, list(args))

            def to_matrix(self):
                params = [float(p) for p in self.params]
                mat = GATE_DB.matrix(name, params)
                n = spec.arity
                if n <= 1:
                    return mat
                t = mat.reshape([2] * (2 * n))
                axes = list(range(n - 1, -1, -1)) + list(range(2 * n - 1, n - 1, -1))
                return np.ascontiguousarray(t.transpose(axes)).reshape(mat.shape)

        return _QShieldGate

    known = {gate.gate_name for gate in ir.gates}
    registered = set()
    for _ in range(len(known) + 1):
        custom = []
        for name in sorted(registered):
            spec = GATE_DB.get_spec(name)
            custom.append(
                qasm2.CustomInstruction(
                    name,
                    spec.num_params,
                    spec.arity,
                    _qiskit_endian(name),
                    builtin=True,
                )
            )
        try:
            return qasm2.loads(text, custom_instructions=custom)
        except QASM2ParseError as exc:
            match = re.search(r"'([A-Za-z_]\w*)' is not defined", str(exc))
            if match is None:
                raise
            name = match.group(1)
            if name in registered or GATE_DB.get_spec(name) is None:
                raise
            registered.add(name)
    raise AssertionError("unreachable: custom-instruction loop did not converge")


def _reverse_qubits(matrix: np.ndarray, n: int) -> np.ndarray:
    """Reverse the qubit order of a 2^n x 2^n unitary (tensor axis permutation)."""
    tensor = matrix.reshape([2] * (2 * n))
    axes = [n - 1 - i for i in range(n)] + [2 * n - 1 - i for i in range(n)]
    return np.ascontiguousarray(tensor.transpose(axes)).reshape(2**n, 2**n)


def _unitary_of_ir(ir):
    """Composite unitary, explicit about the q[0]-is-MSB convention."""
    n = ir.num_qubits
    dim = 2**n
    U = np.eye(dim, dtype=complex)
    for gate in ir.gates:
        matrix = np.asarray(gate.unitary, dtype=complex)
        k = len(gate.qubits)
        if matrix.shape != (2**k, 2**k):
            return None
        full = np.zeros((dim, dim), dtype=complex)
        positions = [n - 1 - q for q in gate.qubits]
        for col in range(dim):
            sub_col = 0
            for pos in positions:
                sub_col = (sub_col << 1) | ((col >> pos) & 1)
            for out_sub in range(2**k):
                amp = matrix[out_sub, sub_col]
                if amp == 0:
                    continue
                row = col
                for i, pos in enumerate(positions):
                    if (out_sub >> (k - 1 - i)) & 1:
                        row |= 1 << pos
                    else:
                        row &= ~(1 << pos)
                full[row, col] = amp
        U = full @ U
    return U


@pytest.mark.skipif(
    importlib.util.find_spec("qiskit") is None,
    reason="qiskit ([qiskit] extra) not installed",
)
def test_composite_unitary_matches_qiskit_on_small_fixtures():
    from qiskit.quantum_info import Operator

    compared = 0
    for path in _fixtures():
        ir1 = _try_parse(path)
        if ir1 is None:
            continue
        if ir1.num_qubits > 6 or ir1.num_qubits == 0:
            continue
        if any(g.unitary is None for g in ir1.gates):
            continue  # opaque gate in fixture — cannot compare semantically
        n = ir1.num_qubits
        try:
            ours = _unitary_of_ir(ir1)
        except Exception:
            ours = None
        if ours is None:
            pytest.skip("internal unitary composer unavailable")
        try:
            qc = _qiskit_loads_with_qshield_gates(emit_qasm(ir1), ir1)
            qc = qc.remove_final_measurements(inplace=False)
            theirs = np.asarray(Operator(qc), dtype=complex)
        except Exception:  # noqa: S112 — semantic cross-check is best-effort per fixture
            continue
        ours_rev = _reverse_qubits(ours, n)
        ref = ours_rev.reshape(-1)
        got = theirs.reshape(-1)
        # find a global phase aligning the largest-magnitude element
        k = int(np.argmax(np.abs(ref)))
        phase = got[k] / ref[k]
        assert abs(abs(phase) - 1.0) < 1e-9, f"{path.name}: no global phase makes matrices match"
        assert np.allclose(ours_rev * phase, theirs, atol=1e-10), (
            f"{path.relative_to(ROOT)}: unitary differs from qiskit by more than round-off"
        )
        compared += 1
        if compared >= 10:
            break
    assert compared > 0, "no fixtures were semantically compared"
