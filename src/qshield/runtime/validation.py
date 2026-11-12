"""Result validation against ideal predictions.

When a backend returns a counts histogram we can ask: is this consistent
with the circuit's Born distribution? QSHIELD computes the ideal
distribution *exactly* for unconditioned circuits up to 12 qubits — by the
deferred-measurement principle this covers mid-circuit measurements too, as
long as no classically-conditional operations or resets are present — and
returns ``unavailable`` — never a guess — otherwise.

Both provider bit-order conventions are tried (MSB: qubit 0 leftmost,
matching the sandbox; LSB: reversed, matching Qiskit/Cirq counts keys).
A match under either convention is reported with the convention noted.

Honesty notes:

- This is a *goodness-of-fit* check against exact ideal probabilities, so
  the M2.2 caveat (goodness-of-fit against *empirical* probes double-counts
  sampling error) does not apply; still, honest device noise will fail this
  test at large shot counts — exactly like drift-vs-ideal in M2.2, that is
  drift, not an attack. Use this check to catch *implausible* results
  (rigged backends, corrupted transport), not as a device-noise FPR.
- Statistical equivalence is necessary, not sufficient: a rigged backend
  returning exactly the ideal histogram passes. The differential tester
  covers that case; the formal layer covers semantics.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from qshield.core.circuit_ir import CircuitIR
from qshield.dynamic.statistical_tests import chi_squared_test

DEFAULT_SIGNIFICANCE = 0.01


@dataclass
class ResultVerdict:
    status: str                      # "match" | "mismatch" | "unavailable"
    chi2: float | None = None
    p_value: float | None = None
    reason: str = ""
    shots: int = 0
    bit_order: str | None = None     # "msb" | "lsb" | None
    details: dict = field(default_factory=dict)


def ideal_probabilities(ir: CircuitIR, *, max_qubits: int = 12) -> dict[str, float] | None:
    """Exact distribution over clbit strings, or None when not computable.

    By the deferred-measurement principle, circuits with only *unconditional*
    gates have the same outcome distribution when all measurements are moved
    to the end. CircuitIR cannot represent measurement positions, so we rely
    on that theorem rather than on positional bookkeeping: we evolve all
    gates ignoring measurements, take the Born distribution, and marginalise
    onto the measured clbits. Classically-conditional operations and resets
    are rejected up front (they invalidate the theorem).
    """
    from qshield.core.circuit_ir import embed_gate_matrix
    from qshield.core.gate_database import GATE_DB

    metadata = ir.metadata or {}
    if metadata.get("conditional_ops") or metadata.get("resets"):
        return None
    if not ir.measurements:
        return None
    n = ir.num_qubits
    if n > max_qubits:
        return None
    state = np.zeros(1 << n, dtype=complex)
    state[0] = 1.0
    for gate in ir.gates:
        matrix = gate.unitary
        if matrix is None:
            matrix = GATE_DB.matrix(gate.gate_name, gate.parameters)
        if matrix is None:
            return None
        state = embed_gate_matrix(matrix, gate.qubits, n) @ state
    probs = np.abs(state) ** 2

    num_clbits = int(ir.num_classical_bits)
    dist: dict[str, float] = {}
    for basis, p in enumerate(probs):
        if p == 0.0:
            continue
        key_chars = ["0"] * num_clbits
        for qubit, clbit in ir.measurements:
            if clbit >= num_clbits:
                return None
            bit = (basis >> (n - 1 - qubit)) & 1   # qubit 0 is the MSB (sandbox convention)
            key_chars[clbit] = str(bit)
        key = "".join(key_chars)
        dist[key] = dist.get(key, 0.0) + float(p)
    return dist


def _match_bit_order(
    counts: dict[str, int],
    probs: dict[str, float],
) -> tuple[str | None, float | None, float | None]:
    """Return (bit_order, chi2, p_value) for whichever order fits, else (None, None, None)."""
    candidates: dict[str, dict[str, int]] = {
        "msb": counts,
        "lsb": {k[::-1]: v for k, v in counts.items()},
    }
    best_order: str | None = None
    best_chi: float | None = None
    best_p: float | None = None
    for order, mapped in candidates.items():
        try:
            chi2, p = chi_squared_test(mapped, probs)
        except ValueError:
            continue
        if best_p is None or p > best_p:
            best_order, best_chi, best_p = order, chi2, p
    return best_order, best_chi, best_p


def validate_counts(
    ir: CircuitIR,
    counts: dict[str, int],
    *,
    max_qubits: int = 12,
    significance: float = DEFAULT_SIGNIFICANCE,
) -> ResultVerdict:
    """Compare an observed counts histogram with the ideal Born distribution."""
    total = sum(counts.values())
    if total == 0:
        return ResultVerdict(status="unavailable", reason="empty counts histogram", shots=0)
    probs = ideal_probabilities(ir, max_qubits=max_qubits)
    if probs is None:
        return ResultVerdict(
            status="unavailable",
            reason=f"exact prediction unavailable (unsupported semantics, or > {max_qubits} qubits, "
                   f"or non-unitary gate)",
            shots=total,
        )
    order, chi2, p = _match_bit_order(counts, probs)
    if order is None:
        return ResultVerdict(status="unavailable", reason="counts keys are not bitstrings", shots=total)
    ok = (p is not None and p >= significance)
    return ResultVerdict(
        status="match" if ok else "mismatch",
        chi2=float(chi2) if chi2 is not None else None,
        p_value=float(p) if p is not None else None,
        reason="counts are statistically consistent with the ideal Born distribution" if ok
               else f"counts deviate from the ideal Born distribution (χ²={chi2:.2f}, p={p:.2e}); "
                    f"drift vs ideal is not an attack — see module docstring",
        shots=total,
        bit_order=order,
        details={"significance": significance, "bins": len(probs)},
    )
