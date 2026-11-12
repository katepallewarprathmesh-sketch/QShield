"""Property verification hooks (no hidden computation on non-output qubits).

Full ZX-diagram property verification is roadmap work (spec M3.1).  What is
available today: an exact partial-freedom check for *small* circuits backed by
the unitary verifier, re-exported here so callers get a single entry point.
"""

from __future__ import annotations

from qshield.core.circuit_ir import CircuitIR
from qshield.static.unitary_verifier import UnitaryVerifier


def verify_ancillas_independent(
    circuit: CircuitIR,
    ancilla_qubits: list[int],
    tolerance: float = 1e-6,
):
    """Exact check that ancilla reduced states are independent of the inputs.

    Returns a :class:`qshield.static.unitary_verifier.LeakageReport`.
    """
    return UnitaryVerifier(max_qubits=min(10, 8)).check_ancilla_independence(
        circuit, ancilla_qubits, tolerance=tolerance
    )
