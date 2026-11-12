"""ZX-calculus bridge between CircuitIR and PyZX.

pyzx is an optional dependency (``pip install 'qshield[formal]'``).
All importers of this module degrade gracefully when pyzx is absent.
"""

from __future__ import annotations

import math
from fractions import Fraction

from qshield.core.circuit_ir import CircuitIR

_PHASE_DENOM = 10**6


class FormalVerificationError(RuntimeError):
    """Raised when a circuit cannot be represented in the ZX calculus."""


def pyzx_available() -> bool:
    try:
        import pyzx  # noqa: F401
    except ImportError:
        return False
    else:
        return True


def _phase(theta: float) -> Fraction:
    """Convert an angle in radians to a fraction of pi (pyzx convention)."""
    value = theta / math.pi
    frac = Fraction(value).limit_denominator(_PHASE_DENOM)
    if abs(float(frac) - value) > 1e-6:
        # snap near-miss singles such as pi/4 written as 0.785
        frac = Fraction(round(value * _PHASE_DENOM), _PHASE_DENOM)
    return frac


def circuit_to_pyzx(ir: CircuitIR):
    """Convert a CircuitIR into a pyzx Circuit.

    Raises :class:`FormalVerificationError` when the circuit contains
    non-unitary or unmappable operations.
    """
    try:
        import pyzx
    except ImportError as exc:
        raise FormalVerificationError("pyzx is not installed") from exc

    # Measurements do not affect the unitary fragment being verified; the
    # equivalence check covers the pre-measurement circuit semantics.
    if ir.metadata.get("resets") or any(g.gate_name == "reset" for g in ir.gates):
        raise FormalVerificationError("circuit contains reset operations (non-unitary)")

    c = pyzx.Circuit(ir.num_qubits)

    # pyzx qubit index == our qubit index (ordering is a naming convention
    # as long as both circuits use the same one, which is the case here)
    for gate in ir.gates:
        q = list(gate.qubits)
        p = list(gate.parameters)
        name = gate.gate_name
        try:
            if name == "id":
                continue
            elif name == "h":
                c.add_gate("H", q[0])
            elif name == "x":
                c.add_gate("NOT", q[0])
            elif name == "y":
                c.add_gate("Y", q[0])
            elif name == "z":
                c.add_gate("Z", q[0])
            elif name == "s":
                c.add_gate("S", q[0])
            elif name == "sdg":
                c.add_gate("S", q[0], adjoint=True)
            elif name == "t":
                c.add_gate("T", q[0])
            elif name == "tdg":
                c.add_gate("T", q[0], adjoint=True)
            elif name == "sx":
                c.add_gate("SX", q[0])
            elif name == "sxdg":
                c.add_gate("SX", q[0], adjoint=True)
            elif name == "rx":
                c.add_gate("XPhase", q[0], phase=_phase(p[0]))
            elif name == "ry":
                c.add_gate("YPhase", q[0], phase=_phase(p[0]))
            elif name == "rz" or name in ("p", "u1"):
                c.add_gate("ZPhase", q[0], phase=_phase(p[0]))
            elif name == "u2":
                c.add_gate("U2", q[0], theta=_phase(p[0]), phi=_phase(p[1]))
            elif name in ("u3", "u"):
                c.add_gate("U3", q[0], theta=_phase(p[0]), phi=_phase(p[1]), rho=_phase(p[2]))
            elif name == "cx":
                c.add_gate("CNOT", q[0], q[1])
            elif name == "cy":
                c.add_gate("CY", q[0], q[1])
            elif name == "cz":
                c.add_gate("CZ", q[0], q[1])
            elif name == "swap":
                c.add_gate("SWAP", q[0], q[1])
            elif name == "ch":
                c.add_gate("CHAD", q[0], q[1])
            elif name == "crz":
                c.add_gate("CRZ", q[0], q[1], phase=_phase(p[0]))
            elif name in ("cp", "cu1"):
                c.add_gate("CPhase", q[0], q[1], phase=_phase(p[0]))
            elif name == "crx":
                c.add_gate("CRX", q[0], q[1], phase=_phase(p[0]))
            elif name == "cry":
                c.add_gate("CRY", q[0], q[1], phase=_phase(p[0]))
            elif name in ("cu3", "cu"):
                c.add_gate("CU3", q[0], q[1], theta=_phase(p[0]), phi=_phase(p[1]), rho=_phase(p[2]))
            elif name == "rxx":
                c.add_gate("RXX", q[0], q[1], phase=_phase(p[0]))
            elif name == "rzz":
                c.add_gate("RZZ", q[0], q[1], phase=_phase(p[0]))
            elif name == "ryy":
                raise FormalVerificationError("ryy has no direct pyzx gate; decompose it first")
            elif name == "ccx":
                c.add_gate("TOF", q[0], q[1], q[2])
            elif name == "ccz":
                c.add_gate("CCZ", q[0], q[1], q[2])
            else:
                raise FormalVerificationError(f"gate {name!r} has no ZX-calculus mapping")
        except TypeError as exc:
            raise FormalVerificationError(f"failed to add gate {name!r} to pyzx circuit: {exc}") from exc
    return c
