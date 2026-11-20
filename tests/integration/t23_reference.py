"""Shared helper: reconstruct the pre-tamper reference for a T2.3 fixture.

Used by tests that need an approved baseline. The reference is derived by
removing the readout-stage basis gate the fixture injects; it is never written
to contain the malicious circuit.
"""

from __future__ import annotations

from pathlib import Path

from qshield.core.circuit_ir import CircuitIR
from qshield.core.parsers import parse_qasm

READOUT_GATES = frozenset({"h", "x", "y", "s", "sdg", "t", "tdg"})


def strip_readout_gates(source: str) -> str:
    """Remove gates that sit immediately before the measurement block."""
    lines = source.splitlines()
    measure_at = next(
        (i for i, line in enumerate(lines) if line.strip().startswith("measure")), None
    )
    if measure_at is None:
        return source
    cut = measure_at
    while cut > 0:
        stripped = lines[cut - 1].strip()
        if not stripped or stripped.startswith("//"):
            cut -= 1
            continue
        token = stripped.split()[0] if stripped.split() else ""
        if token in READOUT_GATES:
            cut -= 1
            continue
        break
    return "\n".join(lines[:cut] + lines[measure_at:]) + "\n"


def approved_reference_for(path: Path, candidate: CircuitIR | None = None) -> CircuitIR:
    """Return the approved reference circuit for a fixture path."""
    del candidate  # kept for call-site symmetry; the source text is authoritative
    return parse_qasm(strip_readout_gates(Path(path).read_text()))
