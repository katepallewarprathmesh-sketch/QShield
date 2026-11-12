"""Circuit-in-transit integrity verification.

Two independent checks run on every intercepted circuit:

1. **Commitment check** — if the submitting party declared an expected
   canonical hash (``X-QShield-Expected-Hash`` header), the intercepted
   circuit's canonical hash must equal it. This is the cryptographic
   "signed commitment" model: the submitter commits to the circuit it
   intends to run; the proxy proves the bytes on the wire match.

2. **Static integrity scan** — the CircuitIR is run through the structural
   analyzer; findings at or above the configured severity are reported.
   This catches *undeclared* tampering (e.g., a compromised transpiler)
   when no commitment was supplied.

Canonical hash: sha256 over the gate sequence, ``name|q0,q1,…|p0,p1,…`` per
gate (parameters quantised to a 1e-9 grid), followed by measurement lines
``m|q->c`` and the qubit count. Semantics-preserving rewrites generally do
NOT preserve this hash — it is a byte-exact identity check, not an
equivalence check, by design: integrity means "exactly the circuit you
committed to", and equivalence is the formal layer's job (``qshield
compare --formal``).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from qshield.core.circuit_ir import CircuitIR

HASH_HEADER = "X-QShield-Expected-Hash"

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def canonical_circuit_hash(ir: CircuitIR, *, param_grid: float = 1e-9) -> str:
    """Deterministic sha256 of the gate/measurement sequence."""
    lines: list[str] = []
    for gate in ir.gates:
        params = ",".join(f"{p:.9f}" for p in gate.parameters)
        qubits = ",".join(str(q) for q in gate.qubits)
        lines.append(f"{gate.gate_name}|{qubits}|{params}")
    for qubit, clbit in ir.measurements:
        lines.append(f"m|{qubit}->{clbit}")
    lines.append(f"n={ir.num_qubits}")
    digest = hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()
    return digest


@dataclass
class CommitmentResult:
    expected: str | None
    actual: str
    ok: bool | None  # None => no commitment supplied

    @property
    def status(self) -> str:
        if self.ok is None:
            return "absent"
        return "ok" if self.ok else "mismatch"


@dataclass
class IntegrityReport:
    circuit_hash: str
    commitment: CommitmentResult
    findings: list = field(default_factory=list)  # list[qshield.reporting.finding.Finding]
    parse_error: str | None = None

    @property
    def max_severity(self) -> str | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_RANK.get(s, 0))

    def findings_at_least(self, severity: str) -> list:
        threshold = SEVERITY_RANK.get(severity, 3)
        return [f for f in self.findings if SEVERITY_RANK.get(f.severity, 0) >= threshold]


def verify_commitment(ir: CircuitIR, expected_hash: str | None) -> CommitmentResult:
    actual = canonical_circuit_hash(ir)
    if expected_hash is None:
        return CommitmentResult(expected=None, actual=actual, ok=None)
    expected_norm = expected_hash.strip().lower().removeprefix("sha256:")
    return CommitmentResult(expected=expected_norm, actual=actual, ok=(actual == expected_norm))


def scan_integrity(ir: CircuitIR, *, config=None) -> list:
    """Run the static structural battery on the circuit. Returns findings."""
    from qshield.static.structural_analyzer import StructuralAnalyzer

    analyzer = StructuralAnalyzer(config=config)
    return analyzer.analyze(ir)


def inspect_circuit(
    ir: CircuitIR,
    *,
    expected_hash: str | None = None,
    static_config=None,
    run_static: bool = True,
) -> IntegrityReport:
    commitment = verify_commitment(ir, expected_hash)
    findings = scan_integrity(ir, config=static_config) if run_static else []
    return IntegrityReport(circuit_hash=commitment.actual, commitment=commitment, findings=findings)
