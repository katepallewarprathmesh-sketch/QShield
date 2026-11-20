"""T2.3 readout-differential evaluator.

Replaces the context-free "basis change before measurement" rule with a check
that only ever speaks about a *change* relative to an approved baseline.

The evaluator has four outcomes and never collapses them:

``PASS``          baseline trusted and the readout is unchanged
``FINDING``       baseline trusted and the readout differs in a specific, named way
``INDETERMINATE`` no usable baseline, or a comparison that cannot be resolved
``ERROR``         malformed input or an internal failure

A missing or unusable baseline is never reported as a pass, and never as a
finding. It is uncertainty, because that is what it is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from qshield.core.circuit_ir import CircuitIR
from qshield.integrity.baseline import BaselineRegistry, BaselineState, BaselineStatus
from qshield.integrity.readout import (
    ComparisonVerdict,
    ReadoutDiff,
    compare_readout,
    extract_readout,
)
from qshield.reporting.finding import CircuitLocation, Evidence, Finding

DETECTOR_ID = "T2.3-readout-differential"
DETECTOR_VERSION = "1.0"


class Outcome(str, Enum):
    """The policy-facing result of a T2.3 evaluation."""

    PASS = "pass"  # noqa: S105 - a verdict name, not a credential
    FINDING = "finding"
    INDETERMINATE = "indeterminate"
    ERROR = "error"


@dataclass
class DifferentialResult:
    """Full result of one T2.3 evaluation."""

    outcome: Outcome
    detail: str
    candidate_digest: str = ""
    reference_digest: str = ""
    readout_diff: ReadoutDiff | None = None
    baseline: BaselineStatus | None = None
    workload_id: str | None = None
    finding: Finding | None = None
    evaluated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    @property
    def is_finding(self) -> bool:
        return self.outcome is Outcome.FINDING

    @property
    def blocked(self) -> bool:
        """True when the outcome must not be treated as an approval."""
        return self.outcome is not Outcome.PASS

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector_id": DETECTOR_ID,
            "detector_version": DETECTOR_VERSION,
            "outcome": self.outcome.value,
            "detail": self.detail,
            "workload_id": self.workload_id,
            "candidate_digest": self.candidate_digest,
            "reference_digest": self.reference_digest,
            "baseline": self.baseline.to_dict() if self.baseline else None,
            "readout_diff": self.readout_diff.to_dict() if self.readout_diff else None,
            "finding_id": self.finding.finding_id if self.finding else None,
            "evaluated_at": self.evaluated_at,
        }


def _finding(
    *,
    diff: ReadoutDiff,
    candidate: CircuitIR,
    workload_id: str,
    baseline_id: str,
) -> Finding:
    """Build the evidence-bearing T2.3 finding."""
    readout_changes = [d for d in diff.differences if d.kind in {
        "qubit_newly_measured",
        "qubit_no_longer_measured",
        "classical_bit_remapped",
        "final_operation_changed",
        "basis_rotation_changed",
    }]
    affected = sorted({d.qubit for d in readout_changes if d.qubit is not None})
    summary = "; ".join(d.detail for d in readout_changes[:4])

    return Finding(
        severity="medium",
        threat_type="T2.3",
        title="Readout differs from the approved baseline",
        description=(
            f"The readout structure of workload {workload_id!r} no longer matches its "
            f"approved reference (baseline {baseline_id}). {summary}. This is a difference "
            "from the artifact that was approved, not an inference from the gate pattern "
            "alone."
        ),
        circuit_id=candidate.circuit_id,
        location=CircuitLocation(qubit_indices=affected),
        evidence=Evidence(
            evidence_type="baseline_differential",
            details={
                "detector": DETECTOR_ID,
                "detector_version": DETECTOR_VERSION,
                "workload_id": workload_id,
                "baseline_id": baseline_id,
                "candidate_digest": diff.candidate_digest,
                "reference_digest": diff.reference_digest,
                "candidate_readout_digest": diff.candidate_readout_digest,
                "reference_readout_digest": diff.reference_readout_digest,
                "difference_category": "readout",
                "differences": [d.to_dict() for d in readout_changes],
            },
        ),
        confidence=0.75,
        remediation=(
            "Confirm the readout change was intended. If it was, approve a new baseline "
            "through the normal approval path. If it was not, restore the circuit from the "
            "approved artifact."
        ),
        false_positive_probability=0.2,
        analysis_type="static",
    )


def evaluate_t23(
    candidate: CircuitIR,
    *,
    registry: BaselineRegistry | None,
    workload_id: str | None = None,
    public_key_pem: bytes | None = None,
    now: datetime | None = None,
) -> DifferentialResult:
    """Evaluate the T2.3 readout-integrity question for one circuit.

    ``workload_id`` defaults to the circuit's name. No baseline means
    ``INDETERMINATE`` — never a pass, never a finding.
    """
    identity = workload_id or candidate.name or candidate.circuit_id
    try:
        candidate_digest = extract_readout(candidate).canonical_digest
    except Exception as exc:  # surfaced as an explicit ERROR state
        return DifferentialResult(
            outcome=Outcome.ERROR,
            detail=f"candidate readout could not be extracted: {exc}",
            workload_id=identity,
        )

    if registry is None:
        return DifferentialResult(
            outcome=Outcome.INDETERMINATE,
            detail=(
                "no baseline registry was supplied, so the readout cannot be compared "
                "against an approved reference"
            ),
            candidate_digest=candidate_digest,
            workload_id=identity,
        )

    status = registry.resolve(identity, public_key_pem=public_key_pem, now=now)
    if not status.usable:
        return DifferentialResult(
            outcome=Outcome.INDETERMINATE,
            detail=_state_detail(status),
            candidate_digest=candidate_digest,
            baseline=status,
            workload_id=identity,
        )

    if status.record is None:  # defensive: usable implies a record
        return DifferentialResult(
            outcome=Outcome.INDETERMINATE,
            detail="baseline was reported usable but carries no record",
            candidate_digest=candidate_digest,
            baseline=status,
            workload_id=identity,
        )
    reference = status.record.reference_circuit
    if reference is None:
        return DifferentialResult(
            outcome=Outcome.INDETERMINATE,
            detail=(
                "the baseline record was verified but its reference circuit is not "
                "available in this session, so no comparison can be made"
            ),
            candidate_digest=candidate_digest,
            baseline=status,
            workload_id=identity,
        )

    # The reference is only usable if it is the artifact the signature covers.
    reference_digest, reference_readout_digest = _digests(reference)
    if reference_digest != status.record.circuit_digest:
        return DifferentialResult(
            outcome=Outcome.INDETERMINATE,
            detail=(
                "the loaded reference circuit does not match the digest bound by the "
                "baseline signature, so the baseline cannot be trusted for this comparison"
            ),
            candidate_digest=candidate_digest,
            reference_digest=reference_digest,
            baseline=status,
            workload_id=identity,
        )
    if reference_readout_digest != status.record.readout_digest:
        return DifferentialResult(
            outcome=Outcome.INDETERMINATE,
            detail=(
                "the loaded reference readout does not match the readout digest bound by "
                "the baseline signature"
            ),
            candidate_digest=candidate_digest,
            reference_digest=reference_digest,
            baseline=status,
            workload_id=identity,
        )

    diff = compare_readout(candidate, reference)

    if diff.verdict in (ComparisonVerdict.IDENTICAL, ComparisonVerdict.EQUIVALENT):
        return DifferentialResult(
            outcome=Outcome.PASS,
            detail=(
                "readout matches the approved reference"
                if diff.verdict is ComparisonVerdict.IDENTICAL
                else "candidate is functionally equivalent to the approved reference"
            ),
            candidate_digest=diff.candidate_digest,
            reference_digest=diff.reference_digest,
            readout_diff=diff,
            baseline=status,
            workload_id=identity,
        )

    if diff.verdict is ComparisonVerdict.READOUT_DIFFERS:
        return DifferentialResult(
            outcome=Outcome.FINDING,
            detail=diff.explanation,
            candidate_digest=diff.candidate_digest,
            reference_digest=diff.reference_digest,
            readout_diff=diff,
            baseline=status,
            workload_id=identity,
            finding=_finding(
                diff=diff,
                candidate=candidate,
                workload_id=identity,
                baseline_id=status.record.baseline_id,
            ),
        )

    if diff.verdict is ComparisonVerdict.STRUCTURE_DIFFERS:
        # A change outside the readout is not a T2.3 finding. It is reported as a
        # pass *for this question* with the difference recorded, so that another
        # detector (or a human) can take it up.
        return DifferentialResult(
            outcome=Outcome.PASS,
            detail=(
                "the circuit differs from the reference outside its readout; "
                "the readout itself is unchanged"
            ),
            candidate_digest=diff.candidate_digest,
            reference_digest=diff.reference_digest,
            readout_diff=diff,
            baseline=status,
            workload_id=identity,
        )

    return DifferentialResult(
        outcome=Outcome.INDETERMINATE,
        detail=diff.explanation,
        candidate_digest=diff.candidate_digest,
        reference_digest=diff.reference_digest,
        readout_diff=diff,
        baseline=status,
        workload_id=identity,
    )


def _digests(circuit: CircuitIR) -> tuple[str, str]:
    from qshield.core.canonicalization import canonical_circuit_hash_v1

    return canonical_circuit_hash_v1(circuit), extract_readout(circuit).digest()


def _state_detail(status: BaselineStatus) -> str:
    mapping = {
        BaselineState.MISSING: "no approved baseline exists for this workload",
        BaselineState.REVOKED: "the baseline for this workload has been revoked",
        BaselineState.EXPIRED: "the baseline for this workload has expired",
        BaselineState.UNVERIFIED: "the baseline could not be verified",
        BaselineState.WRONG_WORKLOAD: "the baseline belongs to a different workload",
        BaselineState.PARSER_INCOMPATIBLE: (
            "the baseline was produced by an incompatible parser or canonicalisation version"
        ),
    }
    head = mapping.get(status.state, f"baseline state is {status.state.value}")
    return f"{head}: {status.reason}" if status.reason else head
