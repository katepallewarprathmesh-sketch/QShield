"""Readout structure extraction and differential classification.

T2.3 asks a question about a *change*, not about a pattern. A basis rotation
before measurement is exactly what a correct Deutsch or Bernstein-Vazirani
circuit does, so the gate alone carries no signal. What carries signal is
whether the readout of this circuit differs from the readout of the circuit that
was approved.

This module extracts a comparable readout profile from a parsed circuit and
classifies the difference between two profiles into distinct properties. The
classifications are deliberately not collapsed into one boolean: "equivalent",
"structurally different", "readout changed" and "undecided" are different facts
with different operational consequences.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from qshield.core.canonicalization import CANONICALIZATION_SPEC, canonical_circuit_hash_v1
from qshield.core.circuit_ir import CircuitIR

#: Gates that rotate the measurement basis when they are the final operation on
#: a qubit. Shared with the historical structural rule so both agree on what a
#: basis rotation is; the difference is that this module only ever reasons about
#: a *change* relative to a reference.
BASIS_ROTATION_GATES = frozenset({"h", "x", "y", "s", "sdg", "t", "tdg"})


class ComparisonVerdict(str, Enum):
    """Outcome of comparing a candidate readout against its approved reference."""

    IDENTICAL = "identical"
    """Canonical forms match exactly: same artifact identity."""

    READOUT_DIFFERS = "readout_differs"
    """Readout structure differs: measured qubits, bit mapping, or final operation."""

    STRUCTURE_DIFFERS = "structure_differs"
    """Circuits differ outside the readout: the change is not a readout change."""

    EQUIVALENT = "equivalent"
    """Circuits differ textually or structurally but compute the same function."""

    UNRESOLVED = "unresolved"
    """A difference exists that this comparison cannot classify."""


@dataclass(frozen=True)
class ReadoutPoint:
    """How a single qubit reaches measurement."""

    qubit: int
    clbit: int
    final_gate: str | None
    final_gate_index: int | None
    is_basis_rotation: bool
    depth_to_measure: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "qubit": self.qubit,
            "clbit": self.clbit,
            "final_gate": self.final_gate,
            "final_gate_index": self.final_gate_index,
            "is_basis_rotation": self.is_basis_rotation,
            "depth_to_measure": self.depth_to_measure,
        }


@dataclass(frozen=True)
class ReadoutProfile:
    """Comparable readout structure of a circuit."""

    num_qubits: int
    num_clbits: int
    points: tuple[ReadoutPoint, ...]
    measurement_order: tuple[tuple[int, int], ...]
    canonical_digest: str
    canonical_spec: str = CANONICALIZATION_SPEC

    def point_for(self, qubit: int) -> ReadoutPoint | None:
        for point in self.points:
            if point.qubit == qubit:
                return point
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "num_qubits": self.num_qubits,
            "num_clbits": self.num_clbits,
            "points": [p.to_dict() for p in self.points],
            "canonical_digest": self.canonical_digest,
            "canonical_spec": self.canonical_spec,
        }

    def digest(self) -> str:
        """Digest of the readout structure alone, independent of the rest of the circuit."""
        payload = json.dumps(
            {
                "num_qubits": self.num_qubits,
                "num_clbits": self.num_clbits,
                "points": [p.to_dict() for p in self.points],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(b"qshield-readout-v1\0" + payload).hexdigest()


def extract_readout(circuit: CircuitIR) -> ReadoutProfile:
    """Build the readout profile of a circuit."""
    last_gate: dict[int, tuple[int, str]] = {}
    for index, gate in enumerate(circuit.gates):
        for qubit in gate.qubits:
            last_gate[qubit] = (index, gate.gate_name)

    points: list[ReadoutPoint] = []
    for qubit, clbit in circuit.measurements:
        entry = last_gate.get(qubit)
        final_gate = entry[1] if entry else None
        final_index = entry[0] if entry else None
        points.append(
            ReadoutPoint(
                qubit=qubit,
                clbit=clbit,
                final_gate=final_gate,
                final_gate_index=final_index,
                is_basis_rotation=final_gate in BASIS_ROTATION_GATES,
                depth_to_measure=0,
            )
        )
    points.sort(key=lambda p: p.qubit)
    return ReadoutProfile(
        num_qubits=circuit.num_qubits,
        num_clbits=circuit.num_classical_bits,
        points=tuple(points),
        measurement_order=tuple(circuit.measurements),
        canonical_digest=canonical_circuit_hash_v1(circuit),
    )


@dataclass
class ReadoutDifference:
    """One specific way the candidate readout differs from the reference."""

    kind: str
    qubit: int | None
    detail: str
    reference_value: Any = None
    candidate_value: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "qubit": self.qubit,
            "detail": self.detail,
            "reference_value": self.reference_value,
            "candidate_value": self.candidate_value,
        }


@dataclass
class ReadoutDiff:
    """The full classified difference between a candidate and a reference."""

    verdict: ComparisonVerdict
    differences: list[ReadoutDifference] = field(default_factory=list)
    reference_digest: str = ""
    candidate_digest: str = ""
    reference_readout_digest: str = ""
    candidate_readout_digest: str = ""
    explanation: str = ""

    @property
    def is_readout_change(self) -> bool:
        return self.verdict is ComparisonVerdict.READOUT_DIFFERS

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "differences": [d.to_dict() for d in self.differences],
            "reference_digest": self.reference_digest,
            "candidate_digest": self.candidate_digest,
            "reference_readout_digest": self.reference_readout_digest,
            "candidate_readout_digest": self.candidate_readout_digest,
            "explanation": self.explanation,
        }


def _describe_gate(gate: str | None) -> str:
    return "no gate (direct measurement)" if gate is None else gate


def compare_readout(candidate: CircuitIR, reference: CircuitIR) -> ReadoutDiff:
    """Compare the readout of ``candidate`` against ``reference``.

    The comparison is layered so that a caller can tell an exact match from a
    readout change, a change elsewhere in the circuit, or an unclassifiable
    difference:

    1. canonical identity — identical artifacts;
    2. readout structure — measured qubits, bit mapping, final operation;
    3. circuit structure — anything outside the readout.
    """
    cand = extract_readout(candidate)
    ref = extract_readout(reference)

    base = ReadoutDiff(
        verdict=ComparisonVerdict.IDENTICAL,
        reference_digest=ref.canonical_digest,
        candidate_digest=cand.canonical_digest,
        reference_readout_digest=ref.digest(),
        candidate_readout_digest=cand.digest(),
    )

    if cand.canonical_digest == ref.canonical_digest:
        base.explanation = "Candidate is the approved artifact, unchanged."
        return base

    differences: list[ReadoutDifference] = []

    if cand.num_qubits != ref.num_qubits:
        differences.append(
            ReadoutDifference(
                kind="width_changed",
                qubit=None,
                detail=f"circuit width changed from {ref.num_qubits} to {cand.num_qubits} qubits",
                reference_value=ref.num_qubits,
                candidate_value=cand.num_qubits,
            )
        )
    if cand.num_clbits != ref.num_clbits:
        differences.append(
            ReadoutDifference(
                kind="classical_width_changed",
                qubit=None,
                detail=(
                    f"classical register width changed from {ref.num_clbits} "
                    f"to {cand.num_clbits} bits"
                ),
                reference_value=ref.num_clbits,
                candidate_value=cand.num_clbits,
            )
        )

    cand_q = {p.qubit for p in cand.points}
    ref_q = {p.qubit for p in ref.points}

    for qubit in sorted(cand_q - ref_q):
        differences.append(
            ReadoutDifference(
                kind="qubit_newly_measured",
                qubit=qubit,
                detail=f"q[{qubit}] is measured in the candidate but not in the reference",
                reference_value=None,
                candidate_value=(cp.final_gate if (cp := cand.point_for(qubit)) else None),
            )
        )
    for qubit in sorted(ref_q - cand_q):
        differences.append(
            ReadoutDifference(
                kind="qubit_no_longer_measured",
                qubit=qubit,
                detail=f"q[{qubit}] is measured in the reference but not in the candidate",
                reference_value=(rp.final_gate if (rp := ref.point_for(qubit)) else None),
                candidate_value=None,
            )
        )

    for qubit in sorted(cand_q & ref_q):
        a = cand.point_for(qubit)
        b = ref.point_for(qubit)
        if a is None or b is None:  # defensive: qubits come from the shared set
            continue
        if a.clbit != b.clbit:
            differences.append(
                ReadoutDifference(
                    kind="classical_bit_remapped",
                    qubit=qubit,
                    detail=(
                        f"q[{qubit}] now writes classical bit {a.clbit} "
                        f"instead of {b.clbit}"
                    ),
                    reference_value=b.clbit,
                    candidate_value=a.clbit,
                )
            )
        if a.final_gate != b.final_gate:
            differences.append(
                ReadoutDifference(
                    kind="final_operation_changed",
                    qubit=qubit,
                    detail=(
                        f"the last operation on q[{qubit}] before measurement changed from "
                        f"{_describe_gate(b.final_gate)} to {_describe_gate(a.final_gate)}"
                    ),
                    reference_value=b.final_gate,
                    candidate_value=a.final_gate,
                )
            )
        elif a.is_basis_rotation != b.is_basis_rotation:
            differences.append(
                ReadoutDifference(
                    kind="basis_rotation_changed",
                    qubit=qubit,
                    detail=f"q[{qubit}] changed between rotated and computational readout",
                    reference_value=b.is_basis_rotation,
                    candidate_value=a.is_basis_rotation,
                )
            )

    readout_kinds = {
        "qubit_newly_measured",
        "qubit_no_longer_measured",
        "classical_bit_remapped",
        "final_operation_changed",
        "basis_rotation_changed",
    }
    readout_changes = [d for d in differences if d.kind in readout_kinds]
    structural_changes = [d for d in differences if d.kind not in readout_kinds]

    base.differences = differences

    if readout_changes:
        base.verdict = ComparisonVerdict.READOUT_DIFFERS
        base.explanation = (
            f"{len(readout_changes)} readout difference(s) against the approved "
            "reference: " + "; ".join(d.detail for d in readout_changes[:5])
        )
        return base

    if structural_changes:
        base.verdict = ComparisonVerdict.STRUCTURE_DIFFERS
        base.explanation = (
            "The circuit differs from the reference outside its readout structure "
            f"({len(structural_changes)} difference(s)); the readout itself is unchanged."
        )
        return base

    # Readout profile and width match, yet canonical identity differs. The change
    # is somewhere this module does not model, so it must not be guessed at.
    base.verdict = ComparisonVerdict.UNRESOLVED
    base.explanation = (
        "Readout structure matches the reference but the whole-circuit identity "
        "differs; the change lies outside the readout and was not classified."
    )
    return base
