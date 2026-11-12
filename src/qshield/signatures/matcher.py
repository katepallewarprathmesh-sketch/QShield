"""Signature matching engine ('YARA for quantum circuits').

Each builtin signature maps to a parametric check.  The matcher never
executes signature content; patterns are interpreted declaratively.
"""

from __future__ import annotations

import math

import numpy as np

from qshield.core.circuit_ir import CircuitIR, GateNode
from qshield.reporting.finding import CircuitLocation, Evidence, Finding
from qshield.signatures.loader import Signature, builtin_signatures, load_directory

_WINDOW = 8


class SignatureMatcher:
    """Apply a set of loaded signatures to a circuit."""

    def __init__(self, signatures: list[Signature] | None = None):
        self.signatures = signatures if signatures is not None else builtin_signatures()
        self.warnings: list[str] = []

    @classmethod
    def from_paths(cls, paths: list[str]) -> SignatureMatcher:
        sigs: list[Signature] = []
        for p in paths:
            sigs.extend(load_directory(p))
        return cls(sigs)

    # ------------------------------------------------------------------
    def match(self, circuit: CircuitIR) -> list[Finding]:
        findings: list[Finding] = []
        for sig in self.signatures:
            try:
                findings.extend(self._match_one(sig, circuit))
            except Exception as exc:  # a broken signature must not kill the scan
                self.warnings.append(f"Signature {sig.id} failed: {exc}")
        findings.sort(key=lambda f: (f.severity_rank, f.confidence), reverse=True)
        return findings

    # ------------------------------------------------------------------
    def _match_one(self, sig: Signature, circuit: CircuitIR) -> list[Finding]:
        ptype = sig.pattern_type
        params = sig.pattern_params
        handler = {
            "gate_sequence_inverse": self._match_inverse_pair,
            "leaf_ancilla": self._match_leaf_ancilla,
            "parameter_grid_encoding": self._match_parameter_grid,
            "measurement_basis": self._match_measurement_basis,
            "micro_rotation_spread": self._match_micro_rotations,
        }.get(ptype or "")
        if handler is None:
            self.warnings.append(f"Signature {sig.id}: unknown pattern type {ptype!r}; skipped")
            return []
        return handler(sig, circuit, params)

    def _finding(self, sig: Signature, circuit: CircuitIR, **kwargs) -> Finding:
        return Finding(
            severity=sig.severity,
            threat_type=sig.threat_type,
            title=kwargs.pop("title", sig.name),
            description=kwargs.pop("description", sig.description.split("\n")[0]),
            circuit_id=circuit.circuit_id,
            confidence=kwargs.pop("confidence", 1.0 - sig.false_positive_probability),
            remediation=kwargs.pop("remediation", sig.remediation),
            references=list(sig.references),
            false_positive_probability=sig.false_positive_probability,
            signature_id=sig.id,
            analysis_type="static",
            **kwargs,
        )

    # ------------------------------------------------------------------
    def _match_inverse_pair(self, sig, circuit, params) -> list[Finding]:
        tol = float(params.get("tolerance", 1e-6))
        window = int(params.get("window", _WINDOW))
        gates = circuit.gates
        out: list[Finding] = []
        for i, gi in enumerate(gates):
            if gi.unitary is None:
                continue
            for j in range(i + 1, min(i + 1 + window, len(gates))):
                gj = gates[j]
                intervening = gates[i + 1:j]
                if any(set(g.qubits) & set(gi.qubits) for g in intervening):
                    break
                if gj.qubits != gi.qubits or gj.unitary is None:
                    continue
                ident = np.eye(gi.unitary.shape[0], dtype=complex)
                if np.linalg.norm(gj.unitary @ gi.unitary - ident) < tol:
                    out.append(self._finding(
                        sig, circuit,
                        title=f"{sig.name}: {gi.gate_name}(#{i}) x {gj.gate_name}(#{j})",
                        description=(
                            f"Signature {sig.id}: gates at indices {i} and {j} on qubits "
                            f"{gi.qubits} cancel to within {tol:g} of identity."
                        ),
                        location=CircuitLocation(
                            gate_ids=[gi.gate_id, gj.gate_id],
                            qubit_indices=list(gi.qubits),
                            gate_indices=[i, j],
                        ),
                        evidence=Evidence(evidence_type="unitary_mismatch",
                                          details={"gate_indices": [i, j], "tolerance": tol}),
                        confidence=0.6,
                    ))
        return out

    def _match_leaf_ancilla(self, sig, circuit, params) -> list[Finding]:
        max_uses = int(params.get("max_ancilla_uses", 1))
        require_meas = bool(params.get("require_measurement", True))
        usage = circuit.get_qubit_usage()
        measured = {q for q, _ in circuit.measurements}
        out: list[Finding] = []
        for idx, gate in enumerate(circuit.gates):
            if len(gate.qubits) != 2 or gate.gate_type.value == "parameterized":
                continue
            for side in gate.qubits:
                if usage.get(side, 0) <= max_uses and (not require_meas or side in measured):
                    out.append(self._finding(
                        sig, circuit,
                        title=f"{sig.name}: q[{side}]",
                        description=(
                            f"Signature {sig.id}: q[{side}] is touched only by "
                            f"{gate.gate_name} (index {idx})"
                            + (" and is measured — consistent with an ancilla leaking computation data."
                               if side in measured else ".")
                        ),
                        location=CircuitLocation(
                            gate_ids=[gate.gate_id],
                            qubit_indices=list(gate.qubits),
                            gate_indices=[idx],
                        ),
                        evidence=Evidence(evidence_type="structural",
                                          details={"ancilla_qubit": side, "total_uses": usage.get(side, 0)}),
                        confidence=0.4,
                    ))
        return out

    def _match_parameter_grid(self, sig, circuit, params) -> list[Finding]:
        min_run = int(params.get("min_run", 6))
        lo, hi = params.get("ascii_range", [32, 126])
        hits: list[tuple[int, int]] = []
        for idx, gate in enumerate(circuit.gates):
            for p in gate.parameters:
                if math.isnan(p):
                    continue
                n_grid = p * 4096.0 / math.pi
                nearest = round(n_grid)
                if nearest != 0 and abs(n_grid - nearest) < 1e-6:
                    byte = int(nearest) & 0x7F
                    hits.append((idx, byte))
        best_run = 0
        cur: list[tuple[int, int]] = []
        for idx, byte in hits:
            if lo <= byte <= hi:
                cur.append((idx, byte))
                best_run = max(best_run, len(cur))
            else:
                cur = []
        if best_run >= min_run:
            decoded = "".join(chr(b) for _, b in hits if lo <= b <= hi)[:32]
            return [self._finding(
                sig, circuit,
                title=sig.name,
                description=(
                    f"Signature {sig.id}: {best_run} consecutive angles are exact multiples of "
                    f"pi/4096 decoding to printable ASCII ({decoded!r}…)."
                ),
                location=CircuitLocation(gate_indices=[i for i, _ in hits]),
                evidence=Evidence(evidence_type="structural",
                                  details={"decoded_prefix": decoded, "hits": len(hits)}),
                confidence=0.6,
            )]
        return []

    def _match_measurement_basis(self, sig, circuit, params) -> list[Finding]:
        watch = set(params.get("gates", ["h", "s", "sdg", "x", "y"]))
        measured = {q for q, _ in circuit.measurements}
        if not measured:
            return []
        last_gate: dict[int, tuple[int, GateNode]] = {}
        for idx, gate in enumerate(circuit.gates):
            for q in gate.qubits:
                last_gate[q] = (idx, gate)
        out: list[Finding] = []
        for q in sorted(measured):
            entry = last_gate.get(q)
            if not entry:
                continue
            idx, gate = entry
            if gate.gate_name in watch:
                out.append(self._finding(
                    sig, circuit,
                    title=f"{sig.name}: {gate.gate_name} before measuring q[{q}]",
                    description=(
                        f"Signature {sig.id}: {gate.gate_name} (index {idx}) is the last gate before "
                        f"measurement of q[{q}]; the effective measurement basis is rotated."
                    ),
                    location=CircuitLocation(
                        gate_ids=[gate.gate_id],
                        qubit_indices=[q], gate_indices=[idx],
                    ),
                    evidence=Evidence(evidence_type="structural",
                                      details={"gate": gate.gate_name, "qubit": q}),
                    confidence=0.6,
                ))
        return out

    def _match_micro_rotations(self, sig, circuit, params) -> list[Finding]:
        max_angle = float(params.get("max_angle", 0.01))
        min_occ = int(params.get("min_occurrences", 6))
        micro = []
        for idx, gate in enumerate(circuit.gates):
            if gate.gate_name in {"rx", "ry", "rz", "p", "u1", "crz"} and gate.parameters:
                theta = gate.parameters[0]
                if not math.isnan(theta) and 0 < abs(theta) < max_angle:
                    micro.append((idx, abs(theta), gate))
        if len(micro) >= min_occ:
            return [self._finding(
                sig, circuit,
                title=sig.name,
                description=(
                    f"Signature {sig.id}: {len(micro)} rotations below {max_angle} rad found; "
                    "cumulative rotation may bias results."
                ),
                location=CircuitLocation(gate_indices=[m[0] for m in micro],
                                         qubit_indices=sorted({m[2].qubits[0] for m in micro})),
                evidence=Evidence(evidence_type="structural",
                                  details={"occurrences": len(micro)}),
                confidence=0.6,
            )]
        return []
