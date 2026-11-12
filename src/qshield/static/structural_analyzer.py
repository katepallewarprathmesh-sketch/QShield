"""Structural anomaly detection (Algorithm 1 in the specification).

Detects suspicious patterns in the circuit DAG without executing the
circuit.  Implemented checks:

* ``check_dead_qubits``          — unused / low-activity measured qubits
* ``check_gate_cancellation``    — gate pairs whose product is identity
* ``check_entanglement_anomaly`` — leaf-ancilla entanglement / suspicious fan-out
* ``check_parameter_anomaly``    — suspicious angles, micro-rotation spreading,
                                   steganographic parameter encoding
* ``check_gate_count_heuristic`` — gate-count and entanglement-density heuristics
* ``check_measurement_basis``    — basis rotations directly before measurement

All checks are O(G * W) with G gates and window W, except unitary products
on small matrices.
"""

from __future__ import annotations

import math
from collections import Counter

import numpy as np

from qshield.core.circuit_ir import CircuitIR, GateNode
from qshield.core.config import QShieldConfig, load_config
from qshield.reporting.finding import CircuitLocation, Evidence, Finding

_WINDOW = 8


def _cancelling_pair_members(gates, tol):
    """Indices of gates that participate in a matched cancelling pair.

    Identity noise (s+sdg, h+h, cx+cx separated) is the classic camouflage
    for hidden structure.  Effective-usage accounting for the leaf-ancilla
    and low-activity rules discounts these gates so that inserting pairs
    cannot disguise a minimally-touched measured qubit.  Greedy, not
    injective: a gate with any cancelling partner is noise for usage
    purposes.
    """
    members: set[int] = set()
    for i, gi in enumerate(gates):
        if gi.unitary is None:
            continue
        for j in range(i + 1, min(i + 1 + _WINDOW, len(gates))):
            gj = gates[j]
            intervening = gates[i + 1:j]
            if any(set(g.qubits) & set(gi.qubits) for g in intervening):
                break
            if not _same_qubit_set(gi, gj):
                continue
            dist = _mats_cancel(gi, gj, tol)
            if dist is not None and dist < tol:
                members.add(i)
                members.add(j)
                break
    return members


def _effective_usage(circuit, tol):
    usage: Counter[int] = Counter()
    noise = _cancelling_pair_members(circuit.gates, tol)
    for i, gate in enumerate(circuit.gates):
        if i in noise:
            continue
        for q in gate.qubits:
            usage[q] += 1
    return usage

_CANCEL_TOL = 1e-6

# Gates whose presence right before measurement is worth flagging (T2.3).
_BASIS_CHANGE_GATES = {"h": ("medium", 0.65), "x": ("low", 0.4), "y": ("low", 0.4),
                       "s": ("low", 0.45), "sdg": ("low", 0.45),
                       "t": ("info", 0.3), "tdg": ("info", 0.3)}


def _same_qubit_set(a: GateNode, b: GateNode) -> bool:
    return a.qubits == b.qubits


_CANCEL_CACHE: dict[bytes, float | None] = {}
_CANCEL_CACHE_MAX = 8192


def _mats_cancel(a: GateNode, b: GateNode, tol: float) -> float | None:
    """Return ||U_b @ U_a - I||_F if both unitaries known, else None.

    Cached by (U_b, U_a, tol) bytes — the parser hands out fresh arrays but
    identical gates are byte-identical, and cancellation is the analyzer's
    hot path on gate-heavy circuits. ``tol`` is part of the key, so cached
    entries never cross tolerance configurations.
    """
    if a.unitary is None or b.unitary is None:
        return None
    if a.unitary.shape != b.unitary.shape:
        return None
    import struct

    ua = np.ascontiguousarray(a.unitary, dtype=complex)
    ub = np.ascontiguousarray(b.unitary, dtype=complex)
    key = ub.tobytes() + ua.tobytes() + struct.pack("<d", float(tol))
    cached = _CANCEL_CACHE.get(key)
    if key in _CANCEL_CACHE:
        return cached
    ident = np.eye(ua.shape[0], dtype=complex)
    product = ub @ ua
    result = float(np.linalg.norm(product - ident))
    if len(_CANCEL_CACHE) >= _CANCEL_CACHE_MAX:
        _CANCEL_CACHE.clear()
    _CANCEL_CACHE[key] = result
    return result


class StructuralAnalyzer:
    """Battery of structural checks over a CircuitIR."""

    def __init__(self, config: QShieldConfig | None = None):
        self.config = config or load_config("default")

    # ------------------------------------------------------------------
    def analyze(self, circuit: CircuitIR) -> list[Finding]:
        cfg = self.config
        findings: list[Finding] = []
        if cfg.static_check("check_dead_qubits"):
            findings += self.check_dead_qubits(circuit)
        if cfg.static_check("check_gate_cancellation"):
            findings += self.check_gate_cancellation(circuit)
        if cfg.static_check("check_entanglement_anomaly"):
            findings += self.check_entanglement_anomaly(circuit)
        if cfg.static_check("check_parameter_anomaly"):
            findings += self.check_parameter_anomaly(circuit)
        if cfg.static_check("check_gate_count_heuristic"):
            findings += self.check_gate_count_heuristic(circuit)
        if cfg.static_check("check_measurement_basis"):
            findings += self.check_measurement_basis(circuit)
        min_conf = cfg.threshold("min_confidence")
        findings = [f for f in findings if f.confidence >= min_conf]
        findings.sort(key=lambda f: (f.severity_rank, f.confidence), reverse=True)
        return findings

    # ------------------------------------------------------------------
    # 1. Dead / low-activity qubits
    # ------------------------------------------------------------------
    def check_dead_qubits(self, circuit: CircuitIR) -> list[Finding]:
        findings: list[Finding] = []
        usage = _effective_usage(circuit, float(self.config.threshold("cancellation_tolerance")))
        measured = {q for q, _ in circuit.measurements}
        ent_pairs = circuit.get_entanglement_map()
        entangled = {q for pair in ent_pairs for q in pair}
        min_activity = int(self.config.threshold("min_qubit_activity"))

        for q in range(circuit.num_qubits):
            n = usage.get(q, 0)
            if n == 0:
                is_measured = q in measured
                findings.append(Finding(
                    severity="low" if is_measured else "info",
                    threat_type="T2.1" if is_measured else "T1.3",
                    title="Allocated qubit never used",
                    description=(
                        f"Qubit q[{q}] is allocated but no gate acts on it"
                        + (" yet it is measured; the written bit carries no information" if is_measured else "")
                        + ". Dead qubits may indicate leftover scaffolding or an unfinished backdoor."
                    ),
                    circuit_id=circuit.circuit_id,
                    location=CircuitLocation(qubit_indices=[q]),
                    evidence=Evidence(evidence_type="structural", details={"qubit": q, "gate_count": 0, "measured": is_measured}),
                    confidence=0.7,
                    remediation="Remove the unused qubit or verify why it is present; investigate if it is measured.",
                    false_positive_probability=0.3,
                    analysis_type="static",
                ))
            elif n < min_activity and q in measured:
                is_entangled = q in entangled
                findings.append(Finding(
                    severity="low",
                    threat_type="T2.1",
                    title="Low-activity measured qubit (possible covert channel)",
                    description=(
                        f"Qubit q[{q}] participates in only {n} gate(s) but is measured. "
                        "A minimally-touched measured qubit is a classic ancilla-leakage pattern: "
                        "it may be used to exfiltrate information about the computation."
                    ),
                    circuit_id=circuit.circuit_id,
                    location=CircuitLocation(qubit_indices=[q]),
                    evidence=Evidence(evidence_type="structural", details={"qubit": q, "gate_count": n, "entangled": is_entangled}),
                    confidence=0.45 if is_entangled else 0.35,
                    remediation="Verify the qubit's role; remove it or justify its measurement. Check what information it carries.",
                    false_positive_probability=0.45,
                    analysis_type="static",
                ))
        return findings

    # ------------------------------------------------------------------
    # 2. Gate cancellation pairs
    # ------------------------------------------------------------------
    def check_gate_cancellation(self, circuit: CircuitIR) -> list[Finding]:
        findings: list[Finding] = []
        gates = circuit.gates
        tol = float(self.config.threshold("cancellation_tolerance"))
        flagged: set[tuple[int, int]] = set()
        for i, gi in enumerate(gates):
            if gi.unitary is None:
                continue
            for j in range(i + 1, min(i + 1 + _WINDOW, len(gates))):
                gj = gates[j]
                # intervening gate must not touch the same qubits
                intervening = gates[i + 1:j]
                if any(set(g.qubits) & set(gi.qubits) for g in intervening):
                    break
                if not _same_qubit_set(gi, gj):
                    if set(gj.qubits) & set(gi.qubits):
                        continue
                    continue
                dist = _mats_cancel(gi, gj, tol)
                if dist is not None and dist < tol and (i, j) not in flagged:
                    flagged.add((i, j))
                    findings.append(Finding(
                        severity="low",
                        threat_type="T1.3",
                        title="Gate cancellation pair",
                        description=(
                            f"Gates {gi.gate_name} (index {i}) and {gj.gate_name} (index {j}) "
                            f"act on the same qubits and cancel to within {dist:.2e} of the identity. "
                            "Cancelling pairs are a common obfuscation / leftover-backdoor pattern."
                        ),
                        circuit_id=circuit.circuit_id,
                        location=CircuitLocation(
                            gate_ids=[gi.gate_id, gj.gate_id],
                            qubit_indices=list(gi.qubits),
                            gate_indices=[i, j],
                        ),
                        evidence=Evidence(
                            evidence_type="unitary_mismatch",
                            details={"frobenius_distance_to_identity": dist, "gate_indices": [i, j]},
                        ),
                        confidence=0.6,
                        remediation="Remove the redundant pair or document why it exists.",
                        false_positive_probability=0.5,
                        analysis_type="static",
                    ))
        return findings

    # ------------------------------------------------------------------
    # 3. Entanglement anomalies
    # ------------------------------------------------------------------
    def check_entanglement_anomaly(self, circuit: CircuitIR) -> list[Finding]:
        findings: list[Finding] = []
        usage = _effective_usage(circuit, float(self.config.threshold("cancellation_tolerance")))
        measured = {q for q, _ in circuit.measurements}

        for gate_idx, gate in enumerate(circuit.gates):
            if len(gate.qubits) != 2:
                continue
            for side in gate.qubits:
                other_gates = usage.get(side, 0)
                # leaf qubit: touched by exactly one (this) gate and measured
                if other_gates == 1 and side in measured:
                    findings.append(Finding(
                        severity="low",
                        threat_type="T2.1",
                        title="Leaf-ancilla entanglement before measurement",
                        description=(
                            f"Qubit q[{side}] is touched only by {gate.gate_name} "
                            f"(gate index {gate_idx}) and then measured. A qubit that exists solely "
                            "to absorb information from the computation is a prime ancilla-leakage suspect."
                        ),
                        circuit_id=circuit.circuit_id,
                        location=CircuitLocation(
                            gate_ids=[gate.gate_id],
                            qubit_indices=list(gate.qubits),
                            gate_indices=[gate_idx],
                        ),
                        evidence=Evidence(
                            evidence_type="structural",
                            details={"ancilla_qubit": side, "entangling_gate": gate.gate_name},
                        ),
                        confidence=0.45,
                        remediation="Remove the ancilla or justify its measurement. Verify no information about the computation is leaked.",
                        false_positive_probability=0.55,
                        analysis_type="static",
                    ))

        # fan-out heuristic: one control fanning out to many disjoint targets
        fanout: Counter[int] = Counter()
        for gate in circuit.gates:
            if gate.gate_name in {"cx", "cy", "cz", "crz", "cp", "crx", "cry"} and len(gate.qubits) == 2:
                fanout[gate.qubits[0]] += 1
        for control, count in fanout.items():
            targets = {g.qubits[1] for g in circuit.gates
                       if g.gate_name in {"cx", "cy", "cz", "crz", "cp", "crx", "cry"} and g.qubits[0] == control}
            if len(targets) >= 4 and count >= 6:
                findings.append(Finding(
                    severity="info",
                    threat_type="T2.1",
                    title="High fan-out from a single qubit",
                    description=(
                        f"Qubit q[{control}] acts as control for {count} two-qubit gates "
                        f"spread over {len(targets)} targets. Broadcasting a control qubit to many "
                        "targets is occasionally used to spread hidden correlations."
                    ),
                    circuit_id=circuit.circuit_id,
                    location=CircuitLocation(qubit_indices=[control, *sorted(targets)]),
                    evidence=Evidence(evidence_type="structural", details={"control": control, "targets": sorted(targets), "count": count}),
                    confidence=0.35,
                    remediation="Review whether the fan-out is algorithmically necessary (e.g. QEC syndrome extraction).",
                    false_positive_probability=0.6,
                    analysis_type="static",
                ))
        return findings

    # ------------------------------------------------------------------
    # 4. Parameter anomalies
    # ------------------------------------------------------------------
    def check_parameter_anomaly(self, circuit: CircuitIR) -> list[Finding]:
        findings: list[Finding] = []
        max_precision = int(self.config.threshold("max_parameter_precision"))
        micro_thresh = float(self.config.threshold("micro_rotation_threshold"))
        micro_min = int(self.config.threshold("micro_rotation_min_occurrences"))

        for gate_idx, gate in enumerate(circuit.gates):
            for param in gate.parameters:
                if math.isnan(param):  # symbolic parameter, not an anomaly
                    continue
                theta = float(param)
                if abs(theta) > 4 * math.pi:
                    findings.append(Finding(
                        severity="info",
                        threat_type="T1.1",
                        title="Unnormalised rotation angle",
                        description=f"Gate {gate.gate_name} at index {gate_idx} uses |theta| > 4*pi ({theta}). Usually benign, but worth normalising.",
                        circuit_id=circuit.circuit_id,
                        location=CircuitLocation(gate_ids=[gate.gate_id], qubit_indices=list(gate.qubits), gate_indices=[gate_idx]),
                        evidence=Evidence(evidence_type="structural", details={"angle": theta}),
                        confidence=0.25,
                        remediation="Normalise angle modulo 2*pi.",
                        false_positive_probability=0.7,
                        analysis_type="static",
                    ))
                frac_digits = _fractional_digits(theta)
                if frac_digits > max_precision:
                    findings.append(Finding(
                        severity="low",
                        threat_type="T1.1",
                        title="Suspiciously high-precision rotation angle",
                        description=(
                            f"Gate {gate.gate_name} at index {gate_idx} uses theta={theta!r} "
                            f"({frac_digits} fractional digits). Attackers hide payloads in "
                            "angles with more precision than the algorithm requires."
                        ),
                        circuit_id=circuit.circuit_id,
                        location=CircuitLocation(gate_ids=[gate.gate_id], qubit_indices=list(gate.qubits), gate_indices=[gate_idx]),
                        evidence=Evidence(evidence_type="structural", details={"angle": theta, "fractional_digits": frac_digits}),
                        confidence=0.5,
                        remediation="Round angles to the precision the algorithm genuinely needs and re-verify.",
                        false_positive_probability=0.5,
                        analysis_type="static",
                    ))

        # Distributed micro-rotation backdoor (ADV-001 style)
        micro: list[tuple[int, float, str]] = []
        for gate_idx, gate in enumerate(circuit.gates):
            if gate.gate_name in {"rx", "ry", "rz", "p", "u1", "crz"} and gate.parameters:
                theta = gate.parameters[0]
                if not math.isnan(theta) and 0 < abs(theta) < micro_thresh:
                    micro.append((gate_idx, abs(theta), gate.gate_name))
        if len(micro) >= micro_min:
            angles = [m[1] for m in micro]
            spread = max(angles) - min(angles)
            findings.append(Finding(
                severity="medium",
                threat_type="T1.1",
                title="Repeated micro-rotation pattern (distributed backdoor)",
                description=(
                    f"{len(micro)} rotations below {micro_thresh} rad were found "
                    f"(spread {spread:.2e}). Splitting a perturbation into many tiny rotations "
                    "defeats single-gate inspection; the cumulative effect may still bias results."
                ),
                circuit_id=circuit.circuit_id,
                location=CircuitLocation(gate_indices=[m[0] for m in micro],
                                         qubit_indices=sorted({circuit.gates[m[0]].qubits[0] for m in micro})),
                evidence=Evidence(evidence_type="structural", details={"occurrences": len(micro), "angles": angles[:20]}),
                confidence=0.6,
                remediation="Accumulate the micro-rotations per qubit and compare against the claimed algorithm; treat unexplained accumulation as a defect.",
                false_positive_probability=0.45,
                analysis_type="static",
            ))

        # Steganographic parameter encoding: angles snapped to a pi/4096 grid
        # whose bytes are all printable ASCII.
        grid_angles: list[tuple[int, int]] = []  # (gate_idx, byte)
        for gate_idx, gate in enumerate(circuit.gates):
            for param in gate.parameters:
                if math.isnan(param):
                    continue
                n_grid = param * 4096.0 / math.pi
                nearest = round(n_grid)
                if nearest != 0 and abs(n_grid - nearest) < 1e-6:
                    byte = int(nearest) & 0x7F
                    grid_angles.append((gate_idx, byte))
        run = _longest_printable_run([b for _, b in grid_angles])
        if run >= 6:
            findings.append(Finding(
                severity="high",
                threat_type="T2.2",
                title="Parameter-encoded ASCII payload suspected",
                description=(
                    f"At least {run} consecutive rotation angles are exact multiples of pi/4096 "
                    "and decode (byte = round(theta*4096/pi) & 0x7F) to printable ASCII. "
                    "This is characteristic of steganographic exfiltration hidden in gate parameters."
                ),
                circuit_id=circuit.circuit_id,
                location=CircuitLocation(gate_indices=list({g for g, _ in grid_angles})),
                evidence=Evidence(
                    evidence_type="structural",
                    details={"decoded_prefix": _decode_ascii([b for _, b in grid_angles])[:32]},
                ),
                confidence=0.55,
                remediation="Decode the parameters and inspect the payload; purge and rebuild the circuit from a trusted source.",
                false_positive_probability=0.35,
                analysis_type="static",
            ))
        return findings

    # ------------------------------------------------------------------
    # 5. Gate count heuristics
    # ------------------------------------------------------------------
    def check_gate_count_heuristic(self, circuit: CircuitIR) -> list[Finding]:
        findings: list[Finding] = []
        gates = circuit.gates
        total = len(gates)
        if total == 0:
            return findings

        expected = circuit.metadata.get("expected_gate_count")
        multiplier = float(self.config.threshold("gate_count_multiplier"))
        if isinstance(expected, (int, float)) and expected > 0 and total > multiplier * expected:
            findings.append(Finding(
                severity="high",
                threat_type="T1.3",
                title="Gate count anomaly",
                description=(
                    f"Circuit contains {total} gates, more than {multiplier}x the expected "
                    f"{int(expected)} for the declared algorithm. Extra gates may be injected backdoors."
                ),
                circuit_id=circuit.circuit_id,
                location=CircuitLocation(),
                evidence=Evidence(evidence_type="structural", details={"gate_count": total, "expected": expected}),
                confidence=0.7,
                remediation="Diff against the reference implementation; remove unaccounted-for gates.",
                false_positive_probability=0.3,
                analysis_type="static",
            ))

        entangling = sum(1 for g in gates if len(g.qubits) >= 2)
        if total >= 20 and entangling / total > 0.9:
            findings.append(Finding(
                severity="info",
                threat_type="T1.3",
                title="Very high entangling-gate density",
                description=f"{entangling}/{total} gates are multi-qubit. Verify this matches the algorithm's structure.",
                circuit_id=circuit.circuit_id,
                location=CircuitLocation(),
                evidence=Evidence(evidence_type="structural", details={"entangling": entangling, "total": total}),
                confidence=0.3,
                remediation="Compare gate-type distribution with a trusted reference circuit.",
                false_positive_probability=0.6,
                analysis_type="static",
            ))
        return findings

    # ------------------------------------------------------------------
    # 6. Basis rotations before measurement (T2.3)
    # ------------------------------------------------------------------
    def check_measurement_basis(self, circuit: CircuitIR) -> list[Finding]:
        findings: list[Finding] = []
        if not circuit.measurements:
            return findings
        measured = {q for q, _ in circuit.measurements}
        last_gate: dict[int, tuple[int, GateNode]] = {}
        for idx, gate in enumerate(circuit.gates):
            for q in gate.qubits:
                last_gate[q] = (idx, gate)
        for q in sorted(measured):
            entry = last_gate.get(q)
            if not entry:
                continue
            idx, gate = entry
            hit = _BASIS_CHANGE_GATES.get(gate.gate_name)
            if hit is None:
                continue
            severity, confidence = hit
            findings.append(Finding(
                severity=severity,
                threat_type="T2.3",
                title=f"Basis change ({gate.gate_name}) immediately before measurement",
                description=(
                    f"Qubit q[{q}] is measured right after a {gate.gate_name} gate (index {idx}). "
                    "Measuring in a rotated basis is legitimate in some protocols, but it is also "
                    "the canonical way to leak information about unmeasured input states."
                ),
                circuit_id=circuit.circuit_id,
                location=CircuitLocation(gate_ids=[gate.gate_id], qubit_indices=[q], gate_indices=[idx]),
                evidence=Evidence(evidence_type="structural", details={"gate": gate.gate_name, "qubit": q}),
                confidence=confidence,
                remediation="Confirm the basis rotation is required by the algorithm; otherwise remove it or measure in the computational basis.",
                false_positive_probability=0.45,
                analysis_type="static",
            ))
        return findings


# ----------------------------------------------------------------------
def _fractional_digits(value: float) -> int:
    text = repr(abs(float(value)))
    if "e" in text or "E" in text:
        mantissa, _, _exp = text.lower().partition("e")
        frac = mantissa.split(".")[1] if "." in mantissa else ""
        return len(frac)
    if "." in text:
        frac = text.split(".")[1]
        return len(frac.rstrip("0")) or 0
    return 0


def _longest_printable_run(bytes_: list[int]) -> int:
    best = cur = 0
    for b in bytes_:
        if 32 <= b <= 126:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def _decode_ascii(bytes_: list[int]) -> str:
    return "".join(chr(b) for b in bytes_ if 32 <= b <= 126)
