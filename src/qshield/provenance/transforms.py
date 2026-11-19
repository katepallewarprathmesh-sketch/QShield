"""Transpilation-stage identity and equivalence reports (v1)."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

from qshield.core.canonicalization import CANONICALIZATION_SPEC, canonical_circuit_hash_v1
from qshield.core.parsers.qasm_parser import parse_qasm

TRANSFORM_REPORT_SPEC = "qshield-transform-report-v1"
_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class TransformReportError(ValueError):
    """Invalid transformation report request or unreadable circuit."""


def _identity(path: Path) -> tuple[Any, dict[str, str]]:
    if not path.is_file():
        raise TransformReportError(f"circuit is not a file: {path}")
    if path.suffix.lower() not in {".qasm", ".qasm2", ".qasm3", ".q"}:
        raise TransformReportError(f"unsupported circuit extension: {path.suffix}")
    try:
        raw = path.read_bytes()
        source = raw.decode("utf-8")
        ir = parse_qasm(source, name=path.stem)
        digest = canonical_circuit_hash_v1(ir)
    except (OSError, UnicodeError, ValueError) as exc:
        raise TransformReportError(f"could not parse {path.name}: {exc}") from exc
    header = re.search(rb"\bOPENQASM\s+([0-9]+(?:\.[0-9]+)?)\s*;", raw, re.IGNORECASE)
    fmt = "openqasm-" + (header.group(1).decode("ascii") if header else ("3" if path.suffix.lower() == ".qasm3" else "2"))
    return ir, {"format": fmt, "source_sha256": hashlib.sha256(raw).hexdigest(), "circuit_sha256": digest}


def _decision(before: Any, after: Any, *, tolerance: float, prefer_formal: bool) -> dict[str, str]:
    if before.num_qubits != after.num_qubits:
        return {
            "status": "inconclusive",
            "method": "unavailable",
            "scope": "none",
            "message": f"qubit-width mismatch ({before.num_qubits} vs {after.num_qubits}); no embedding policy is defined",
        }
    if before.num_classical_bits != after.num_classical_bits or before.measurements != after.measurements:
        return {
            "status": "inconclusive",
            "method": "unavailable",
            "scope": "none",
            "message": "classical output width or measurement mapping differs; comparison does not infer an output remapping",
        }

    if canonical_circuit_hash_v1(before) == canonical_circuit_hash_v1(after):
        return {
            "status": "equivalent",
            "method": "canonical_identity",
            "scope": "exact structural identity under qshield-circuit-c14n-v1",
            "message": "canonical circuit digests match; this is identity evidence, not a separate semantic proof",
        }

    def try_formal() -> dict[str, str] | None:
        from qshield.formal import zx_equivalence_check

        result = zx_equivalence_check(before, after)
        if result.equivalent is None:
            return None
        return {
            "status": "equivalent" if result.equivalent else "not_equivalent",
            "method": result.method,
            "scope": "ZX-calculus or bounded exact tensor fallback",
            "message": result.message,
        }

    formal_error: str | None = None
    if prefer_formal:
        try:
            formal = try_formal()
            if formal is not None:
                return formal
        except Exception as exc:
            # The bounded exact comparison below can still decide small cases.
            formal_error = str(exc)

    if before.measurements == after.measurements:
        unitary_before = before.to_unitary()
        unitary_after = after.to_unitary()
        if (unitary_before is not None and unitary_after is not None
                and unitary_before.shape == unitary_after.shape):
            overlap = np.vdot(unitary_after, unitary_before)
            phase = overlap / abs(overlap) if abs(overlap) else 1.0
            distance = float(np.linalg.norm(unitary_before - phase * unitary_after))
            equivalent = distance <= tolerance
            return {
                "status": "equivalent" if equivalent else "not_equivalent",
                "method": "exact_unitary",
                "scope": f"full unitary matrix up to global phase; Frobenius distance {distance:.12g}, tolerance {tolerance:.12g}",
                "message": "unitaries match within tolerance" if equivalent else "unitaries differ beyond tolerance",
            }

    if not prefer_formal:
        try:
            formal = try_formal()
            if formal is not None:
                return formal
        except Exception as exc:
            formal_error = str(exc)
    message = "no available comparison method decided this pair; do not treat as equivalent"
    if formal_error:
        message += f"; formal checker error: {formal_error}"
    return {
        "status": "inconclusive",
        "method": "unavailable_or_over_limit",
        "scope": "none",
        "message": "no available comparison method decided this pair; do not treat as equivalent",
    }


def build_transform_report(
    original_path: str | Path,
    stages: Sequence[tuple[str, str | Path]],
    *,
    tolerance: float = 1e-6,
    prefer_formal: bool = False,
) -> dict[str, Any]:
    """Build an ordered report comparing each user-supplied pipeline stage.

    Each stage is a label and a circuit file produced after that pass. QSHIELD
    does not run a transpiler; callers provide the pass outputs they want audited.
    """
    if not math.isfinite(tolerance) or tolerance <= 0:
        raise TransformReportError("tolerance must be a finite positive number")
    if not stages:
        raise TransformReportError("at least one --stage LABEL=FILE is required")

    original = Path(original_path)
    previous_ir, previous_identity = _identity(original)
    transforms: list[dict[str, Any]] = []
    labels: set[str] = set()
    for label, stage_path in stages:
        if not _LABEL_RE.fullmatch(label):
            raise TransformReportError(f"invalid stage label {label!r}; use 1-64 letters, digits, dot, underscore, or hyphen")
        if label in labels:
            raise TransformReportError(f"duplicate stage label: {label}")
        labels.add(label)
        current_ir, current_identity = _identity(Path(stage_path))
        comparison = _decision(previous_ir, current_ir, tolerance=tolerance, prefer_formal=prefer_formal)
        transforms.append({
            "pass": label,
            "before": previous_identity,
            "after": current_identity,
            "comparison": comparison,
        })
        previous_ir, previous_identity = current_ir, current_identity

    statuses = [item["comparison"]["status"] for item in transforms]
    overall = "not_equivalent" if "not_equivalent" in statuses else (
        "inconclusive" if "inconclusive" in statuses else "equivalent"
    )
    return {
        "spec_version": TRANSFORM_REPORT_SPEC,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "canonicalization_spec": CANONICALIZATION_SPEC,
        "overall_status": overall,
        "original": previous_identity if not transforms else transforms[0]["before"],
        "transforms": transforms,
        "limitations": [
            "A randomized comparison is not used to claim equivalence.",
            "Inconclusive results are reported separately from a pass.",
            "QSHIELD records supplied pass outputs but does not execute or attest to the transpiler itself.",
        ],
    }
