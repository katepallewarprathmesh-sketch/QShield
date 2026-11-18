"""Versioned, deterministic circuit serialization and hashing.

Canonicalization contract ``qshield-circuit-c14n-v1``:

* Identity includes qubit/classical-bit counts, ordered gate names, ordered
  gate operands, each gate's ordered parameters, and ordered measurements.
* Source framework, source text/hash, circuit name, gate IDs, annotations,
  matrices, and metadata are excluded. This is a structural identity hash,
  not a semantic-equivalence proof; use ``qshield compare`` for equivalence.
* Gate names are Unicode NFC-normalized but otherwise preserved. Numeric
  parameters are converted to finite IEEE-754 doubles, rendered as decimal,
  and rounded to nine fractional digits using ROUND_HALF_EVEN. Negative zero
  canonicalizes to positive zero. Parameter order is significant.
* The canonical payload is UTF-8 JSON with sorted object keys, no whitespace,
  and no non-standard JSON values. The digest is SHA-256 over the domain tag
  ``qshield-circuit-c14n-v1\0`` followed by those payload bytes.

Changing any rule requires a new spec ID/version and new golden vectors.
The legacy runtime-proxy hash deliberately remains separate and unchanged.
"""

from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from decimal import ROUND_HALF_EVEN, Decimal, InvalidOperation, localcontext
from typing import Any

from qshield.core.circuit_ir import CircuitIR

CANONICALIZATION_SPEC = "qshield-circuit-c14n-v1"
_SPEC_DOMAIN = (CANONICALIZATION_SPEC + "\0").encode("ascii")
_GRID = Decimal("0.000000001")


def _integer(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _parameter(value: Any, gate_index: int, parameter_index: int) -> str:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(
            f"gate {gate_index} parameter {parameter_index} is not a finite number"
        ) from exc
    if not math.isfinite(number):
        raise ValueError(f"gate {gate_index} parameter {parameter_index} is not finite")

    decimal_value = Decimal(str(number))
    # Decimal's default precision is too small for the full finite float range
    # when quantizing to nine fractional digits.
    with localcontext() as context:
        context.prec = max(40, len(decimal_value.as_tuple().digits) + 16)
        try:
            quantized = decimal_value.quantize(_GRID, rounding=ROUND_HALF_EVEN)
        except InvalidOperation as exc:
            raise ValueError(
                f"gate {gate_index} parameter {parameter_index} is outside the supported numeric range"
            ) from exc
    if quantized.is_zero():
        quantized = abs(quantized)
    return format(quantized, ".9f")


def canonical_circuit_payload(ir: CircuitIR) -> bytes:
    """Return the canonical UTF-8 JSON payload for spec v1."""
    num_qubits = _integer(ir.num_qubits, "num_qubits")
    num_clbits = _integer(ir.num_classical_bits, "num_classical_bits")

    gates: list[dict[str, Any]] = []
    for gate_index, gate in enumerate(ir.gates):
        if not isinstance(gate.gate_name, str) or not gate.gate_name:
            raise ValueError(f"gate {gate_index} must have a non-empty string name")
        operands: list[int] = []
        for operand in gate.qubits:
            q = _integer(operand, f"gate {gate_index} qubit")
            if q >= num_qubits:
                raise ValueError(f"gate {gate_index} qubit {q} is outside num_qubits={num_qubits}")
            operands.append(q)
        parameters = [
            _parameter(value, gate_index, parameter_index)
            for parameter_index, value in enumerate(gate.parameters)
        ]
        gates.append({
            "name": unicodedata.normalize("NFC", gate.gate_name),
            "qubits": operands,
            "parameters": parameters,
        })

    measurements: list[list[int]] = []
    for measurement_index, (qubit, clbit) in enumerate(ir.measurements):
        q = _integer(qubit, f"measurement {measurement_index} qubit")
        c = _integer(clbit, f"measurement {measurement_index} classical bit")
        if q >= num_qubits:
            raise ValueError(f"measurement {measurement_index} qubit {q} is outside num_qubits={num_qubits}")
        if c >= num_clbits:
            raise ValueError(
                f"measurement {measurement_index} classical bit {c} is outside num_classical_bits={num_clbits}"
            )
        measurements.append([q, c])

    body = {
        "spec": CANONICALIZATION_SPEC,
        "num_qubits": num_qubits,
        "num_classical_bits": num_clbits,
        "gates": gates,
        "measurements": measurements,
    }
    return json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_circuit_hash_v1(ir: CircuitIR) -> str:
    """Return the lowercase SHA-256 hex digest for canonicalization spec v1."""
    payload = canonical_circuit_payload(ir)
    return hashlib.sha256(_SPEC_DOMAIN + payload).hexdigest()
