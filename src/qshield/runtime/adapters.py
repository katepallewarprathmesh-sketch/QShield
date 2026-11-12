"""Provider-agnostic extraction of circuits and results from HTTP payloads.

Quantum cloud APIs (IBM Quantum Runtime, IonQ, Rigetti QCS, …) do not share a
wire format. QSHIELD therefore works against a small set of declarative
"shapes" rather than a single vendor schema, and degrades to "no circuit
found" (never to a false verdict) when a payload does not match.

Supported submission shapes (documented, tested against synthetic payloads):

- raw QASM body (``OPENQASM …``) — content-type ``text/plain`` / ``application/qasm``
- JSON object with a QASM-like string at ``qasm`` | ``circuit`` | ``program``
- JSON object with ``circuits`` or ``params.circuits`` — a list of QASM strings
  (IBM Quantum Runtime style: ``{"program_id": "…", "params": {"circuits": […]}}``)
- JSON object nesting any of the above under ``input`` / ``params`` / ``job``
  (bounded-depth recursive search)
- job metadata discovered anywhere in the object: ``id``/``job_id``/``jobId``
  (str), ``shots``/``count`` (int), ``backend``/``backend_name``/``target`` (str)

Supported result shapes (for post-hoc validation):

- ``{"counts": {bitstring: n, …}}``
- ``{"results": [{"counts": {…}}, …]}`` (first entry)
- ``{"data": {"counts": {…}}}`` / ``{"result": {"counts": {…}}}``

Bit ordering: provider counts keys are assumed big-endian (qubit 0 leftmost,
matching :class:`SandboxExecutor` MSB convention); if the direct comparison is
not statistically plausible we also try the bit-reversed mapping and report
which one matched. Both are exact under our terminal-measurement restriction.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

MAX_BODY_BYTES = 8 * 1024 * 1024  # 8 MiB hard cap on intercepted bodies
_MAX_DEPTH = 6
_MAX_QASM_STRING = 4 * 1024 * 1024


@dataclass
class TransportCircuit:
    """A circuit observed on the wire."""

    qasm: str
    shots: int | None = None
    backend: str | None = None
    job_id: str | None = None
    shape: str = "unknown"  # which extraction rule fired (for logs/tests)


@dataclass
class TransportResult:
    """A result payload observed on the wire."""

    counts: dict[str, int]
    job_id: str | None = None
    shape: str = "unknown"
    raw_keys: int = field(default=0)

    @property
    def total_shots(self) -> int:
        return sum(self.counts.values())


def looks_like_qasm(text: str) -> bool:
    head = text.lstrip()[:16].upper()
    return head.startswith("OPENQASM")


def _find_qasm_strings(node: Any, depth: int = 0) -> list[tuple[str, str]]:
    """Recursively collect (shape, qasm-string) pairs from decoded JSON."""
    out: list[tuple[str, str]] = []
    if depth > _MAX_DEPTH:
        return out
    if isinstance(node, str):
        if len(node) <= _MAX_QASM_STRING and looks_like_qasm(node):
            out.append(("bare-string", node))
        return out
    if isinstance(node, list):
        for item in node:
            out.extend(_find_qasm_strings(item, depth + 1))
        return out
    if not isinstance(node, dict):
        return out
    for key, value in node.items():
        lk = str(key).lower()
        if lk in ("qasm", "circuit", "program", "source") and isinstance(value, str) \
                and looks_like_qasm(value):
            out.append((f"key:{lk}", value))
        elif lk in ("circuits", "experiments") and isinstance(value, list):
            for j, item in enumerate(value):
                if isinstance(item, str) and looks_like_qasm(item):
                    out.append((f"{lk}[{j}]", item))
                elif isinstance(item, dict):
                    for sk, sv in item.items():
                        if isinstance(sv, str) and looks_like_qasm(sv):
                            out.append((f"{lk}[{j}].{sk}", sv))
        else:
            out.extend(_find_qasm_strings(value, depth + 1))
    return out


def _find_meta(node: Any, depth: int = 0) -> dict[str, Any]:
    """Collect job metadata anywhere in the object (shallow preference)."""
    meta: dict[str, Any] = {}
    if depth > _MAX_DEPTH or not isinstance(node, dict):
        return meta
    for key, value in node.items():
        lk = str(key).lower()
        if lk in ("id", "job_id", "jobid") and isinstance(value, str) and value:
            meta.setdefault("job_id", value)
        elif lk in ("shots", "count", "shot_count") and isinstance(value, int) and value > 0:
            meta.setdefault("shots", value)
        elif lk in ("backend", "backend_name", "target") and isinstance(value, str) and value:
            meta.setdefault("backend", value)
    # fall back to a nested scan, but keep the shallow (top-level) values if any
    if "job_id" not in meta or "shots" not in meta or "backend" not in meta:
        for value in node.values():
            child = _find_meta(value, depth + 1) if isinstance(value, (dict,)) else {}
            for k, v in child.items():
                meta.setdefault(k, v)
    return meta


def extract_circuits(body: bytes, content_type: str = "") -> list[TransportCircuit]:
    """Find circuits in an intercepted request body. Empty list if none found."""
    if not body:
        return []
    if len(body) > MAX_BODY_BYTES:
        raise ValueError(f"request body exceeds {MAX_BODY_BYTES} bytes")
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return []

    if looks_like_qasm(text):
        return [TransportCircuit(qasm=text, shape="raw-qasm")]

    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []

    found = _find_qasm_strings(doc)
    meta = _find_meta(doc)
    circuits = [
        TransportCircuit(qasm=qasm, shots=meta.get("shots"), backend=meta.get("backend"),
                         job_id=meta.get("job_id"), shape=shape)
        for shape, qasm in found
    ]
    return circuits


def _find_counts(node: Any, depth: int = 0) -> tuple[dict[str, int] | None, str]:
    if depth > _MAX_DEPTH:
        return None, ""
    if isinstance(node, dict):
        lk_items = {str(k).lower(): v for k, v in node.items()}
        for lk, value in lk_items.items():
            if lk == "counts" and isinstance(value, dict) and value:
                counts: dict[str, int] = {}
                ok = True
                for k, v in value.items():
                    if not isinstance(k, str):
                        ok = False
                        break
                    try:
                        counts[k] = int(v)
                    except (TypeError, ValueError):
                        ok = False
                        break
                if ok and counts:
                    return counts, "counts"
        for lk, value in lk_items.items():
            if lk in ("results", "data", "result", "output"):
                found, shape = _find_counts(value, depth + 1)
                if found is not None:
                    return found, f"{lk}.{shape}"
        # generic nested scan as last resort
        for value in node.values():
            found, shape = _find_counts(value, depth + 1)
            if found is not None:
                return found, shape
    elif isinstance(node, list):
        for item in node:
            found, shape = _find_counts(item, depth + 1)
            if found is not None:
                return found, shape
    return None, ""


def extract_job_id(body: bytes) -> str | None:
    """Return the job id declared anywhere in a JSON body, else None."""
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    meta = _find_meta(doc)
    return meta.get("job_id")


def extract_result(body: bytes) -> TransportResult | None:
    """Find a counts histogram in an intercepted response body, or None."""
    if not body:
        return None
    if len(body) > MAX_BODY_BYTES:
        return None
    try:
        doc = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    counts, shape = _find_counts(doc)
    if counts is None:
        return None
    meta = _find_meta(doc)
    return TransportResult(counts=counts, job_id=meta.get("job_id"),
                           shape=shape or "counts", raw_keys=len(counts))
