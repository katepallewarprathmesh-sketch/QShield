"""QUBO/Ising model analysis for annealing workflows.

Annealing-based quantum workflows (D-Wave and friends) do not submit circuits.
They submit a **QUBO**: a quadratic unconstrained binary optimisation problem,
usually expressed as an upper-triangular matrix or a JSON/QUBO file, sometimes
as an Ising model of linear biases and couplers.

That changes the security question. With a circuit you ask "was a gate tampered
with?". With a QUBO you ask: *is the model I am about to submit the model I
intended, and will the solver be able to honour it?* The published field work is
consistent about this shape: supply-chain routing papers encode ~2,500-variable
QUBOs one truck at a time, and warehouse pilots push those models through a
hybrid quantum-classical stack. The model file is the artifact that crosses the
trust boundary, so it is the artifact worth checking.

What this module checks
-----------------------
Integrity
  * **Digest commitment** — a deterministic SHA-256 over the canonical model, so
    a submitted model can be compared against a trusted one.
  * **Structural validity** — symmetric shape, finite coefficients, no
    duplicate entries, index bounds.

Solver feasibility
  * **Chain strength** for minor-embedded problems, using the standard
    ``max|J| / min|J|`` rule of thumb.
  * **Variable-count feasibility** against a stated hardware budget.

Coefficient risk
  * **Weak couplings** that risk being lost to integrated control error.
  * **Zero-weight variables** that are unconstrained model bloat.
  * **Extreme dynamic range**, which makes the annealer's schedule do the work
    in a regime that is hard to calibrate.

Scope: these are model-level checks on the artifact you submit. They do not
predict solution quality, and they are not a claim about any vendor's hardware.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

from qshield.reporting.finding import CircuitLocation, Evidence, Finding

QUBO_SPEC_VERSION = "qshield-qubo-v1"

# Couplings below this magnitude are treated as at risk of being swamped by
# control error on current hardware. Published annealer specs quote integrated
# control error around this order, so it is a defensible default rather than a
# tuned threshold.
WEAK_COUPLING_FLOOR = 1e-3
# At or above this ratio between the largest and smallest non-trivial coupling,
# a single anneal schedule spans a range the hardware cannot resolve: the
# smallest weight falls below the QPU's coefficient resolution relative to the
# largest one. The limit is inclusive so a ratio of exactly 1e6 is reported.
MAX_DYNAMIC_RANGE = 1e6

# Model files are read fully into memory, so they carry the same size cap as
# circuit sources; a model document has no legitimate reason to be larger.
MAX_MODEL_BYTES = 64 * 1024 * 1024

# A model larger than this cannot be embedded on current annealers or held in
# memory for analysis, and a declared count this large is a denial-of-service
# vector rather than a real instance.
MAX_VARIABLES = 1_000_000


@dataclass
class QuboFinding:
    """A single model-level observation."""

    severity: str          # "high" | "medium" | "low" | "info"
    category: str          # "integrity" | "feasibility" | "coefficients"
    title: str
    detail: str
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "data": self.data,
        }


@dataclass
class QuboModel:
    """A parsed quadratic binary model.

    ``quadratic`` maps ``(i, j)`` with ``i <= j`` to a coefficient; the diagonal
    holds linear terms, which is the convention every annealer API accepts.
    """

    num_variables: int
    quadratic: dict[tuple[int, int], float]
    source: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    def linear(self) -> dict[int, float]:
        return {i: w for (i, j), w in self.quadratic.items() if i == j}

    def couplings(self) -> dict[tuple[int, int], float]:
        return {k: w for k, w in self.quadratic.items() if k[0] != k[1]}

    def neighbours(self) -> dict[int, set[int]]:
        """Adjacency map. Terms outside the declared range are still recorded.

        A model can carry a term for a variable it does not declare, and that is
        a finding to report, not a reason to fail while building the graph.
        """
        adj: dict[int, set[int]] = {i: set() for i in range(self.num_variables)}
        for i, j in self.couplings():
            adj.setdefault(i, set()).add(j)
            adj.setdefault(j, set()).add(i)
        return adj

    def canonical_bytes(self) -> bytes:
        """Deterministic serialisation used for the digest commitment.

        Coefficients are hashed at full IEEE-754 precision. Rounding them would
        make the commitment blind to small perturbations, which is precisely the
        tamper the digest exists to catch.
        """
        items = sorted(
            (i, j, (0.0 if w == 0.0 else float(w)))
            for (i, j), w in self.quadratic.items()
            if w != 0.0
        )
        payload = {
            "spec": QUBO_SPEC_VERSION,
            "num_variables": int(self.num_variables),
            "terms": [[int(i), int(j), w.hex()] for i, j, w in items],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()

    def digest(self) -> str:
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


# ----------------------------------------------------------------------
# Parsing
# ----------------------------------------------------------------------
def _coerce_weight(value: Any, where: str) -> float:
    """Convert a coefficient to float, rejecting anything that coerces silently."""
    if isinstance(value, bool):
        raise TypeError(f"{where}: boolean coefficient {value!r} is not a number")
    if isinstance(value, str):
        raise TypeError(f"{where}: coefficient {value!r} is a string, expected a number")
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{where}: coefficient {value!r} is not numeric") from exc


def _parse_pair(key: Any, where: str) -> tuple[int, int]:
    """Parse an ``"i,j"`` (or ``[i, j]``) index pair."""
    if isinstance(key, str):
        parts = key.replace(",", " ").split()
        if len(parts) != 2:
            raise ValueError(f"{where}: key {key!r} is not an 'i,j' index pair")
        try:
            i, j = int(parts[0]), int(parts[1])
        except ValueError as exc:
            raise ValueError(f"{where}: key {key!r} does not contain two integers") from exc
    elif isinstance(key, (list, tuple)) and len(key) == 2:
        try:
            i, j = int(key[0]), int(key[1])
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{where}: key {key!r} does not contain two integers") from exc
    else:
        raise ValueError(f"{where}: key {key!r} is not an 'i,j' index pair")
    if i < 0 or j < 0:
        raise ValueError(f"{where}: index pair ({i}, {j}) contains a negative variable index")
    return i, j


def _check_index_bound(n: int) -> int:
    """Reject variable counts that a solver could never hold."""
    if n > MAX_VARIABLES:
        raise ValueError(
            f"model declares {n} variables, above the {MAX_VARIABLES} supported for analysis"
        )
    return n


def from_matrix(matrix: Any, source: str | None = None) -> QuboModel:
    """Build a model from an upper-triangular (or symmetric) QUBO matrix.

    Both upper- and lower-triangular entries are accepted: a symmetric matrix is
    read from whichever triangle carries the coefficient, and the two are never
    summed. Supplying the same coupling in both triangles with *different*
    weights is ambiguous and rejected.
    """
    arr = np.asarray(matrix, dtype=float)
    if arr.ndim != 2 or arr.shape[0] != arr.shape[1]:
        raise ValueError(f"QUBO matrix must be square, got shape {arr.shape}")
    n = _check_index_bound(int(arr.shape[0]))
    quadratic: dict[tuple[int, int], float] = {}
    for i in range(n):
        for j in range(i, n):
            upper = float(arr[i, j])
            lower = float(arr[j, i]) if i != j else 0.0
            if upper and lower and not math.isclose(upper, lower, rel_tol=0.0, abs_tol=1e-12):
                raise ValueError(
                    f"QUBO matrix is asymmetric at ({i}, {j}): {upper!r} above the diagonal "
                    f"but {lower!r} below it"
                )
            value = upper if upper else lower
            if value:
                quadratic[(i, j)] = value
    return QuboModel(num_variables=n, quadratic=quadratic, source=source, metadata={"format": "qubo"})


def _from_ising(data: dict[str, Any], source: str | None) -> QuboModel:
    """Build a model from D-Wave style ``{"linear": {...}, "quadratic": {...}}``."""
    quadratic: dict[tuple[int, int], float] = {}
    indices: set[int] = set()

    for key, value in (data.get("linear") or {}).items():
        i, _ = _parse_pair(f"{key},{key}" if "," not in str(key) else key, "linear")
        quadratic[(i, i)] = _coerce_weight(value, f"linear[{key!r}]")
        indices.add(i)

    for key, value in (data.get("quadratic") or {}).items():
        i, j = _parse_pair(key, "quadratic")
        if i == j:
            quadratic[(i, i)] = quadratic.get((i, i), 0.0) + _coerce_weight(
                value, f"quadratic[{key!r}]"
            )
        else:
            quadratic[(min(i, j), max(i, j))] = _coerce_weight(value, f"quadratic[{key!r}]")
        indices.update((i, j))

    declared = data.get("num_variables")
    n = max(indices) + 1 if indices else 0
    if declared is not None:
        if not isinstance(declared, int) or isinstance(declared, bool) or declared < 0:
            raise ValueError(f"num_variables must be a non-negative integer, got {declared!r}")
        if declared < n:
            raise ValueError(
                f"num_variables is {declared} but a term references variable {n - 1}"
            )
        n = declared
    return QuboModel(
        num_variables=_check_index_bound(n),
        quadratic=quadratic,
        source=source,
        metadata={"format": "ising"},
    )


def _from_qubo_json(data: dict[str, Any], source: str | None) -> QuboModel:
    qubo = data["qubo"]
    terms: dict[tuple[int, int], float] = {}
    indices: set[int] = set()

    if isinstance(qubo, dict):
        for key, value in qubo.items():
            i, j = _parse_pair(key, "qubo")
            weight = _coerce_weight(value, f"qubo[{key!r}]")
            if (min(i, j), max(i, j)) in terms and not math.isclose(
                terms[(min(i, j), max(i, j))], weight, rel_tol=0.0, abs_tol=1e-12
            ):
                raise ValueError(
                    f"qubo: coupling ({i}, {j}) is declared twice with different weights"
                )
            terms[(min(i, j), max(i, j))] = weight
            indices.update((i, j))
    elif isinstance(qubo, list):
        for row_index, row in enumerate(qubo):
            if not isinstance(row, (list, tuple)):
                raise TypeError(f"qubo: row {row_index} is not a list of coefficients")
            if len(row) != len(qubo):
                raise ValueError(
                    f"qubo: row {row_index} has {len(row)} entries, expected {len(qubo)}"
                )
            for col_index, value in enumerate(row):
                weight = _coerce_weight(value, f"qubo[{row_index}][{col_index}]")
                if weight:
                    terms[(row_index, col_index)] = weight
                    indices.update((row_index, col_index))
    else:
        raise TypeError("'qubo' must be a mapping of index pairs or a matrix")

    n = max(indices) + 1 if indices else 0
    declared = data.get("num_variables")
    if declared is not None:
        if not isinstance(declared, int) or isinstance(declared, bool) or declared < 0:
            raise ValueError(f"num_variables must be a non-negative integer, got {declared!r}")
        if declared < n:
            raise ValueError(f"num_variables is {declared} but a term references variable {n - 1}")
        n = declared
    return QuboModel(
        num_variables=_check_index_bound(n),
        quadratic=terms,
        source=source,
        metadata={"format": "qubo"},
    )


def from_dict(data: dict[str, Any], source: str | None = None) -> QuboModel:
    """Build a model from a QUBO/Ising JSON document."""
    if not isinstance(data, dict):
        raise TypeError("model document must be a mapping")
    if "qubo" in data:
        return _from_qubo_json(data, source)
    if "linear" in data or "quadratic" in data:
        return _from_ising(data, source)
    raise ValueError(
        "unrecognised model document: expected a 'qubo' matrix, or 'linear'/'quadratic' terms"
    )


def parse_qubo(path: str | Path) -> QuboModel:
    """Parse a ``.qubo`` / ``.json`` QUBO or Ising file.

    Parse failures are reported as ``ValueError`` so callers have one exception
    type to handle, with the file name included in the message.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"model file not found: {p}")
    size = p.stat().st_size
    if size > MAX_MODEL_BYTES:
        raise ValueError(
            f"{p.name} is {size} bytes, above the {MAX_MODEL_BYTES} byte cap for model files"
        )
    text = p.read_text(encoding="utf-8")
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{p.name}: not valid JSON ({exc.msg} at line {exc.lineno})") from exc
    try:
        if not isinstance(document, dict):
            # A bare list of lists is accepted as a matrix.
            return from_matrix(document, source=str(p))
        return from_dict(document, source=str(p))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{p.name}: {exc}") from exc


# ----------------------------------------------------------------------
# Analysis
# ----------------------------------------------------------------------
@dataclass
class QuboReport:
    model: QuboModel
    findings: list[QuboFinding]
    stats: dict[str, Any]

    @property
    def digest(self) -> str:
        return self.model.digest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "spec_version": QUBO_SPEC_VERSION,
            "source": self.model.source,
            "num_variables": self.model.num_variables,
            "digest": self.digest,
            "stats": self.stats,
            "findings": [f.to_dict() for f in self.findings],
            "max_severity": self.max_severity,
        }

    @property
    def max_severity(self) -> str | None:
        order = {"info": 0, "low": 1, "medium": 2, "high": 3}
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: order[f.severity]).severity


def _chain_strength(model: QuboModel, prefactor: float = 1.414) -> dict[str, Any]:
    """Chain strength from uniform torque compensation.

    The recommendation is the coupling magnitude that keeps a chain intact
    against the torques applied by the model's own biases::

        J_chain = prefactor * sqrt( (sum J_ij^2 + sum h_i^2) / n_variables )

    This is the default strategy in Ocean's embedding tools. It is a starting
    point to tune from, not a guarantee: the right value depends on the
    embedding, the chain lengths, and the solver's anneal schedule.
    """
    quadratic = list(model.couplings().values())
    linear = list(model.linear().values())
    terms = [w for w in quadratic + linear if math.isfinite(w)]
    if model.num_variables < 1 or not terms:
        return {"available": False, "method": "uniform_torque_compensation"}
    energy = sum(w * w for w in terms) / model.num_variables
    recommended = prefactor * math.sqrt(energy)
    magnitudes = [abs(w) for w in quadratic if w]
    out: dict[str, Any] = {
        "available": math.isfinite(recommended),
        "method": "uniform_torque_compensation",
        "prefactor": prefactor,
        "recommended_chain_strength": round(recommended, 6) if math.isfinite(recommended) else None,
    }
    if magnitudes:
        out["largest_coupling"] = round(max(magnitudes), 12)
        out["smallest_coupling"] = round(min(magnitudes), 12)
    return out


def analyse_qubo(
    model: QuboModel,
    *,
    hardware_variables: int | None = None,
    expected_digest: str | None = None,
) -> QuboReport:
    """Check a model for integrity, feasibility, and coefficient risk."""
    findings: list[QuboFinding] = []
    couplings = model.couplings()
    linear = model.linear()
    adjacency = model.neighbours()

    # ---- integrity --------------------------------------------------
    structural_ok = True
    for (i, j), weight in model.quadratic.items():
        if not math.isfinite(weight):
            structural_ok = False
            findings.append(
                QuboFinding(
                    severity="high",
                    category="integrity",
                    title="non-finite coefficient",
                    detail=f"term ({i}, {j}) has a non-finite weight; the solver cannot interpret it",
                    data={"term": [i, j]},
                )
            )
        if i > j:
            structural_ok = False
            findings.append(
                QuboFinding(
                    severity="medium",
                    category="integrity",
                    title="lower-triangular term",
                    detail=f"term ({i}, {j}) is stored below the diagonal; it may be silently ignored",
                    data={"term": [i, j]},
                )
            )
        if i < 0 or j < 0:
            structural_ok = False
            findings.append(
                QuboFinding(
                    severity="high",
                    category="integrity",
                    title="index out of range",
                    detail=f"term ({i}, {j}) references a negative variable index",
                    data={"term": [i, j]},
                )
            )
        elif i >= model.num_variables or j >= model.num_variables:
            structural_ok = False
            findings.append(
                QuboFinding(
                    severity="high",
                    category="integrity",
                    title="index out of range",
                    detail=f"term ({i}, {j}) is outside the declared variable count {model.num_variables}",
                    data={"term": [i, j]},
                )
            )

    if expected_digest is not None and expected_digest.lower() != model.digest():
        findings.append(
            QuboFinding(
                severity="high",
                category="integrity",
                title="digest mismatch",
                detail="the model does not match the digest you committed to before submission",
                data={"expected": expected_digest, "actual": model.digest()},
            )
        )

    # ---- feasibility -------------------------------------------------
    if hardware_variables is not None and model.num_variables > hardware_variables:
        findings.append(
            QuboFinding(
                severity="high",
                category="feasibility",
                title="model exceeds the stated variable budget",
                detail=(
                    f"{model.num_variables} variables cannot fit a {hardware_variables}-variable "
                    "budget without decomposition or minor embedding"
                ),
                data={"variables": model.num_variables, "budget": hardware_variables},
            )
        )

    chain = _chain_strength(model)

    # ---- coefficients ------------------------------------------------
    weak = [(pair, w) for pair, w in couplings.items() if 0 < abs(w) < WEAK_COUPLING_FLOOR]
    if weak:
        findings.append(
            QuboFinding(
                severity="medium",
                category="coefficients",
                title="weak couplings below the control-error floor",
                detail=(
                    f"{len(weak)} coupling(s) have |J| < {WEAK_COUPLING_FLOOR:g}; these are easily "
                    "swamped by integrated control error"
                ),
                data={"count": len(weak), "examples": [[list(p), w] for p, w in weak[:5]]},
            )
        )

    magnitudes = [abs(w) for w in couplings.values() if w]
    smallest = min(magnitudes) if magnitudes else 0.0
    dynamic_range = (max(magnitudes) / smallest) if smallest else None
    if dynamic_range is not None and dynamic_range >= MAX_DYNAMIC_RANGE:
        findings.append(
            QuboFinding(
                severity="low",
                category="coefficients",
                title="extreme dynamic range across couplings",
                detail=(
                    f"largest/smallest coupling ratio is {dynamic_range:.3g}, at or above "
                    f"{MAX_DYNAMIC_RANGE:g}; normalise the model before submission"
                ),
                data={"dynamic_range": round(dynamic_range, 6)},
            )
        )

    unconstrained = [
        i
        for i in range(model.num_variables)
        if not adjacency.get(i) and i not in linear and i >= 0
    ]
    if unconstrained:
        findings.append(
            QuboFinding(
                severity="low",
                category="coefficients",
                title="variables with no terms",
                detail=(
                    f"{len(unconstrained)} variable(s) carry no linear or quadratic term and "
                    "contribute nothing to the objective"
                ),
                data={"count": len(unconstrained), "examples": unconstrained[:10]},
            )
        )

    # The unit-range expectation belongs to an Ising document, where coefficients
    # are conventionally normalised before embedding. A QUBO is expressed on the
    # caller's own cost scale, so magnitude alone is not a defect there.
    if model.metadata.get("format") == "ising" and (couplings or linear):
        weights = list(couplings.values()) + list(linear.values())
        if not all(-1.0 <= w <= 1.0 for w in weights):
            findings.append(
                QuboFinding(
                    severity="info",
                    category="coefficients",
                    title="Ising coefficients outside the [-1, 1] range",
                    detail=(
                        "couplings or biases exceed the conventional unit range; scale them so "
                        "the annealer's normalisation does not flatten relative weights"
                    ),
                    data={},
                )
            )

    stats = {
        "num_variables": model.num_variables,
        "num_linear_terms": len(linear),
        "num_couplings": len(couplings),
        "density": round(
            (2 * len(couplings)) / (model.num_variables * (model.num_variables - 1)), 6
        )
        if model.num_variables > 1
        else 0.0,
        "structural_ok": structural_ok,
        "chain_strength": chain,
        "digest": model.digest(),
    }
    if magnitudes:
        stats["coupling_range"] = [round(min(magnitudes), 12), round(max(magnitudes), 12)]
        stats["dynamic_range"] = round(dynamic_range, 6) if dynamic_range else None

    return QuboReport(model=model, findings=findings, stats=stats)


# QUBO categories mapped onto the published threat taxonomy so model findings
# travel through the same reports, SARIF rules, and severity gates as circuit
# findings. T3 covers supply-chain/model integrity; T1 covers model tampering.
_CATEGORY_THREAT = {
    "integrity": "T3.1",
    "feasibility": "T3.2",
    "coefficients": "T1.4",
}


def to_findings(report: QuboReport) -> list[Finding]:
    """Convert model findings into standard findings for the shared reporters."""
    out: list[Finding] = []
    for item in report.findings:
        out.append(
            Finding(
                severity=item.severity,
                threat_type=_CATEGORY_THREAT.get(item.category, "T3.1"),
                title=f"QUBO model: {item.title}",
                description=item.detail,
                circuit_id=report.model.source or f"qubo-{report.digest[:12]}",
                location=CircuitLocation(),
                evidence=Evidence(
                    evidence_type="model",
                    details={"category": item.category, **item.data},
                ),
                confidence=0.9 if item.severity in ("high", "medium") else 0.6,
                remediation=(
                    "Re-derive the model from the trusted source, normalise coefficient scale, "
                    "and confirm the digest before submitting to the annealer."
                ),
                false_positive_probability=0.1 if item.severity == "high" else 0.35,
                analysis_type="static",
            )
        )
    return out
