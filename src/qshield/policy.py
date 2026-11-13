"""Policy-as-code for quantum circuits — the QSHIELD Workbench Policy Studio.

Security/hygiene policies expressed as small, deterministic, offline rules
over the circuit IR.  Unlike the builtin *threat signatures* (which encode
known attack patterns), policies encode your organisation's *own* rules
("no opaque continuous rotations", "no mid-circuit measurement") and can be
evaluated against the whole fixture corpus to show exactly what each policy
costs you in false positives and what it catches.

Honest scope: these are heuristic lint-style policies.  They are not threat
detectors, they are not sound, and they say so in their descriptions.
They complement — never replace — the signature engine.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from qshield.core.circuit_ir import CircuitIR

SEVERITIES = ("critical", "high", "medium", "low", "info")
RULE_KINDS = (
    "forbidden_gate",
    "max_depth",
    "max_two_qubit_density",
    "max_measurements",
    "max_width",
)


class PolicyError(ValueError):
    """Raised when a policy spec is malformed."""


@dataclass(frozen=True)
class PolicySpec:
    id: str
    name: str
    description: str
    severity: str
    rule: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PolicyFinding:
    policy_id: str
    policy_name: str
    severity: str
    message: str
    gate_indices: list[int]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _validate_spec(raw: dict[str, Any]) -> PolicySpec:
    if not isinstance(raw, dict):
        raise PolicyError("policy must be a JSON object")
    for key in ("id", "name", "rule"):
        if not isinstance(raw.get(key), str) and key != "rule":
            raise PolicyError(f"policy missing required string field {key!r}")
        if key == "rule" and not isinstance(raw.get(key), dict):
            raise PolicyError("policy 'rule' must be an object")
    sev = str(raw.get("severity", "medium"))
    if sev not in SEVERITIES:
        raise PolicyError(f"severity must be one of {SEVERITIES}")
    rule = raw["rule"]
    kind = rule.get("kind")
    if kind not in RULE_KINDS:
        raise PolicyError(f"rule.kind must be one of {RULE_KINDS}, got {kind!r}")
    params = rule.get("params", {})
    if not isinstance(params, dict):
        raise PolicyError("rule.params must be an object")
    if kind == "forbidden_gate":
        gates = params.get("gates")
        if not isinstance(gates, list) or not gates or not all(isinstance(g, str) for g in gates):
            raise PolicyError("forbidden_gate requires params.gates: non-empty list of gate names")
    elif kind in ("max_depth", "max_width"):
        if not isinstance(params.get("max"), int) or params["max"] < 1:
            raise PolicyError(f"{kind} requires params.max: positive integer")
    elif kind == "max_two_qubit_density":
        v = params.get("max")
        if not isinstance(v, (int, float)) or not 0.0 < float(v) <= 1.0:
            raise PolicyError("max_two_qubit_density requires params.max: float in (0, 1]")
    elif kind == "max_measurements" and (not isinstance(params.get("max"), int) or params["max"] < 1):
        raise PolicyError("max_measurements requires params.max: positive integer")
    return PolicySpec(
        id=raw["id"],
        name=raw["name"],
        description=str(raw.get("description", "")),
        severity=sev,
        rule={"kind": kind, "params": params},
    )


def check_policy(circuit: CircuitIR, spec: PolicySpec) -> list[PolicyFinding]:
    kind = spec.rule["kind"]
    params = spec.rule["params"]
    findings: list[PolicyFinding] = []

    def emit(message: str, indices: list[int]) -> None:
        findings.append(
            PolicyFinding(
                policy_id=spec.id,
                policy_name=spec.name,
                severity=spec.severity,
                message=message,
                gate_indices=indices,
            )
        )

    if kind == "forbidden_gate":
        banned = set(params["gates"])
        hits = [i for i, g in enumerate(circuit.gates) if g.gate_name in banned]
        for idx in hits:
            emit(f"forbidden gate {circuit.gates[idx].gate_name!r} (index {idx})", [idx])
    elif kind == "max_depth":
        depth = circuit.get_depth()
        if depth > int(params["max"]):
            emit(f"circuit depth {depth} exceeds policy maximum {params['max']}", [])
    elif kind == "max_two_qubit_density":
        total = len(circuit.gates) or 1
        two_q = sum(1 for g in circuit.gates if len(g.qubits) >= 2)
        ratio = two_q / total
        if ratio > float(params["max"]):
            emit(f"two-qubit gate density {ratio:.2f} exceeds policy maximum {params['max']}", [])
    elif kind == "max_measurements":
        count = len(circuit.measurements) + sum(1 for g in circuit.gates if g.gate_name == "measure")
        if count > int(params["max"]):
            emit(f"measurement fan-out {count} exceeds policy maximum {params['max']}", [])
    elif kind == "max_width" and circuit.num_qubits > int(params["max"]):
        emit(f"circuit width {circuit.num_qubits} qubits exceeds policy maximum {params['max']}", [])
    return findings


class PolicyEngine:
    """Validates and evaluates policy specs against CircuitIR."""

    def __init__(self, specs: list[PolicySpec]) -> None:
        ids = [s.id for s in specs]
        if len(set(ids)) != len(ids):
            raise PolicyError("duplicate policy ids")
        self.specs = list(specs)

    @classmethod
    def from_dicts(cls, dicts: list[dict[str, Any]]) -> PolicyEngine:
        if not isinstance(dicts, list) or not dicts:
            raise PolicyError("at least one policy is required")
        return cls([_validate_spec(d) for d in dicts])

    def check(self, circuit: CircuitIR) -> list[PolicyFinding]:
        out: list[PolicyFinding] = []
        for spec in self.specs:
            out += check_policy(circuit, spec)
        return out

    def check_source(self, qasm: str, *, name: str = "circuit") -> list[PolicyFinding]:
        from qshield.core.parsers.qasm_parser import parse_qasm

        return self.check(parse_qasm(qasm, name=name))


BUILTIN_POLICIES: tuple[PolicySpec, ...] = (
    PolicySpec(
        id="POL-001",
        name="No opaque continuous rotations",
        description=(
            "Flags bare/opaque 'u' and 'u3' gates. Continuous parameter gates resist review and "
            "can hide arbitrary single-qubit behavior; require explicit rx/ry/rz decomposition. "
            "Heuristic hygiene rule, not a threat detector."
        ),
        severity="medium",
        rule={"kind": "forbidden_gate", "params": {"gates": ["u", "u3"]}},
    ),
    PolicySpec(
        id="POL-002",
        name="Measurement fan-out ceiling 16",
        description=(
            "Flags circuits reporting to more than 16 classical bits. Unusually wide measurement "
            "surfaces are a staging shape for result scraping. Heuristic hygiene rule, not a "
            "threat detector; OpenQASM measurements are position-less in the IR, so ordering is "
            "not asserted."
        ),
        severity="medium",
        rule={"kind": "max_measurements", "params": {"max": 16}},
    ),
    PolicySpec(
        id="POL-003",
        name="Depth ceiling 64",
        description=(
            "Circuits deeper than 64 layers deserve manual review: disproportionate depth is the "
            "signature of camouflaged dead-code insertion. Heuristic hygiene rule, not a threat detector."
        ),
        severity="low",
        rule={"kind": "max_depth", "params": {"max": 64}},
    ),
    PolicySpec(
        id="POL-004",
        name="Two-qubit density ceiling 75%",
        description=(
            "Two-qubit gates above 75% of the pool suggest gate-soup optimisation or dilution. "
            "Heuristic hygiene rule, not a threat detector."
        ),
        severity="low",
        rule={"kind": "max_two_qubit_density", "params": {"max": 0.75}},
    ),
    PolicySpec(
        id="POL-005",
        name="Width ceiling 24 qubits",
        description=(
            "Circuits wider than 24 qubits are outside the reviewed small-system envelope. "
            "Heuristic hygiene rule, not a threat detector."
        ),
        severity="info",
        rule={"kind": "max_width", "params": {"max": 24}},
    ),
    PolicySpec(
        id="POL-006",
        name="No ccx (Toffoli) gates",
        description=(
            "Toffoli gates concentrate multi-qubit control structure; in reviewed pipelines they "
            "should be decomposed and tracked explicitly. Heuristic hygiene rule, not a threat detector."
        ),
        severity="medium",
        rule={"kind": "forbidden_gate", "params": {"gates": ["ccx"]}},
    ),
)


def builtin_policies() -> list[PolicySpec]:
    return list(BUILTIN_POLICIES)


@dataclass
class CorpusEvalRow:
    id: str
    name: str
    severity: str
    tp: int
    fn: int
    fp: int
    tn: int

    @property
    def tpr(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tpr"] = round(self.tpr, 4)
        d["fpr"] = round(self.fpr, 4)
        return d


def _even_sample(files: list[Path], n: int | None) -> list[Path]:
    files = sorted(files)
    if not n or len(files) <= n:
        return files
    step = len(files) / n
    return [files[int(i * step)] for i in range(n)]


def evaluate_corpus(
    engine: PolicyEngine,
    clean_dir: str | Path,
    malicious_dir: str | Path,
    *,
    sample: int | None = None,
) -> dict[str, Any]:
    """Evaluate every policy on the fixture corpus (QASM files).

    Returns per-policy TPR/FPR plus the any-policy aggregate.  Fixture-corpus
    rates — not field rates; stated as such because they are.
    """
    from qshield.core.parsers.qasm_parser import parse_qasm

    clean_files = _even_sample(list(Path(clean_dir).glob("*.qasm")), sample)
    mal_files = _even_sample(list(Path(malicious_dir).glob("*.qasm")), sample)
    if not clean_files or not mal_files:
        raise PolicyError(f"corpus not found or empty: clean={clean_dir} malicious={malicious_dir}")

    rows: dict[str, dict[str, int]] = {s.id: {"tp": 0, "fn": 0, "fp": 0, "tn": 0} for s in engine.specs}
    agg = {"tp": 0, "fn": 0, "fp": 0, "tn": 0}
    skipped = 0

    for _label, files, key in (("clean", clean_files, ("fp", "tn")), ("malicious", mal_files, ("tp", "fn"))):
        hit_key, miss_key = key
        for f in files:
            try:
                ir = parse_qasm(f.read_text(), name=f.stem)
            except Exception:
                skipped += 1
                continue
            for spec in engine.specs:
                fired = bool(check_policy(ir, spec))
                rows[spec.id][hit_key if fired else miss_key] += 1
            fired_any = bool(engine.check(ir))
            agg[hit_key if fired_any else miss_key] += 1

    per_policy = [
        CorpusEvalRow(
            id=spec.id,
            name=spec.name,
            severity=spec.severity,
            tp=rows[spec.id]["tp"],
            fn=rows[spec.id]["fn"],
            fp=rows[spec.id]["fp"],
            tn=rows[spec.id]["tn"],
        ).to_dict()
        for spec in engine.specs
    ]
    agg_tpr = agg["tp"] / (agg["tp"] + agg["fn"]) if (agg["tp"] + agg["fn"]) else 0.0
    agg_fpr = agg["fp"] / (agg["fp"] + agg["tn"]) if (agg["fp"] + agg["tn"]) else 0.0
    return {
        "per_policy": per_policy,
        "any_policy": {**agg, "tpr": round(agg_tpr, 4), "fpr": round(agg_fpr, 4)},
        "corpus": {"clean": len(clean_files), "malicious": len(mal_files), "skipped_unparseable": skipped},
        "note": "Fixture-corpus rates on the bundled clean/malicious QASM fixtures — not field rates.",
    }
