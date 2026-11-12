"""Finding data structures shared across all analyses."""

from __future__ import annotations

import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class CircuitLocation:
    """Location within a circuit."""

    gate_ids: list[str] = field(default_factory=list)
    qubit_indices: list[int] = field(default_factory=list)
    gate_indices: list[int] = field(default_factory=list)   # position in gate sequence
    source_file: str | None = None
    source_line: int | None = None


@dataclass
class Evidence:
    """Evidence supporting a finding."""

    evidence_type: str          # "unitary_mismatch" | "statistical" | "structural" | ...
    details: dict = field(default_factory=dict)
    visualizations: list[str] = field(default_factory=list)
    raw_data: dict | None = None


@dataclass
class Finding:
    """Single security finding."""

    severity: str                      # "critical" | "high" | "medium" | "low" | "info"
    threat_type: str                   # "T1.1" | "T1.2" | ... | "T4.2"
    title: str
    description: str
    circuit_id: str = ""
    location: CircuitLocation = field(default_factory=CircuitLocation)
    evidence: Evidence = field(default_factory=lambda: Evidence(evidence_type="structural"))
    confidence: float = 0.5
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    false_positive_probability: float = 0.5
    finding_id: str = field(default_factory=lambda: f"QSH-{uuid.uuid4().hex[:8].upper()}")
    analysis_type: str = "static"      # "static" | "dynamic" | "formal" | "supply_chain"
    signature_id: str | None = None

    def __post_init__(self) -> None:
        self.severity = self.severity.lower()
        if self.severity not in SEVERITY_ORDER:
            raise ValueError(f"Unknown severity: {self.severity}")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    @property
    def severity_rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity_rank"] = self.severity_rank
        return d


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")
