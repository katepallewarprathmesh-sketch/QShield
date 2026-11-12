"""Loader and validator for QSHIELD threat signatures (YAML).

Signature files follow the schema in the specification, section 4.2.
A signature is *data*, never executed as code.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_METHODS = {"structural", "unitary", "statistical", "pattern"}
_THREAT_TYPE_RE = re.compile(r"^T[1-4]\.[1-4]$")
_ID_RE = re.compile(r"^QSig-\d{4}-\d{4}$")


class SignatureError(ValueError):
    """Raised when a signature file fails validation."""


@dataclass
class Signature:
    id: str
    name: str
    version: str
    author: str
    date: str
    severity: str
    threat_type: str
    description: str
    detection: dict
    references: list[str] = field(default_factory=list)
    false_positive_probability: float = 0.5
    remediation: str = ""
    source_path: str | None = None

    @property
    def method(self) -> str:
        return str(self.detection.get("method", "structural"))

    @property
    def pattern_type(self) -> str | None:
        return (self.detection.get("structural_pattern") or {}).get("type")

    @property
    def pattern_params(self) -> dict:
        return dict(self.detection.get("structural_pattern") or {})

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "version": self.version,
            "author": self.author, "date": self.date, "severity": self.severity,
            "threat_type": self.threat_type, "description": self.description,
            "detection": self.detection, "references": self.references,
            "false_positive_probability": self.false_positive_probability,
            "remediation": self.remediation,
        }


def load_signature(path: str | Path) -> Signature:
    path = Path(path)
    if not path.exists():
        raise SignatureError(f"Signature file not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SignatureError(f"Signature {path} must be a YAML mapping")
    return validate_signature(data, source_path=str(path))


def validate_signature(data: dict, source_path: str | None = None) -> Signature:
    required = ["id", "name", "version", "severity", "threat_type", "description", "detection"]
    missing = [k for k in required if k not in data]
    if missing:
        raise SignatureError(f"Signature missing required keys: {', '.join(missing)}")

    sig_id = str(data["id"])
    if not _ID_RE.match(sig_id):
        raise SignatureError(f"Signature id {sig_id!r} must match QSig-YYYY-NNNN")

    severity = str(data["severity"]).lower()
    if severity not in VALID_SEVERITIES:
        raise SignatureError(f"Invalid severity {severity!r}; expected one of {sorted(VALID_SEVERITIES)}")

    threat_type = str(data["threat_type"])
    if not _THREAT_TYPE_RE.match(threat_type):
        raise SignatureError(f"Invalid threat_type {threat_type!r}; expected T<1-4>.<1-4>")

    detection = data["detection"]
    if not isinstance(detection, dict):
        raise SignatureError("'detection' must be a mapping")
    method = str(detection.get("method", "")).lower()
    if method not in VALID_METHODS:
        raise SignatureError(f"Invalid detection.method {method!r}; expected one of {sorted(VALID_METHODS)}")

    try:
        fp = float(data.get("false_positive_probability", 0.5))
    except (TypeError, ValueError):
        fp = 0.5
    fp = min(1.0, max(0.0, fp))

    return Signature(
        id=sig_id,
        name=str(data["name"]),
        version=str(data["version"]),
        author=str(data.get("author", "unknown")),
        date=str(data.get("date", "")),
        severity=severity,
        threat_type=threat_type,
        description=str(data["description"]).strip(),
        detection=detection,
        references=[str(r) for r in data.get("references", [])],
        false_positive_probability=fp,
        remediation=str(data.get("remediation", "")).strip(),
        source_path=source_path,
    )


def load_directory(path: str | Path) -> list[Signature]:
    path = Path(path)
    if not path.is_dir():
        raise SignatureError(f"Signature path is not a directory: {path}")
    signatures = []
    for yaml_file in sorted(path.glob("*.yaml")) + sorted(path.glob("*.yml")):
        signatures.append(load_signature(yaml_file))
    return signatures


def builtin_signatures() -> list[Signature]:
    return load_directory(Path(__file__).resolve().parent / "builtin")
