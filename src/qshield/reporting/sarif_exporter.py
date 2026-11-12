"""SARIF 2.1.0 export (GitHub Security tab compatible)."""

from __future__ import annotations

import json
from typing import Any

from qshield.reporting.finding import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _rule_id(finding: Finding) -> str:
    return finding.signature_id or f"QSHIELD-{finding.threat_type}"


def to_sarif(
    findings: list[Finding],
    tool_name: str = "QSHIELD",
    tool_version: str = "0.1.0",
    information_uri: str = "https://github.com/qshield/qshield",
) -> dict[str, Any]:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rule_id = _rule_id(f)
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": f.title.split(":")[0].strip().replace(" ", "") or rule_id,
            "shortDescription": {"text": f.title[:512]},
            "fullDescription": {"text": f.description[:2048]},
            "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
            "properties": {
                "severity": f.severity,
                "threatType": f.threat_type,
                "confidence": f.confidence,
            },
        })
        region: dict[str, Any] = {}
        if f.location.gate_indices:
            region["startLine"] = max(1, f.location.gate_indices[0] + 1)
        if f.location.gate_ids:
            region["snippet"] = {"text": f"gates: {', '.join(f.location.gate_ids)}"}
        logical = [
            {"fullyQualifiedName": gid, "kind": "member"} for gid in f.location.gate_ids
        ]
        results.append({
            "ruleId": rule_id,
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f.description},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.location.source_file or "circuit.qasm",
                        },
                        **({"region": region} if region else {}),
                    },
                    "logicalLocations": logical,
                }
            ],
            "partialFingerprints": {
                "qshield/v1": f"{f.threat_type}:{f.title}:{','.join(map(str, f.location.gate_indices))}"
            },
            "properties": {
                "confidence": f.confidence,
                "findingId": f.finding_id,
                "falsePositiveProbability": f.false_positive_probability,
                "remediation": f.remediation,
            },
        })

    return {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "informationUri": information_uri,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif(findings: list[Finding], **kwargs) -> str:
    return json.dumps(to_sarif(findings, **kwargs), indent=2)
