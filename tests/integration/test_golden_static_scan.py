"""Golden tests for the static scan pipeline (implementation plan Task 2.1).

Pins the exact findings the engine produces on every bundled fixture, so any
future IR or detector refactor must be provably output-neutral.

If this test fails after an *intentional* engine change, review the diff, then
regenerate the golden file deliberately:

    QSHIELD_UPDATE_GOLDEN=1 pytest tests/integration/test_golden_static_scan.py

and commit the updated ``tests/fixtures/golden_static_scan.json`` together with
the engine change. Never refresh blindly.

What is pinned: severity, threat type, title, confidence, gate/qubit indices,
evidence type and normalized evidence details, signature id — in emission
order. What is deliberately NOT pinned: finding ids and circuit ids (random
uuids), timing, and total elapsed time.
"""

import json
import os
from pathlib import Path

import pytest

from qshield import Scanner

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures"
GOLDEN = ROOT / "tests" / "fixtures" / "golden_static_scan.json"


def _fingerprint(finding) -> dict:
    details = finding.evidence.details if finding.evidence else {}

    def _norm(obj):
        if isinstance(obj, float):
            return round(obj, 6)
        if isinstance(obj, dict):
            return {str(k): _norm(v) for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
        if isinstance(obj, (list, tuple)):
            return [_norm(v) for v in obj]
        return obj

    location = finding.location
    return {
        "severity": finding.severity,
        "threat_type": finding.threat_type,
        "title": finding.title,
        "confidence": round(finding.confidence, 6),
        "signature_id": finding.signature_id,
        "gate_indices": list(location.gate_indices),
        "qubit_indices": list(location.qubit_indices),
        "evidence_type": finding.evidence.evidence_type if finding.evidence else None,
        "details": _norm(details),
    }


def _scan_fixture(path: Path) -> list[dict]:
    scanner = Scanner()
    scanner.add_circuit(path.read_text(encoding="utf-8"), name=path.stem)
    results = scanner.run(analyses=["static"])
    return [_fingerprint(f) for f in results.findings]


def _all_fixtures() -> list[Path]:
    out = list(FIXTURES.rglob("*.qasm"))
    assert out, "fixture corpus not found"
    return sorted(out)


@pytest.mark.skipif(os.environ.get("QSHIELD_SKIP_GOLDEN") == "1", reason="golden tests disabled")
def test_static_scan_matches_golden():
    fixtures = _all_fixtures()
    current = {str(p.relative_to(ROOT)): _scan_fixture(p) for p in fixtures}

    if os.environ.get("QSHIELD_UPDATE_GOLDEN") == "1":
        GOLDEN.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        pytest.skip(f"golden file regenerated at {GOLDEN} ({len(current)} fixtures)")

    if not GOLDEN.exists():
        pytest.fail(
            f"golden file missing: {GOLDEN}\n"
            "generate it with: QSHIELD_UPDATE_GOLDEN=1 pytest tests/integration/test_golden_static_scan.py"
        )

    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    missing = sorted(set(current) - set(expected))
    stale = sorted(set(expected) - set(current))
    changed = sorted(k for k in set(current) & set(expected) if current[k] != expected[k])

    problems = []
    if missing:
        problems.append(f"fixtures absent from golden: {missing}")
    if stale:
        problems.append(f"fixtures in golden but not on disk: {stale}")
    if changed:
        preview = []
        for key in changed[:5]:
            preview.append(f"  {key}:\n    expected {json.dumps(expected[key], sort_keys=True)}\n    actual   {json.dumps(current[key], sort_keys=True)}")
        problems.append("fingerprints changed:\n" + "\n".join(preview))

    assert not problems, (
        "static scan output changed. If intentional, regenerate the golden file:\n"
        "  QSHIELD_UPDATE_GOLDEN=1 pytest tests/integration/test_golden_static_scan.py\n"
        + "\n".join(problems)
    )
