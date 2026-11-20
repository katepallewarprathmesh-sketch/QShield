"""T2.3 baseline-differential evaluation over the bundled corpus.

Measures three configurations so they can never be confused with one another:

1. **pattern**   — the historical context-free rule, reproduced from the legacy
                   implementation, for the before column.
2. **absent**    — the redesigned check with no baselines: T2.3 reports
                   INDETERMINATE and contributes no findings.
3. **baselined** — the redesigned check with an approved, signed reference for
                   each fixture whose reference the generator documents.

Run: ``python benchmarks/t23_baseline_eval.py [--write]``
"""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qshield.core.circuit_ir import CircuitIR
from qshield.core.parsers import parse_qasm
from qshield.integrity.baseline import BaselineRegistry, create_baseline, sign_baseline
from qshield.integrity.evaluate import evaluate_t23
from qshield.integrity.readout import compare_readout
from qshield.scanner import Scanner

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures"
RESULTS = REPO / "benchmarks" / "results" / "t23-baseline-eval.json"
SPEC = "qshield-t23-baseline-eval-v1"

#: Gates the historical rule watches, used only to reproduce the "before" column.
BASIS_GATES = frozenset({"h", "x", "y", "s", "sdg", "t", "tdg"})


@dataclass
class Fixture:
    name: str
    split: str
    expected: str | None
    path: Path


def load_corpus_index() -> dict[str, str | None]:
    index = json.loads((REPO / "benchmarks" / "corpus_index.json").read_text())
    generated = index.get("generated_malicious", {})
    curated = {
        "ancilla_leakage": "T2.1",
        "cx_cx_separated": "T1.3",
        "distributed_backdoor": "T1.1",
        "fanout_shadow_channel": "T2.1",
        "h_cancellation_adjacent": "T1.3",
        "identity_pair_hidden": "T1.3",
        "leaf_ancilla_measure": "T2.1",
        "leaf_ancilla_swap": "T2.1",
        "measurement_manipulation": "T2.3",
        "micro_rotation_dense": "T1.1",
        "micro_rotation_hidden": "T1.1",
        "parameter_encoded": "T2.2",
        "s_sdg_separated": "T1.3",
        "stego_ascii_backdoor": "T2.2",
        "stego_ascii_qshield": "T2.2",
        "tdg_before_measure": "T2.3",
        "x_before_measure": "T2.3",
        "y_before_measure": "T2.3",
        "y_y_pair_separated": "T1.3",
        "z_cancellation_hidden": "T1.3",
    }
    return {**curated, **generated}


def load_fixtures() -> list[Fixture]:
    expected = load_corpus_index()
    out: list[Fixture] = []
    for split, folder in (("clean", "clean_circuits"), ("malicious", "malicious_circuits")):
        for path in sorted((FIXTURES / folder).glob("*.qasm")):
            out.append(
                Fixture(
                    name=path.stem,
                    split=split,
                    expected=None if split == "clean" else expected.get(path.stem),
                    path=path,
                )
            )
    return out


# ----------------------------------------------------------------------
# Reference construction
# ----------------------------------------------------------------------
def _strip_readout_gates(source: str) -> str:
    """Remove basis-rotation gates that sit between the last entangling work and
    the measurements.

    This reconstructs the pre-tamper artifact: the circuit as it was before the
    readout-stage gate was injected. It is applied only to the four hand-written
    T2.3 fixtures, which the generator does not produce, and those are labelled
    ``derived`` rather than ``documented`` in the report.
    """
    lines = source.splitlines()
    measure_at = next((i for i, line in enumerate(lines) if line.strip().startswith("measure")), None)
    if measure_at is None:
        return source
    # Walk backwards over contiguous readout-stage statements.
    cut = measure_at
    while cut > 0:
        candidate = lines[cut - 1].strip()
        if not candidate or candidate.startswith("//"):
            cut -= 1
            continue
        token = candidate.split()[0] if candidate.split() else ""
        if token in BASIS_GATES:
            cut -= 1
            continue
        break
    return "\n".join(lines[:cut] + lines[measure_at:]) + "\n"


def reference_for(fixture: Fixture) -> tuple[CircuitIR | None, str]:
    """Return the approved reference circuit and how it was obtained."""
    source = fixture.path.read_text()
    # Documented: the generator builds gen_basis* as base + one injected gate.
    if fixture.expected == "T2.3" and fixture.name.startswith("gen_basis"):
        return parse_qasm(_strip_readout_gates(source)), "documented"
    # Derived: hand-written fixtures; the readout gate is removed to recover the
    # pre-tamper circuit. Recorded as derived because no generator defines it.
    if fixture.expected == "T2.3":
        return parse_qasm(_strip_readout_gates(source)), "derived"
    # Clean fixtures: the approved artifact is the circuit itself.
    return parse_qasm(source), "self"


# ----------------------------------------------------------------------
# Measurement
# ----------------------------------------------------------------------
def legacy_pattern_fires(circuit: CircuitIR) -> bool:
    """Reproduce the historical T2.3 rule for the before column."""
    measured = {q for q, _ in circuit.measurements}
    if not measured:
        return False
    last: dict[int, str] = {}
    for gate in circuit.gates:
        for qubit in gate.qubits:
            last[qubit] = gate.gate_name
    return any(last.get(q) in BASIS_GATES for q in measured)


def scan_flags(circuit: CircuitIR) -> bool:
    """Run the real static pipeline and report whether anything reaches medium."""
    scanner = Scanner(parallel=False)
    scanner.add_circuit(circuit)
    results = scanner.run(analyses=["static"])
    return any(
        f.severity in {"critical", "high", "medium"} for f in results.findings
    )


def measure() -> dict[str, Any]:
    fixtures = load_fixtures()

    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )

    registry = BaselineRegistry()
    refs: dict[str, tuple[CircuitIR | None, str]] = {}
    for fixture in fixtures:
        if fixture.split != "clean" and fixture.expected != "T2.3":
            continue
        reference, provenance = reference_for(fixture)
        refs[fixture.name] = (reference, provenance)
        if reference is None:
            continue
        record = sign_baseline(
            create_baseline(
                reference,
                workload_id=f"fixture:{fixture.name}",
                approved_by="benchmarks/t23_baseline_eval.py",
            ),
            private_pem,
        )
        registry.register(record, public_key_pem=public_pem)

    per_fixture: list[dict[str, Any]] = []
    for fixture in fixtures:
        circuit = parse_qasm(fixture.path.read_text())
        legacy = legacy_pattern_fires(circuit)
        result = evaluate_t23(
            circuit,
            registry=registry,
            workload_id=f"fixture:{fixture.name}",
            public_key_pem=public_pem,
        )
        # The no-baseline configuration must be measured separately: passing the
        # registry would silently report the baselined outcome in both columns.
        absent = evaluate_t23(
            circuit,
            registry=None,
            workload_id=f"fixture:{fixture.name}",
        )
        reference, provenance = refs.get(fixture.name, (None, "none"))

        readout_changed = None
        if reference is not None:
            readout_changed = compare_readout(circuit, reference).is_readout_change

        per_fixture.append(
            {
                "name": fixture.name,
                "split": fixture.split,
                "expected": fixture.expected,
                "legacy_pattern_fires": legacy,
                "t23_outcome": result.outcome.value,
                "t23_outcome_no_baseline": absent.outcome.value,
                "reference_provenance": provenance,
                "readout_changed": readout_changed,
            }
        )

    clean = [f for f in per_fixture if f["split"] == "clean"]
    malicious = [f for f in per_fixture if f["split"] == "malicious"]
    t23_family = [f for f in malicious if f["expected"] == "T2.3"]

    def _summarise(rows: list[dict[str, Any]], field: str) -> dict[str, int]:
        return {
            "total": len(rows),
            "flagged": sum(1 for r in rows if r[field] is True),
        }

    return {
        "spec_version": SPEC,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "corpus": {"clean": len(clean), "malicious": len(malicious)},
        "summary": {
            "legacy_pattern": {
                "clean_flagged": _summarise(clean, "legacy_pattern_fires")["flagged"],
                "t23_family_flagged": _summarise(t23_family, "legacy_pattern_fires")["flagged"],
            },
            "differential_absent": {
                "clean_findings": sum(
                    1 for r in clean if r["t23_outcome_no_baseline"] == "finding"
                ),
                "clean_indeterminate": sum(
                    1 for r in clean if r["t23_outcome_no_baseline"] == "indeterminate"
                ),
                "t23_family_findings": sum(
                    1 for r in t23_family if r["t23_outcome_no_baseline"] == "finding"
                ),
                "t23_family_indeterminate": sum(
                    1 for r in t23_family if r["t23_outcome_no_baseline"] == "indeterminate"
                ),
            },
            "differential_baselined": {
                "clean_findings": sum(1 for r in clean if r["t23_outcome"] == "finding"),
                "t23_family_findings": sum(
                    1 for r in t23_family if r["t23_outcome"] == "finding"
                ),
                "t23_family_pass": sum(1 for r in t23_family if r["t23_outcome"] == "pass"),
                "t23_family_indeterminate": sum(
                    1 for r in t23_family if r["t23_outcome"] == "indeterminate"
                ),
            },
            "reference_provenance": {
                "documented": sum(
                    1 for r in t23_family if r["reference_provenance"] == "documented"
                ),
                "derived": sum(1 for r in t23_family if r["reference_provenance"] == "derived"),
            },
        },
        "distinct_t23_fixtures": len({_digest(f) for f in t23_family}),
        "per_fixture": per_fixture,
    }


def _digest(fixture: dict[str, Any]) -> str:
    path = FIXTURES / (
        "clean_circuits" if fixture["split"] == "clean" else "malicious_circuits"
    ) / f"{fixture['name']}.qasm"
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write results JSON")
    parser.add_argument("--check", action="store_true", help="fail if results are stale")
    args = parser.parse_args()

    report = measure()
    summary = report["summary"]

    print("T2.3 baseline-differential evaluation")
    print(f"  corpus: {report['corpus']['clean']} clean, {report['corpus']['malicious']} malicious")
    print(f"  distinct T2.3 fixtures by content: {report['distinct_t23_fixtures']}")
    print()
    print(f"  legacy pattern rule      : clean flagged {summary['legacy_pattern']['clean_flagged']}"
          f", T2.3 family flagged {summary['legacy_pattern']['t23_family_flagged']}")
    print(f"  differential, no baseline: clean findings {summary['differential_absent']['clean_findings']}"
          f", T2.3 family findings {summary['differential_absent']['t23_family_findings']}"
          f" (indeterminate {summary['differential_absent']['t23_family_indeterminate']})")
    print(f"  differential, baselined  : clean findings {summary['differential_baselined']['clean_findings']}"
          f", T2.3 family findings {summary['differential_baselined']['t23_family_findings']}")
    print(f"  reference provenance     : {summary['reference_provenance']}")

    payload = json.dumps(report, indent=1, sort_keys=True) + "\n"
    # Timestamps must not make a reproducible result look stale.
    comparable = json.dumps({**report, "generated_at": "<ts>"}, indent=1, sort_keys=True) + "\n"
    if args.write:
        RESULTS.parent.mkdir(parents=True, exist_ok=True)
        RESULTS.write_text(payload)
        print(f"\nwrote {RESULTS.relative_to(REPO)}")
    if args.check:
        if not RESULTS.exists():
            print("no results file to check")
            return 1
        stored = json.loads(RESULTS.read_text())
        if (
            json.dumps({**stored, "generated_at": "<ts>"}, indent=1, sort_keys=True) + "\n"
            != comparable
        ):
            print("results are stale; rerun with --write")
            return 1
        print("results are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
