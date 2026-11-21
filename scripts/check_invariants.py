"""Check invariants that are cheap to state and expensive to rediscover.

Each rule here exists because it was broken at least once. They are mechanical
on purpose: a rule a human has to remember is a rule that eventually gets
forgotten, and the failure mode (a silently fabricated benchmark number, or a
second detector quietly re-introducing a removed defect) is worse than a red
build.

Run: python scripts/check_invariants.py
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class Violation(Exception):
    pass


def check_no_docs_directory() -> None:
    """`docs/` is forbidden: it would ship internal notes into the distribution."""
    if (ROOT / "docs").exists():
        raise Violation(
            "docs/ must not exist (see scripts/check_public_docs_boundary.py). "
            "Design notes do not belong in this repository."
        )


def check_t23_has_one_producer() -> None:
    """Exactly one module may emit a T2.3 finding.

    The defect this guards against: T2.3 had two independent emitters, so fixing
    one left the other producing all 68 false positives. If a third appears,
    this fails.
    """
    offenders: list[str] = []
    for path in (ROOT / "src").rglob("*.py"):
        source = path.read_text()
        if "T2.3" not in source:
            continue
        # Only count sites that actually construct a finding with T2.3.
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.keyword) and node.arg == "threat_type":
                value = node.value
                if isinstance(value, ast.Constant) and value.value == "T2.3":
                    offenders.append(str(path.relative_to(ROOT)))
    allowed = {"src/qshield/integrity/evaluate.py"}
    unexpected = sorted(set(offenders) - allowed)
    if unexpected:
        raise Violation(
            f"T2.3 findings constructed outside {sorted(allowed)}: {unexpected}. "
            "T2.3 is a baseline differential; adding a pattern emitter re-introduces "
            "the false positives the redesign removed."
        )


def check_benchmark_results_are_not_hand_edited() -> None:
    """Published results must carry the metrics the corpus actually produces.

    Guards against the temptation to improve a number by editing JSON. This is a
    shape/consistency check, not a re-run: CI does the re-run via --check.
    """
    path = ROOT / "benchmarks" / "results" / "benchmark-v1.json"
    data = json.loads(path.read_text())
    metrics = data["metrics"]
    counts = metrics["counts"]

    clean = counts["clean"]
    malicious = counts["malicious"]
    tp = counts["true_positives"]
    fp = counts["false_positives"]
    tn = counts["true_negatives"]
    fn = counts["false_negatives"]

    def close(a: float, b: float, tol: float = 1e-4) -> bool:
        return abs(a - b) <= tol

    problems = []
    if tp + fn != malicious:
        problems.append(f"TP+FN ({tp}+{fn}) != malicious ({malicious})")
    if fp + tn != clean:
        problems.append(f"FP+TN ({fp}+{tn}) != clean ({clean})")
    if not close(metrics["tpr"], tp / malicious if malicious else 0):
        problems.append(f"tpr {metrics['tpr']} does not match TP/malicious {tp}/{malicious}")
    if not close(metrics["fpr"], fp / clean if clean else 0):
        problems.append(f"fpr {metrics['fpr']} does not match FP/clean {fp}/{clean}")
    if tp + fp:
        precision = tp / (tp + fp)
        if not close(metrics["precision"], precision):
            problems.append(f"precision {metrics['precision']} != {precision:.4f}")
    if problems:
        raise Violation("benchmark metrics are internally inconsistent: " + "; ".join(problems))


def check_archived_results_are_marked() -> None:
    """A historical results file must be unmistakable so it is never quoted as current."""
    for path in (ROOT / "benchmarks" / "results").glob("*.json"):
        if path.name == "benchmark-v1.json":
            continue
        data = json.loads(path.read_text())
        if data.get("archived") is True and data.get("archived_note"):
            continue
        if "spec_version" in data:  # a live, non-archived result set
            continue
        raise Violation(
            f"{path.relative_to(ROOT)} is neither the current results file nor "
            "marked archived with an archived_note"
        )


def check_no_new_markdown() -> None:
    """No new `.md` files outside the allowlist.

    Internal notes, audits and design write-ups do not belong in a public
    package: they expose implementation detail and turn the repo into a journal.
    The allowlist is the set of documents that were already published for
    released formats; nothing else may be added.
    """
    allowed = {
        "README.md",
        "CHANGELOG.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "AGENTS.md",
        "benchmarks/benchmark-v1.md",
        "editors/vscode/qshield/README.md",
        "examples/plugins/identity-pair/README.md",
        "src/qshield/signatures/community/CONTRIBUTING.md",
        "specs/circuit-canonicalization-v1.md",
        "specs/coverage-v1.md",
        "specs/provenance-v1.md",
        "specs/qubo-model-audit-v1.md",
        "specs/transpilation-report-v1.md",
    }
    found = {
        str(path.relative_to(ROOT))
        for path in ROOT.rglob("*.md")
        if not any(
            part in {".git", "node_modules", "build", "dist", ".venv", ".pytest_cache"}
            for part in path.relative_to(ROOT).parts
        )
    }
    unexpected = sorted(found - allowed)
    if unexpected:
        raise Violation(
            f"unexpected marketing/notes file(s): {unexpected}. Keep prose in "
            "README.md, CHANGELOG.md and docstrings. If a released format genuinely "
            "needs a spec, add it to the allowlist deliberately."
        )


def check_fixture_copies_match() -> None:
    """The packaged fixtures must be byte-identical to the test fixtures.

    They are duplicated: tests/fixtures/ for the benchmark, src/qshield/fixtures/
    for the installed package. Nothing regenerates both, so an edit to one
    silently leaves the other stale and the UI serves circuits that no longer
    match the corpus.
    """
    pairs = []
    for split in ("clean_circuits", "malicious_circuits"):
        pairs.append((ROOT / "tests" / "fixtures" / split, ROOT / "src" / "qshield" / "fixtures" / split))
    drift = []
    for source, copy in pairs:
        if not source.is_dir() or not copy.is_dir():
            continue
        for path in sorted(source.glob("*.qasm")):
            twin = copy / path.name
            if not twin.exists() or twin.read_bytes() != path.read_bytes():
                drift.append(path.name)
    if drift:
        names = sorted(drift)
        raise Violation(
            f"{len(names)} fixture(s) out of sync between tests/fixtures and "
            f"src/qshield/fixtures: {names[:5]}. Copy them across (and fix the "
            "generator if the difference came from regenerating the corpus)."
        )


CHECKS = (
    check_no_docs_directory,
    check_t23_has_one_producer,
    check_benchmark_results_are_not_hand_edited,
    check_archived_results_are_marked,
    check_no_new_markdown,
    check_fixture_copies_match,
)


def main() -> int:
    failed = 0
    for check in CHECKS:
        name = check.__name__.removeprefix("check_")
        try:
            check()
        except Violation as exc:
            print(f"FAIL  {name}\n      {exc}")
            failed += 1
        except Exception as exc:  # noqa: BLE001 - a broken check must be visible
            print(f"ERROR {name}: {type(exc).__name__}: {exc}")
            failed += 1
        else:
            print(f"OK    {name}")
    print()
    print("invariants hold" if not failed else f"{failed} invariant(s) violated")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
