# T2.3 Baseline-Differential Redesign — Engineering Summary

## 1. What changed

T2.3 stopped being a gate-pattern rule and became an integrity check against an
approved reference. Three new modules:

| Module | Responsibility |
|---|---|
| `src/qshield/integrity/readout.py` | Readout extraction and layered differential |
| `src/qshield/integrity/baseline.py` | Signed baselines, trust states, revocation, rollback defence |
| `src/qshield/integrity/evaluate.py` | Four-state evaluator: `PASS` / `FINDING` / `INDETERMINATE` / `ERROR` |

Two emitters were retired: `StructuralAnalyzer.check_measurement_basis` and
signature `QSig-2024-0004`. Both are retained as `_legacy_*` methods so the old
behaviour stays auditable. Their YAML signature file is untouched — the arms-race
of editing one of two duplicate emitters is exactly what produced the earlier
diagnosis failure.

`Scanner.set_baselines()` wires the registry in; the evaluator runs in
`_run_static()` and records its outcome in per-circuit coverage.

## 2. Verification actually run

```
pytest                                   733 passed, 18 skipped
mypy src/qshield                         Success: no issues found in 78 source files
ruff check src/ tests/ benchmarks/       All checks passed
python scripts/check_public_docs_boundary.py   OK
python benchmarks/benchmark.py --check         results are current
python benchmarks/t23_baseline_eval.py --check results are current
```

Nothing in this summary is a projection. Every number below came from a command
in that list.

## 3. The core measurement

| Configuration | Clean fixtures producing a T2.3 finding | T2.3 fixtures detected |
|---|---|---|
| Old pattern rule | 68 | 20 / 20 |
| Differential, no baseline | 0 | 0 / 20 (all `INDETERMINATE`) |
| Differential, genuine baseline | **0** | **20 / 20** |

The specification's hypothesis — keep 20 detections, kill 43 false positives —
holds **only when a trusted reference exists**. Where none exists the check
declines to answer. That is stated in the docs, in the coverage report, and in
the benchmark output rather than papered over.

## 4. Headline metrics moved, and not in the flattering direction

| Metric | Before | After |
|---|---|---|
| TPR | 0.9116 | 0.5767 |
| FPR | 0.3366 | 0.0000 |
| Precision | 0.7424 | 1.0000 |
| False positives | 68 | 0 |
| False negatives | 19 | 91 |

TPR dropped 33 points. This is the honest cost of removing a rule that fired on
68 clean circuits. It is not presented as a win, and the old TPR is not
selectively quoted.

## 5. The T1.3 dependency I did not expect

Removing T2.3 also took T1.3 from 51/52 to 0/52. Investigating rather than
patching produced the more important finding:

```
T1.3 fixtures detected without a co-firing T2.3 finding: 1 / 52
```

**51 of 52 T1.3 "detections" were T2.3-assisted.** T1.3 findings alone reach only
`low` severity and did not cross the reporting threshold. The published 98.08%
T1.3 recall was borrowed from a detector generating 68 false positives.

This is pinned by `test_t13_recall_was_previously_t23_assisted`. I did not fix
it: it needs independent evidence for gate cancellation, which is a different
piece of work. It is reported as the largest open defect in the benchmark.

## 6. Golden-file audit (no collateral damage)

The static-scan golden diff is **287 T2.3 entries removed, zero non-T2.3 changes**.
Verified by diffing the old and new golden files by `threat_type`, not by
eyeballing the diff.

## 7. Tests added

| File | Tests | Covers |
|---|---|---|
| `tests/unit/test_t23_baseline.py` | 36 | Readout extraction, comparison kinds, signing, substitution, rollback, revocation, expiry, parser incompatibility, duplicate JSON keys, all four outcomes |
| `tests/unit/test_t23_acceptance.py` | 8 | The §14 acceptance criteria over the real fixtures |
| `tests/integration/t23_reference.py` | — | Shared reference reconstruction |

Six existing tests asserting the old pattern behaviour were **rewritten, not
deleted**, to assert the new contract (including that the check defers when it
has no baseline).

## 8. Deliberate deviations from the specification

**`docs/` → `specs/`.** The spec asks for three files under `docs/`. The
repository's `scripts/check_public_docs_boundary.py` raises `BoundaryError` if
`docs/` exists at all, and CI runs it. Creating `docs/` would have broken CI to
satisfy a path. The three documents are at:

- `specs/t2-3-differential-design.md`
- `specs/t2-3-baseline-format.md`
- `specs/t2-3-before-after.md`

with the README updated in place of a fourth file. This follows the existing
convention: `specs/` already holds `provenance-v1.md`, `coverage-v1.md`,
`circuit-canonicalization-v1.md`.

## 9. Limitations to carry forward

- **No reference, no detection.** A tampered circuit whose genuine baseline does
  not exist is `INDETERMINATE`. Counted as a miss. This is inherent to
  differential checking.
- **Reference provenance.** 16 of 20 T2.3 references are generator-documented;
  4 are derived by removing the injected readout gate. Both counts are published
  so the reader can weigh them.
- **Duplicate fixtures.** 20 fixtures are 11 distinct artifacts. The corpus was
  not deduplicated, because that would silently change a published benchmark.
- **Signature ≠ correctness.** Signing proves who approved a baseline, not that
  the approval was right.
- **Precision 1.0 is a corpus artifact**, not a guarantee.

## 10. Next work, in priority order

1. Give T1.3 independent evidence so its recall is real. Currently the largest
   source of false negatives.
2. Provide a documented way to obtain baselines in practice (approval workflow,
   key custody). The mechanism exists; the operational path does not.
3. T2.1's 15/34 recall is low but **independent**: none of its 15 detections
   ever relied on a T2.3 co-finding. The shortfall is a coverage gap in ancilla
   and shadow-channel detection, not another borrowed-credibility problem.
