# T2.3 Redesign — Before / After

All figures below are measured, not estimated. Reproduce with:

```
python benchmarks/benchmark.py --check          # main corpus metrics
python benchmarks/t23_baseline_eval.py --check  # T2.3 differential
pytest                                          # 733 passed, 18 skipped
```

The default scan path supplies **no baseline**. That is the honest default: the
scanner does not know what was approved, so T2.3 reports `INDETERMINATE`.

## 1. Headline metrics (default scan path)

| Metric | Before | After |
|---|---|---|
| True positive rate | 0.9116 | **0.5767** |
| False positive rate | 0.3366 | **0.0000** |
| Precision | 0.7424 | **1.0000** |
| Recall | 0.9209 | 0.8279 |
| True positives | 196 | 124 |
| False positives | 68 | **0** |
| False negatives | 19 | 91 |

**TPR fell by 33 points and precision rose to 1.0.** This is the expected
consequence of removing a detector that fired on 68 clean circuits, and it is
reported plainly rather than framed as a win.

## 2. Where the 43 false-positive fixtures went

| | clean fixtures flagged with T2.3 |
|---|---|
| Before | 68 |
| After (no baseline) | **0** |
| After (with genuine reference) | **0** |

The specification's 43 "pure" FPs are the subset where T2.3 was the only finding.
All 68 are now clean, and every one of them was verified against a genuine
reference — its own approved artifact.

## 3. T2.3 detection under a baseline

| Configuration | T2.3 fixtures detected | Clean findings |
|---|---|---|
| Old pattern rule | 20 / 20 | 68 |
| Differential, no baseline | 0 / 20 (20 `INDETERMINATE`) | 0 |
| Differential, baselined | **20 / 20** | **0** |

So the target — preserve 20 detections while removing 43 FPs — is **met when a
trusted reference exists**, and only then. Without one, the check declines to
answer.

### Reference provenance

| Source | Count | Meaning |
|---|---|---|
| `documented` | 16 | Generator documents the pre-tamper base (`gen_basis*`) |
| `derived` | 4 | Hand-written fixtures; readout gate removed to recover the pre-tamper circuit |

No reference was authored to contain the malicious circuit.

### Duplicates

The corpus contains **19 duplicate groups**; the 20 T2.3 fixtures are **11
distinct artifacts** by content. Both denominators are published. The corpus was
not deduplicated, because that would change the published benchmark.

## 4. The T1.3 finding

T1.3 recall was **51/52 before** and **0/52 after**. That is not a regression
introduced by this change; it is a dependency that was hidden by it.

Measured against the previous results file: **51 of the 52 "detected" T1.3
fixtures carried a co-firing T2.3 finding**, and T1.3 findings alone reached only
`low` severity. One fixture (`gen_cancel_2`) has an independent detection but
also only reaches `low`.

```
T1.3 detected without T2.3 help: 1 / 52
```

The published 98.08% T1.3 recall therefore depended on a detector that was
generating 68 false positives. T2.3 was lending T1.3 the severity to cross the
threshold. This is now visible instead of inherited, and is pinned by
`test_t13_recall_was_previously_t23_assisted`.

Fixing T1.3 requires giving gate-cancellation detection real evidence of its own.
That is out of scope here and is not attempted. It is reported as the largest
open defect in the benchmark.

## 5. Preservation of unrelated detectors

| Family | Before | After |
|---|---|---|
| T1.1 micro-rotations | 65/65 | 65/65 |
| T2.1 ancilla/shadow | 15/34 | 15/34 |
| T2.2 parameter/stego | 44/44 | 44/44 |

Golden-file audit: the static-scan golden diff is **287 T2.3 entries removed,
zero non-T2.3 changes**.

## 6. What this benchmark does not claim

- These are fixture-corpus measurements, not production detection rates.
- A tampered circuit with no genuine reference is reported `INDETERMINATE` and
  counted as a miss. The redesigned check cannot detect what it has no reference
  for; that is a property of the approach, not a tuning gap.
- Precision 1.0 reflects the corpus. It is not a guarantee.
