# T2.3 Readout Differential — Design

**Status:** implemented
**Spec version:** `qshield-t23-differential-v1`
**Supersedes:** the context-free "basis change before measurement" pattern rule

## 1. The problem with the old check

T2.3 previously fired whenever a basis-rotation gate was the last operation on a
measured qubit. That is a description of the *gate pattern*, not of an attack.

A correct Deutsch circuit ends with a Hadamard before measurement. So does a
correct Bernstein–Vazirani circuit. So does every fixture in the corpus that
prepares a readout basis. The old rule fired on all of them:

| | clean fixtures flagged | T2.3 fixtures detected |
|---|---|---|
| old pattern rule | **68** | 20 |

Those 68 false positives were not a tuning problem. They were the rule working
exactly as written. The corpus analysis confirmed it: clean and malicious T2.3
circuits are **gate-for-gate identical at the tail**. There is no local signal
that distinguishes them, because the difference is not local — it is whether the
readout was *approved*.

## 2. What replaces it

A differential against a trusted reference:

```
candidate  ──extract──▶  readout profile ─┐
                                          ├─▶ compare ──▶ verdict
reference  ──verify───▶  readout profile ─┘
```

The reference must be verified **before** it is used:

1. The baseline record is signed (Ed25519) and covers the circuit digest, the
   readout digest, the workload identity and a monotonic version.
2. The registry refuses a record whose signature does not verify, whose version
   is not newer than the approved one (rollback), or which is revoked/expired.
3. The evaluator re-derives the digests of the loaded reference circuit and
   refuses the comparison if they do not match the signed payload — so a
   substituted reference cannot be smuggled in behind a valid signature.

## 3. The four states

The evaluator never collapses uncertainty into a verdict.

| Outcome | Meaning | Blocks? |
|---|---|---|
| `PASS` | baseline trusted, readout unchanged | no |
| `FINDING` | baseline trusted, readout differs | yes |
| `INDETERMINATE` | no usable baseline, or a comparison that cannot be resolved | **yes** |
| `ERROR` | malformed input or internal failure | **yes** |

A missing baseline is `INDETERMINATE`, not a pass and not a finding. Treating
"no reference" as "clean" is how a tampered circuit would walk through, and
treating it as "malicious" is how the old rule produced 68 false positives.

## 4. What counts as a readout difference

The readout profile of a circuit records, per measured qubit, the classical bit
it maps to, the final operation before measurement, and whether that operation
is a basis rotation.

Differences are reported by name:

- `qubit_newly_measured` / `qubit_no_longer_measured`
- `classical_bit_remapped`
- `final_operation_changed`
- `basis_rotation_changed`
- `width_changed`

A change that does **not** touch the readout (an extra gate earlier in the
circuit, say) is `STRUCTURE_DIFFERS` and is *not* a T2.3 finding. It is reported
as a pass for this question with the difference recorded, so another detector or
a human can take it up. T2.3 answers one question and does not speculate beyond
it.

## 5. Where it lives

| Component | Path |
|---|---|
| Readout extraction and comparison | `src/qshield/integrity/readout.py` |
| Baseline record, signing, registry | `src/qshield/integrity/baseline.py` |
| Four-state evaluator | `src/qshield/integrity/evaluate.py` |
| Scanner integration | `Scanner.set_baselines()` → `_run_static()` |

The two former emitters (`StructuralAnalyzer.check_measurement_basis` and the
`QSig-2024-0004` signature) are retained but no longer emit. Their legacy bodies
are kept as `_legacy_*` methods so the historical behaviour stays auditable.

## 6. Deliberate limits

- The check cannot detect a tampered circuit for which no genuine reference
  exists. This is a real limitation, not a bug: it is reported as
  `INDETERMINATE` and counted as a miss in the benchmark.
- The reference must be an approved artifact. Deriving a "reference" by editing
  the malicious circuit would make the check vacuous; the benchmark records how
  each reference was obtained (`documented`, `derived`, `self`) so the reader can
  judge it.
- Signing proves *who approved what*. It does not prove the approver was right.
