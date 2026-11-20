# T2.3 Baseline-Differential — Repository Audit (Phase 0)

**HEAD at audit:** `ee49b30` · **Date:** 20 November 2026

Every claim below was read from the current source tree, not from prior reports.

---

## 1. Existing T2.3 implementation

| Location | Role |
|---|---|
| `src/qshield/static/structural_analyzer.py:475-517` | `check_measurement_basis()` — the context-free pattern rule |
| `src/qshield/static/structural_analyzer.py:73-76` | `_BASIS_CHANGE_GATES` map: gate → (severity, confidence) |
| `src/qshield/signatures/builtin/measurement_manipulation.yaml` | Duplicate signature rule (QSig-2024-0004) emitting the same T2.3 |
| `src/qshield/core/config.py:22` | `check_measurement_basis: True` toggle |

### Current execution flow

```
Scanner.run()
  └─ StructuralAnalyzer.analyze(circuit)
       └─ if config.static_check("check_measurement_basis"):
            check_measurement_basis(circuit)
              for each measured qubit q:
                find last gate touching q
                if that gate ∈ _BASIS_CHANGE_GATES:
                   emit Finding(T2.3)          ← context-free
  └─ SignatureMatcher.match(circuit)
       └─ QSig-2024-0004 emits a second T2.3 for the same condition
```

The check is purely local: circuit in, finding out. There is **no reference, no baseline, and no notion of "should have been"**. A correct Deutsch circuit and a tampered readout are indistinguishable to it, which is the defect.

**`scan()` accepts no reference.** `qshield.scan(source)` and `Scanner.add_circuit()` take a circuit only.

## 2. Reusable components (do not rewrite)

| Component | Path | Reuse |
|---|---|---|
| Canonical circuit hash, versioned | `core/canonicalization.py` — `qshield-circuit-c14n-v1` | Baseline + candidate identity |
| Circuit IR | `core/circuit_ir.py` | Both sides of the comparison |
| QASM parser | `core/parsers/` | Candidate and reference parsing |
| Ed25519 signing/verification | `provenance/manifest.py` — `sign_manifest`, `verify_manifest` | **Baseline attestation** |
| Policy engine | `policy.py` — `PolicySpec`, `check_policy` | Gating |
| Findings model | `reporting/finding.py` — `Finding`, `Evidence`, `CircuitLocation` | Evidence output |
| Benchmark harness | `benchmarks/benchmark.py` | Before/after measurement |

`provenance/manifest.py` already implements Ed25519 with `key_id = "sha256:" + sha256(pubkey)`. The task says not to introduce an unrelated signing implementation — I will reuse this directly.

## 3. Required modifications

1. New module `src/qshield/integrity/readout.py` — readout extraction and differential classification.
2. New module `src/qshield/integrity/baseline.py` — baseline records, trust states, signing, revocation, rollback defence.
3. New module `src/qshield/integrity/evaluate.py` — the T2.3 evaluator returning PASS / FINDING / INDETERMINATE / ERROR.
4. `StructuralAnalyzer.check_measurement_basis` — **must stop producing T2.3 findings** for a bare pattern match, or it will re-inject every false positive.
5. `signatures/builtin/measurement_manipulation.yaml` — the duplicate signature must be re-scoped the same way, or it alone preserves the 68 FPs.
6. `Scanner` — optional baseline registry; unchanged default behaviour when absent.
7. `benchmark.py` — differential path alongside the existing measurement.

## 4. Potential regressions

| Risk | Mitigation |
|---|---|
| Two components emit T2.3; fixing one leaves 68 FPs | Both are changed; a test asserts exactly one T2.3 source remains |
| Removal of the pattern rule silently drops T2.3 entirely | Explicit INDETERMINATE state when no baseline is supplied |
| Baseline signing could accept a substituted file | Digest binding tested against substitution and rollback |
| Other detectors affected by normalisation changes | No change to T1.1/T1.3/T2.1/T2.2 code paths |

## 5. Three findings that change the plan

### 5.1 The corpus has duplicate fixtures

`gen_basis_0_h`, `gen_basis2_0_h` and `gen_basis2_6_h` are **byte-identical**. Across the malicious set there are **19 duplicate groups**. The "20 T2.3 malicious fixtures" are ~8 distinct circuits, so 16 distinct generated readout-tamper circuits is the honest denominator.

I will **not** deduplicate the corpus — that would change the published benchmark. I report the true distinct count in the after-report.

### 5.2 A "genuine reference" can be defined without fabricating approval

The generator (`benchmarks/generate_corpus.py:231-234, 320-325`) documents the pre-tamper base for every `gen_basis*` fixture:

```python
body = f"h q[0];\ncx q[0], q[1];\n{gate} q[{k % 2}];\n"   # malicious = base + injected gate
```

The approved reference is therefore **the same circuit with the injected basis change removed** — a real pre-tamper artifact, not a hand-written baseline that encodes the malicious circuit as approved. `measurement_manipulation`, `x_before_measure`, `y_before_measure` and `tdg_before_measure` are hand-written and have no generated base; for those I will report explicitly that no genuine reference exists in the repository rather than invent one.

### 5.3 `docs/` is forbidden by an existing gate

`scripts/check_public_docs_boundary.py:22` raises if `docs/` exists in the source tree. The task's §10 requires four files under `docs/`. I verified the gate rejects it.

**Decision:** write them under `specs/` (where `qubo-model-audit-v1.md` and the other engineering specs live) and report the deviation. Creating `docs/` would break CI and violate the project's own public-boundary contract.

## 6. Proposed approach

Prototype result (measured, not assumed), using the generator-documented base as reference:

```
MALICIOUS: 16/16 gen_basis* fixtures show a readout differential vs base
CLEAN    :  0/43 T2.3-only false positives still fire (reference = self)
```

Implement as a four-state evaluator:

- **PASS** — baseline trusted, readout identical.
- **FINDING** — baseline trusted, readout differs; evidence names each difference.
- **INDETERMINATE** — no baseline, revoked, expired, unverified, wrong workload, or parser mismatch.
- **ERROR** — malformed input or internal failure.

Comparison is split into distinct properties that must not collapse to one boolean: exact artifact equality, structural difference, readout difference, functional equivalence (reusing the existing comparison engine), and unresolved semantic difference.
