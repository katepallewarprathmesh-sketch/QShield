# QSHIELD Transpilation-aware Report v1

**Spec ID:** `qshield-transform-report-v1`  
**Status:** Implemented in the source tree; reports user-supplied pre/post stage files. It does not execute a transpiler.

## Input and pipeline model

The caller supplies an original OpenQASM 2/3 file and one or more `LABEL=FILE` stage outputs in pipeline order. QSHIELD compares each stage against the immediately preceding file and records raw source and versioned canonical circuit digests for both sides. Local paths and source contents are not included in the report.

Example:

```bash
qshield provenance transform-report source.qasm \
  --stage optimize=optimized.qasm \
  --stage map=mapped.qasm \
  --output transpilation-report.json
```

## Verdicts

Each step is `equivalent`, `not_equivalent`, or `inconclusive`:

- **Equivalent:** canonical structural identities match, or an available exact-unitary/ZX method decides equivalence within its stated scope.
- **Not equivalent:** an available exact-unitary/ZX method reports a difference.
- **Inconclusive:** the width or measurement mapping differs, an optional method is unavailable, or resource/representation limits prevent a decision. This is never a pass.

The report records method, scope, and explanation per pass. Exact-unitary comparison is bounded by QSHIELD's existing exact-qubit limit and is not a compiler attestation. Randomized testing is not used to claim equivalence. `--formal` tries ZX first; otherwise the tool tries bounded exact comparison and falls back to ZX when needed. Overall status is `not_equivalent` if any step differs, else `inconclusive` if any step is undecided, else `equivalent`.

The schema is [`transform-report-v1.schema.json`](../src/qshield/provenance/transform-report-v1.schema.json) and is included in the Python package.
