# Contributing to the QSHIELD Community Signature Pack

The community pack is the public signature channel for QSHIELD. A merged
contribution ships to every QSHIELD installation that runs
`qshield sig update` (there is no background auto-update; installing is
always explicit). That makes the review
bar higher than for one-off custom signatures: **every signature in the
pack must be (a) valid, (b) discriminating, and (c) honestly characterised.**

## Quick start

```bash
# 1. pick the next free community id (never reuse a builtin/community id)
qshield sig id-suggest

# 2. scaffold a template
qshield sig new T2.2 --severity high --name "My Detector" --out QSig-2026-0002.yaml

# 3. edit the YAML, then validate it
qshield sig validate QSig-2026-0002.yaml

# 4. measure it against the labeled corpus — this is the acceptance gate
qshield sig test QSig-2026-0002.yaml --min-tpr 0.5 --max-fpr 0.1
```

## Quality bar

| Requirement | Gate |
|---|---|
| YAML loads, schema valid | `qshield sig validate` exits 0 |
| Unique `QSig-YYYY-NNNN` id | CI / review |
| TPR on the malicious fixture corpus | `--min-tpr` (author picks; ≥ 0.5 typical for narrow rules) |
| FPR on the clean fixture corpus | `--max-fpr` (≤ 0.10 for `low`, ≤ 0.05 for `high`+) |
| `false_positive_probability` honestly estimated | reviewer checks against `sig test` output |
| Every reference resolves (spec/URL/DOI) | review |
| Remediation advice is actionable | review |

A narrow signature with TPR 0.05 and FPR 0.00 is *welcome* — say so in
`false_positive_probability` and ship it. A broad signature with FPR 0.4 is
not, even if its TPR is 0.95.

## Example (illustrative only — not shipped)

```yaml
id: "QSig-2026-0002"
name: "Example: Long-Range Camouflage Cancellation"
version: "1.0"
author: "Your Name <you@example.org>"
date: "2026-11-12"
severity: "low"
threat_type: "T1.3"
description: Widens the builtin cancellation window (8) to 32 gates.
detection:
  method: "structural"
  structural_pattern:
    type: "gate_sequence_inverse"
    window: 32
    tolerance: 1.0e-6
references:
  - "spec://QSHIELD/2.1#T1.3"
false_positive_probability: 0.6
remediation: "Remove the cancelling pair or justify it."
```

Measure it before opening the PR — on this corpus the window-32 variant
fires on ~25% of *both* clean and malicious fixtures, so it would fail the
gate as a standalone rule. "It matches things" is not a signature; "it
separates" is.

## Workflow

1. Fork / branch, add `QSig-YYYY-NNNN.yaml` to `src/qshield/signatures/community/`.
2. Regenerate the manifest: `qshield sig manifest-build src/qshield/signatures/community --version 2026.2`.
3. Open a PR. CI runs `qshield sig validate`,  the manifest integrity check
   (`sha256` drift between manifest and files), and `qshield sig test` on
   every contributed signature. A red gate blocks merge.
4. A maintainer reproduces your `sig test` numbers on the reference corpus
   and reviews FP analysis before merge.
5. Release tags pack the directory; `qshield sig update` picks it up.

## House rules

* Signatures are **data, never code** — they are matched declaratively and
  must never require executing circuit content.
* No signatures that encode real-world secrets, personal data, or targeting
  information about specific vendors without public CVE/advisory backing.
* Every signature lists at least one reference (spec section, paper, CVE,
  or benchmarks/ artifact).
* False-positive probability is yours to estimate and defend. The reviewers
  will re-measure it.
