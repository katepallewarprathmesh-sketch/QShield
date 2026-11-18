# Security Policy

QSHIELD is a supply-chain security tool for quantum circuits. We take
vulnerabilities in it seriously — but please read the honesty note below
before reporting: **most "it missed my circuit" reports are detection-quality
issues, not security vulnerabilities**, and are best filed as regular issues.

## Reporting a vulnerability

**Preferred: GitHub private vulnerability reporting**
<https://github.com/katepallewarprathmesh-sketch/QShield/security/advisories/new>
(this repository has private reporting enabled; no email address is published)

If that page is unavailable, open a **minimal** public issue asking a
maintainer to open a private channel — do not include exploit detail,
proof-of-concept payloads, or circuit IP in it.

### What to include

- QSHIELD version and install method (source build, Docker image, Action)
- Affected component (parser / scanner / CLI / Workbench server / signature pack / CI Action)
- Minimal reproduction (a small `.qasm` snippet is usually enough)
- Your assessment of impact — hang/crash (DoS), wrong-trust decisions,
  signature-pack verification bypass, key/IP exposure, etc.

### What we commit to

- We will **not** pursue legal action against good-faith security research
  that respects this policy.
- Best-effort targets (not SLAs): acknowledgement **≤ 72 h**; initial
  triage **≤ 7 days**; a coordinated-disclosure default of **90 days** from
  acknowledgement, adjusted by mutual agreement for severe cases.
- Credit in the release notes / advisory, if you want it. There is **no bug
  bounty** and none is planned.

## Supported versions

| Version | Supported |
|---|---|
| 1.5.x (latest release line) | ✅ supported; security fixes land here |
| 1.4.x | ✅ supported; upgrade to 1.5.x for the latest fixes |
| `main` (untagged) | ⚠️ fixes may land here; no release/support guarantees |
| < 1.4.0 | ❌ unsupported; upgrade before reporting a version-specific issue |

## Scope

**In scope**

- Parser(s) and expression evaluator: crashes, hangs, memory exhaustion,
  or language-level injection triggered by crafted circuit files.
- Scanner / detectors: crashes, or crafted input that produces trusted
  signatures/verification results that are not what was claimed.
- Signature-pack verification: bypasses of the integrity checks at load.
- Workbench server (`qshield ui`): request handling, body limits, fixture
  access, the optional cloud-AI endpoints (key handling, request routing).
- The bundled Docker image and CI Action: misconfigurations that silently
  weaken the security gates (e.g., a failing scan that exits 0).

**Out of scope**

- Detection quality — false positives/negatives on the fixture corpora or in
  the field (these are openly tracked as limitations; file a regular issue
  with the corpus/circuit).
- Vulnerabilities in **third-party dependencies** — please report upstream;
  we will bump pinned versions promptly. The optional `sarvamai` cloud path
  sends finding *summaries* to Sarvam — Sarvam's own service is out of scope
  here; QSHIELD key handling is in scope.
- Findings that require attacker control of your own machine, CI secrets, or
  repository settings.
- "QSHIELD didn't prove my circuit safe" — it never claims that; findings
  are evidence of known tampering classes, not proofs.

## Handling your report

We keep reports private while coordinating a fix, publish an advisory when
the fix ships, and never share reporter details without consent.

---

*This policy is versioned with the repository and reflects the v1.5.0 supported-version policy.*
