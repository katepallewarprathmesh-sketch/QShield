# QSHIELD — Limitations and honest scope

QSHIELD finds *evidence of known tampering classes*. It is not a proof of
anything stronger. This page consolidates every limitation stated elsewhere.

## What QSHIELD is not

- **Not a guarantee of device honesty** — a clean scan means no known
  attack pattern matched; it does not certify a backend.
- **Not equivalence checking** — the integrity commitment
  (`X-QShield-Expected-Hash`) is byte-exact identity. Semantic equivalence
  is `compare --formal` (PyZX), complete only for Clifford fragments;
  beyond that: exponential or undecidable.
- **Not a side-channel defense** — no timing/power analysis.
- **Not a noise-vs-attack arbiter** — on noisy hardware, ideal-Born
  validation reports `mismatch` for honest drift; treat `mismatch` as an
  anomaly to investigate, never an automatic block.

## Detection limits (measured)

- Static heuristics: fixture corpus TPR/FPR as reported in README phase
  sections; T1.1 signature heuristic is 0.60-confidence by design.
- Differential tester: TPR 0.958 at rigging δ≥0.1; FPR 0.025 ideal, 0.008
  across Aer twins (sample-vs-sample B2) — M2.2.
- ML GNN: TPR 0.991 / FPR 0.079 supervised (AUROC 0.978, 5-fold nested
  CV); autoencoder TPR 0.58 / FPR 0.07 — informational, not a gate.
- Signature pack ships **zero** community signatures (two candidates
  failed discrimination on fixtures and were rejected).

## Scale caps (hard limits)

- Sandboxed execution: ≤ 12 qubits, measured branching is projective.
- Exact unitary: ≤ MAX_EXACT_QUBITS (small); density-matrix ancilla
  snapshots capped at 8 ancillas.
- QASM parsing/scanning: hard caps — 1 MiB source, 512 qubits per circuit, 100 000 emitted gates, 16-level gate-expansion depth, 10 s parse budget (excess work is rejected loudly, not performed). Static analysis beyond that is not supported.
- Parameter expressions: ≤ 2048 chars, |exponent| ≤ 128.
- Ideal Born predictions (runtime result validation): ≤ 12 qubits, no
  classically-conditional gates, no resets; else `unavailable`.
- `X-QShield-Result: unvalidated` when no pending prediction exists
  (job never seen by the proxy / result arrived standalone).

## Process limits

- No telemetry, no phone-home; all checks local.
- Community pack is sha256 **integrity only, not publisher
  authentication**; opt-in (`use_community: false` default); installing
  always explicit.
- Nothing published: no PyPI, no GitHub Marketplace, no VS Code
  Marketplace, no Zenodo — all artifacts are source builds.
- Real quantum hardware: none was used in this project (no credentials);
  M4.2 acceptance is unmet on hardware and measured only on synthetic
  noise twins.
- Reports embed circuit IP metadata — handle accordingly.
