# Changelog

All notable changes to QSHIELD. Historical spec annotations live in
`docs/spec/QSHIELD.md`; this file records released versions.

## [1.1.0] — 2026-11-12 · Workbench pivot (software-only)

**Scope change (breaking for claims):** QSHIELD is now explicitly and permanently software-only. No QPU, no device SDK, no hardware in any acceptance criterion — M4.2 (real-hardware validation) is superseded; the publication roadmap is out of scope. Detection/verification/scoring all run offline. See `docs/PRODUCT_V2.md` and the v2.0 amendment atop `docs/spec/QSHIELD.md`.

### Added
- **QSHIELD Workbench** (`qshield ui`, `src/qshield/ui/`) — offline, local, stdlib-only web UI: Overview dashboard (corpus + measured headline numbers), Scan (paste/load `.qasm` → severity-ranked findings with gate indices), Compare (exact-unitary ≤12 qubits, or ZX-calculus for decidable fragments → EQUIVALENT/DIFFERENT/UNDECIDED), About & limits page. Zero network calls; 127.0.0.1 default bind; 8 MiB body cap; content never executed.
- **Policy Studio** (`src/qshield/policy.py`, novel) — policy-as-code for circuits: six builtin heuristic hygiene policies (opaque-rotation ban, measurement fan-out ceiling, depth/width ceilings, two-qubit-density ceiling, Toffoli ban) with strict spec validation, plus live TPR/FPR scoring on the bundled 417-circuit fixture corpus (202 clean / 215 malicious). Fixture-corpus rates — not field rates.
- **Robustness Probe** (`src/qshield/redteam.py`, novel) — after a flag, re-scans the circuit under five semantics-preserving camouflage transforms (camouflage, synonyms, rotation_split, dead_code, qubit_relabel) × k seeded variants; reports per-finding survived/fragile/evaded with per-attack breakdown. Evidence stability — not a proof of safety.
- CLI: `qshield ui [--host] [--port]`.
- Tests: 21 new (policy engine, probe, HTTP endpoints incl. 400/404 paths). New suite total 468 passed / 1 skipped locally (two environment-dependency failures only: qiskit-Aer and pyzx absent in this sandbox; CI green covers them).

### Changed
- Version 1.0.0 → 1.1.0. README gains the v2.0 software-only banner, Workbench quickstart and corrected status; stale "Phase 1 vertical slice" already fixed in 648e166.
- Spec gains the v2.0 scope amendment (CRLF round-trip preserved); M4.2 and publication milestones remain in the document as historical record, explicitly superseded.

### Honest limits (unchanged)
- Fixture-corpus metrics, not field rates; twin-calibrated dynamic results are simulator-measured; findings are evidence, not proofs; community pack ships zero signatures by design.

## [1.0.0] — 2026-11-12

First production release. Phases 1–4 of the roadmap are implemented; see the
spec for per-milestone acceptance evidence and honest limits.

### Phase 1 — Foundation (static detection)
- CircuitIR + parser (OpenQASM 2.0), 101-gate database with unitaries.
- Structural analyzer battery (entanglement anomaly, dead qubits, gate
  cancellation, leaf-ancilla), unitary/density-matrix verifier, dependency
  auditor (`qshield audit-deps`, typosquatting + advisories), signature
  engine ("YARA for quantum": QSig-2024-0001..0005), SARIF/JSON/HTML/PDF
  reporting, `qshield scan/compare/verify/audit-deps/audit-package/db/init-config`.
- Phase-1 measured: corpus TPR 215/215, FPR 0/202 (static heuristics,
  fixtures); 100-qubit static scan.

### Phase 2 — Dynamic & noise-aware detection
- Sandboxed NumPy executor (born-rule collapse logging, ancilla density
  snapshots + purity, qubit/gate/wall-clock caps), Aer differential tester
  (homogeneity chi²; **TPR 0.958 @ δ≥0.1, FPR 0.025 ideal, 0.008 across
  depolarizing+amplitude-damping Aer twins** — B2 twin-vs-twin), mutation
  fuzzer (camouflage evasion 0.736 → 0.000 after effective-usage hardening),
  OpenQASM 3.0 subset parser, paper 2.

### Phase 3 — Formal & ML
- PyZX ZX-calculus equivalence verdict contract (sound verdicts only;
  100–150-qubit Clifford proofs ≤0.284 s; measured & documented undecidable
  beyond fragments) + paper 3, `qshield compare --formal`.
- ML anomaly detection: GNN autoencoder (TPR 0.58 / FPR 0.07) and supervised
  GNN classifier (TPR 0.991 / FPR 0.079 / AUROC 0.978, 5-fold nested CV).
- Evasion-resistance suite: camouflage/synonym/rotation-split/identity-pair/
  relabel attacks; adversarial training lifts overall resistance 0.732 →
  0.828 (FPR attacked-clean ≤ 0.059).
- Community signature ecosystem: empty-by-design pack + sha256-verified
  update (integrity only, opt-in, never silent), `qshield sig` toolchain.

### Phase 4 — Runtime & cloud security
- **M4.1 runtime monitor** (`qshield runtime proxy|check`): API interceptor
  reverse proxy, in-transit commitment (`X-QShield-Expected-Hash`,
  byte-exact identity), static scan reuse, exact ideal-Born result
  validation (deferred-measurement; MSB/LSB auto-order), `X-QShield-Result`
  match|mismatch|unavailable|unvalidated, real-time alerts (stderr/JSONL/
  webhook, best-effort isolation). Acceptance met: **<100 ms/call — p95
  ≈1.6 ms POST / ≈1.1 ms GET** (`benchmarks/runtime_latency.py`).
- **M4.2 noise-aware calibration — synthetic twins only**: ideal-Born
  validation false-alarms on honest noisy twins (FPR→1.0 @ ≥4k shots);
  noise-model-referenced chi² validation calibrated (FPR ≤5% @ α≤0.05,
  TPR=1.000 @ δ≥0.05 rigging, all three twins). **NOT validated on real
  IBM/IonQ/Rigetti hardware (no credentials) — acceptance unmet on
  hardware.** See `docs/case_studies/quantum_cloud_audit.md`.
- **M4.3 CI/CD integrations (source builds)**: composite GitHub Action,
  GitLab CI template, VS Code extension (inline diagnostics), executed
  Jupyter audit notebook. Nothing published.
- **M4.4 production hardening**: 1000-qubit static analysis ≈ **1.5–2 s /
  ~75 MB** (acceptance: 300 s) — `benchmarks/large_circuit.py`; lazy SVD
  and gate-cancellation caching; comprehensive docs (user guide,
  runtime monitor, CI/CD, limitations, security self-audit);
  `pip-audit --local` clean.
- **M4.5 thesis & fourth paper**: paper 4 — *Securing Quantum Cloud
  Services: Runtime Monitoring and Result Verification*
  (`docs/research/runtime_cloud_security_paper.md`): architecture,
  commitment semantics, deferred-measurement Born verification, measured
  <100 ms/call overhead and noise-twin false-alarm economics (ideal-Born
  FPR→≈1.0 on honest noisy twins; noise-model-referenced χ² calibrated,
  TPR=1.000 @ δ≥0.05). Thesis-by-publication compilation
  (`docs/thesis/qshield_thesis.md`, ~13.9k words, rebuilt by
  `docs/thesis/compile_thesis.py`) — a compilation draft, not
  examination-ready.

### Known limits (v1.0.0)
- No real quantum hardware validation (M4.2); hardware runs are documented
  and scaffolded but unexecuted.
- Ideal-Born validation is goodness-of-fit, not device authentication;
  `mismatch` = drift-or-attack, never auto-block.
- Community pack ships zero signatures by design; pack integrity ≠
  publisher authentication.
- No SLSA/provenance attestation for releases yet (post-1.0).
- Not on PyPI / any marketplace; install from source.

### Verification
- Suite: **447 passed, 1 skipped** (2026-11-12, qshield[all extras]); 95%
  coverage; ruff + mypy clean; CI matrix py3.10–3.13.
