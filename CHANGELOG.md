# Changelog

All notable changes to QSHIELD. Historical spec annotations live in
`docs/spec/QSHIELD.md`; this file records released versions.

## [1.3.0] — Workbench security and UX

### Added
- Non-loopback Workbench binds now require the explicit `--allow-remote` flag and print a warning that the server has no built-in authentication. Docker opts in inside the container; README guidance keeps host publishing on loopback.
- Policy Studio reports when the fixture corpus is available and gives install-path guidance when it is missing.
- Finding search/severity filters and improved keyboard-accessible tab navigation.

### Changed
- Workbench responses now use a per-response CSP nonce for scripts and security headers. Compare UI wording accurately describes dense-unitary distance rather than claiming proof.
- Simplified the Workbench by removing trust-boundary and AI cloud disclosure boxes and related copy.

### Fixed
- Runtime proxy closes upstream HTTP error responses after reading them.
- Corrected the QASM3 test's regex escape warning.

## [1.2.0] — 2026-11-16 · Real-engine Pages site + CI hardening

### Added
- **CI hardening (Phase 1 of the global-scale implementation plan)** — Docker image now build-verified in CI with a non-root assertion and a bundled-fixture scan smoke (`T2.1` expected); Workbench policy fixture root is overridable via `QSHIELD_FIXTURES_DIR`; CI matrix is now Python 3.10–3.13 × Qiskit 1.4.x and 2.x; optional-extra tests (`qiskit`-backed differential tester, `pyzx` formal path) carry explicit skip reasons instead of failing in minimal environments. Docker image contains no AI features enabled and needs no network.

### Added
- **Optional Sarvam AI assistance — `qshield ai`** (`triage` / `speak` / `listen` / `report`). Cloud, opt-in only, advisory only — the offline core is untouched. `triage` sends finding *summaries* (never the raw circuit) to 105B for plain-English explanation and remediation prioritization; `speak`/`listen` use Bulbul TTS / Saaras STT (voice round-trip verified); `report` renders the short audit report in 22 Indian languages via Sarvam-Translate. Requires `pip install sarvamai` and `SARVAM_API_KEY` (.env gitignored). LLM output is a lead for human auditors, never a verdict.
- `scripts/sarvam_chat.py` — minimal API sanity check.
- **Workbench AI tab** — all three AI features in the UI (opt-in, cloud, advisory): AI Triage with live Sarvam 105B reply (finding summaries only, never raw circuit); Speak (Bulbul TTS, 9 languages) and Listen (Saaras STT, browser mic) cards; Sarvam-Translate audit reports in 22 languages shown side-by-side with the English source. Key stays server-side (never reaches the browser); `/api/ai/status|triage|speak|listen|report`. Static demo ships precomputed real outputs (ancilla fixture) and disables cloud calls honestly.

### Added
- **Golden static-scan tests** — `tests/integration/test_golden_static_scan.py` + `tests/fixtures/golden_static_scan.json` pin the exact findings (1,323 fingerprints across all 417 bundled fixtures) of the static pipeline, in emission order, excluding randomized ids/timing. Refresh deliberately with `QSHIELD_UPDATE_GOLDEN=1 pytest tests/integration/test_golden_static_scan.py` after intentional engine changes. Guards the "existing outputs unchanged" contract for the circuit IR.

### Added
- **Dependency & secret hygiene** (supply-chain hardening) — GitHub Actions pinned to full commit SHAs (dependabot keeps them fresh); `dependabot.yml` with weekly pip + github-actions updates (grouped); `requirements-dev-lock.txt`, a sorted, fully-pinned known-good dev snapshot; new CI `audit` job fails on known vulnerabilities in the runtime closure (clean as of 2026-11-14). Secret scanning and push protection were already enabled repository-wide.

### Added
- **SBOM in CI and on releases** (supply-chain hardening) — `scripts/generate_sbom.sh` builds CycloneDX 1.6 SBOMs (JSON + XML, root component `qshield`, resolved runtime deps, reproducible) in two throwaway venvs so tooling never leaks into the inventory; a CI `sbom` job uploads it as an artifact on every push; a new tag-triggered `release.yaml` creates/updates the GitHub Release for `v*` tags and attaches the SBOM + resolved requirements.

### Added
- **OpenQASM 2.0 emitter + round-trip acceptance (Phase 2.2)** — `qshield.core.qasm_emitter.emit_qasm(ir)` serializes a `CircuitIR` back to OpenQASM 2.0 source (re-exported as `qshield.core.emit_qasm` / `qshield.core.QASMEmitError`). Only unitary, gate-level content is emitted; circuits containing `reset` or classical-feedback `if` are refused loudly (`QASMEmitError`), as are non-finite parameters, invalid gate names and out-of-range qubit references — unsupported constructs never silently change semantics across a round-trip. Barriers are counted by the parser but not re-emitted (scheduling hint only, positions not retained); custom `gate` definitions are expanded inline by the parser and emitted as their flattened call sequence. Round-trip coverage: `tests/integration/test_qasm_roundtrip.py` — structural identity (names/qubits/parameters) across all 417 bundled fixtures through parse → emit → parse, per-gate unitary equality where defined, and a Qiskit-mediated semantic cross-check (357 small fixtures, matches up to global phase; custom instructions registered only for names missing from Qiskit's `qelib1.inc`, converted to Qiskit's little-endian matrix convention; native gates left to the spec-compliant importer). `tests/integration/test_unsupported_constructs.py` is a characterization battery pinning the parser's documented contract: hard failures raise `QASMParseError` (duplicate registers, caps, bad expressions, unterminated gate blocks, QASM 3 `def` blocks, recursive gate expansion), while `reset`/`if`/`barrier`/opaque gates/unrecognised statements are tolerated and flagged in IR metadata — never silently dropped.
- **GitHub Pages site now runs the real engine — not precomputed responses** — the static Workbench site (katepallewarprathmesh-sketch.github.io/QShield/) loads a pinned, self-hosted Pyodide (CPython 3.12.7, v0.27.7) runtime with the wheel built from the same repo, and serves every analysis in the visitor's tab: scan, compare (exact unitary; ZX reports UNDECIDED honestly when pyzx is absent), robustness probe, policy scoring on the bundled 417-circuit corpus (≈1 s in-browser), policies and overview. No CDN and no third-party requests at page view — runtime, wheels and the fixture corpus are vendored into the Pages artifact; nothing the visitor pastes leaves the machine. Build-time downloads are SHA256-verified against pinned hashes (packages against the pinned `pyodide-lock.json`) and the build fails closed on mismatch. AI Triage stays honest: precomputed real outputs on the ancilla fixture, always labeled — a static page cannot hold a Sarvam key; live AI is local (`qshield ui` + `SARVAM_API_KEY`). CI `pages.yml` builds and sanity-checks the site on every relevant change (PRs included, no deploy) and fast-forward-pushes to `gh-pages` on main. The old canned-response demo is gone; fixture example buttons now read the real bundled corpus.
- **Parser notes now surface on scans** — the scanner propagates IR parser warnings (e.g. `reset encountered: circuit is not unitary`, `conditional operation encountered: excluded from unitary computation`) into `ScanResults.warnings`, so scanning a non-unitary circuit no longer prints a clean verdict with no hint of what was excluded. No findings are added; the golden fingerprints are unchanged.

### Security
- **Parser hardening** (production-hardening roadmap, input-handling audit): parameter expressions are capped (≤ 2048 chars), exponents are capped (|exp| ≤ 128 — kills the `rz(2**10**10)` hang), oversized numeric literals rejected, math-domain/arity errors surface as `ExpressionError`, and deeply-nested expressions/null bytes can no longer escape as raw tracebacks. The QASM parser now enforces source size (1 MiB), register width (512 qubits / 1024 classical bits), total emitted gates (100 000), custom-gate expansion depth (16) and a 10 s parse budget — violations raise `QASMParseError`, never a hang or silent truncation. The only public failure mode of `parse_qasm` is now `QASMParseError`. Per-statement line lookup is O(log n) (was O(n²) on statement-heavy files). Found + fixed via property-based fuzzing (hypothesis) — including a latent crash on `sqrt()` with zero arguments. New: 19 fuzz/robustness tests (`tests/security/test_parser_fuzz.py`, `test_parser_robustness.py`).

## [1.1.1] — 2026-11-13 · Supply-chain framing + static demo + Docker

### Added
- **Dockerfile** + `.dockerignore` — slim non-root image; `docker build -t qshield . && docker run -p 8765:8765 qshield`. Includes `tests/fixtures` so Policy Studio works in-container.
- **Static Workbench demo** on GitHub Pages (`katepallewarprathmesh-sketch.github.io/QShield/`) — same UI, browser-only; responses are precomputed outputs of the real engine on the bundled fixtures, honestly labeled as such. Reproducible via `scripts/build_static_site.py`.
- GitHub repo description/topics now lead with the supply-chain positioning (`supply-chain-security`, `software-supply-chain`, `trojan-detection`).

### Changed
- **Supply-chain framing everywhere user-facing**: Workbench `<title>`/header, VS Code extension display name, GitHub description, static demo.
- **README rewritten** — abstraction pass: internals hidden, only the required surface (what/why/install/quickstart/limits) shown; stale test count refreshed (468).
- Publish process: normal pushes only (no history rewrites).

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
