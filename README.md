# 🛡 QSHIELD — Quantum Software Supply Chain Security Framework

> New here? Read [docs/WHAT_IS_QSHIELD.md](docs/WHAT_IS_QSHIELD.md) — a one-page
> plain-English explainer (what it does, what it honestly doesn't, verified commands).

> Detect, analyze and prevent security vulnerabilities in **quantum software supply chains**:
> backdoor gates, trojan unitaries, covert channels and malicious circuit modifications in
> quantum programs, libraries and cloud services.

> **v2.0 — SOFTWARE-ONLY, by design and forever.** No QPU, no device SDK, no cloud account,
> no hardware in any acceptance criterion — detection, verification and scoring all run
> offline on files. Publication is out of scope. See
> [docs/PRODUCT_V2.md](docs/PRODUCT_V2.md). The UI surface is the **QSHIELD Workbench**
> (`qshield ui`) — offline, local, stdlib-only.

**Status: v1.1.0 — software-only workbench pivot.** All detection runs offline; no hardware, network or account is ever required, now and by design permanently. M4.2 (real-hardware validation) and the publication roadmap are **superseded** — see the v2.0 scope amendment in [docs/spec/QSHIELD.md](docs/spec/QSHIELD.md) and [docs/PRODUCT_V2.md](docs/PRODUCT_V2.md). QSHIELD parses OpenQASM 2.0/3.0 and Qiskit/Cirq/PennyLane circuits into a framework-agnostic IR, runs structural static analysis, exact unitary/density-matrix verification, ZX-calculus equivalence checking, sandboxed differential testing, quantum supply-chain audits, an intercepting runtime monitor, and emits CI-ready reports (SARIF / JSON / HTML). Measured: 468 tests (local run), 1000-qubit static scan ≈ 2 s, runtime overhead p95 ≈ 1.5 ms — simulator/fixture-corpus numbers, not field rates. New in v1.1.0: **QSHIELD Workbench UI**, **Policy Studio** (policy-as-code scored on the bundled 417-circuit corpus) and the **Robustness Probe** (do your findings survive semantics-preserving camouflage?).

```
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 1 · STATIC          │ LAYER 2 · DYNAMIC      │ LAYER 3    │
│ structural analyzer        │ sandbox simulator      │ runtime    │
│ unitary verifier           │ differential testing   │ monitor    │
│ dependency scanner         │ statistical tests      │ (shipped)  │
│ formal ZX check (pyzx)     │                        │            │
└──────────────┬─────────────┴───────────┬────────────┴────────────┘
               │     LAYER 4 · REPORTING & POLICY                  │
               │ SARIF · JSON · HTML · CI gate (GitHub Actions)   │
               └────────────────────────────────────────────────────┘
```

## Workbench (UI)

```bash
pip install -e .
qshield ui                 # http://127.0.0.1:8765 — offline, local, no telemetry
```

Tabbed console: **Overview** (corpus + measured headline numbers) · **Scan** (paste/load a
`.qasm`, get severity-ranked findings with gate indices) · **Compare** (exact-unitary or
ZX equivalence of two circuits) · **Robustness Probe** (novel — re-scans your flagged
circuit under five semantics-preserving camouflage transforms; shows per-finding
survived/fragile/evaded verdicts) · **Policy Studio** (novel — your own lint-style
security policies as reviewable specs, scored live on the bundled 417-circuit fixture
corpus with TPR/FPR per policy) · **About & limits**.

Every analysis path is offline: no hardware, no cloud, no accounts, no network calls.

## Why

Everyone is busy with post-quantum cryptography (PQC) — security for *classical* data against
quantum attacks. Almost nobody is securing **quantum software itself**. Classical SAST/DAST/SCA
tools cannot analyze quantum circuits: gates are unitary matrices, states can't be copied for
inspection, and measurement is destructive. QSHIELD is purpose-built for this territory
(see the threat taxonomy T1–T4 / attacker models A1–A4 in the spec).

## Install

```bash
pip install -e .                       # core (OpenQASM parser, static analysis, CLI)
pip install -e '.[qiskit,cirq]'        # + framework parsers (qiskit-aer used by --full)
pip install -e '.[formal]'             # + ZX-calculus verification (PyZX, Z3)
pip install -e '.[dev]'                # + test/lint tooling
```

Requires Python ≥ 3.10.

## Quickstart

### Documentation

* [Developer guide](docs/developer_guide/contributing.md)
* [Quickstart](docs/user_guide/quickstart.md)
* [Configuration](docs/user_guide/configuration.md)
* [CI/CD integration](docs/user_guide/ci_cd_integration.md)
* [Custom signatures](docs/user_guide/custom_signatures.md)
* [Threat taxonomy paper](docs/research/threat_taxonomy_paper.md)
* [Detection methods paper](docs/research/detection_methods_paper.md)
* [Full specification](docs/spec/QSHIELD.md)

### CLI

```bash
qshield scan circuit.qasm                       # scan (text report)
qshield scan circuit.qasm --fail-on high        # CI gate: exit 1 on high+ findings
qshield scan . --recursive --format sarif -o out.sarif   # GitHub Security tab
qshield scan circuit.qasm --full                # + differential simulation testing
qshield scan circuit.qasm --format pdf -o report.pdf  # PDF report (needs: pip install weasyprint)
qshield compare original.qasm suspicious.qasm --formal   # ZX-calculus equivalence proof
qshield compare original.qasm suspicious.qasm             # randomized check at scale (~20 qubits)
qshield verify circuit.qasm --expected-unitary u.npy     # matrix check (≤12 qubits)
qshield audit-deps --requirements requirements.txt       # quantum supply-chain audit
qshield db search ancilla                       # query builtin signatures
qshield init-config                             # write .qshield.yaml template
qshield sig status                              # show installed community signature pack
qshield sig update --offline                    # install bundled signature pack (no network)
qshield sig test my_sig.yaml --min-tpr 0.8      # gate a signature against the fixture corpus
```

### Python API

```python
import qshield

results = qshield.scan("circuit.qasm")          # quick static scan
print(results.is_clean, results.summary.total)

scanner = qshield.Scanner(config="strict")      # or "default" | "permissive" | path/to/.qshield.yaml
scanner.add_circuit(my_qiskit_circuit)          # QuantumCircuit / cirq.Circuit / qml tape / QASM text
scanner.add_package("qiskit-nature", version="0.7.0")
results = scanner.run(dynamic_shots=10_000)
print(results.to_json(), results.to_sarif(), results.to_html())

# round-trip Qiskit -> CircuitIR -> Qiskit (semantics preserved exactly):
from qshield.core.parsers.framework_parsers import parse_qiskit
from qshield.core.exporters import to_qiskit

ir = parse_qiskit(my_qiskit_circuit)   # qshield CircuitIR
exported = to_qiskit(ir)               # back to QuantumCircuit; same unitary
```

## What it detects (Phase 1)

| Spec threat | Example | Detection | Verdict |
|---|---|---|---|
| T1.1 Parameter perturbation | `rz(π/4 + 0.001)` | exact unitary compare vs expected (`verify`, `expected_unitary=`), distributed micro-rotation spread analysis | catches cumulative drift |
| T1.3 Extra gate injection / obfuscation | `cx … cx` cancelling pairs, gate-count anomalies | structural analysis + signature matching | immediate |
| T2.1 Ancilla information leakage | ancilla copying input before mixing | exact partial-trace independence test (≤8 qubits) | deterministic |
| T2.2 Parameter-encoded payloads | angles = bytes on a π/4096 grid | grid-alignment + ASCII-run signature | deterministic |
| T2.3 Measurement basis manipulation | `h` right before `measure` | structural + signature | immediate |
| T3.1 Package tampering | typosquatting, pinned-vulnerable versions, direct-URL installs | embedded advisory DB + similarity scan | immediate |
| T3.2/T3.3 Compromised compiler/backend | pre/post-compile or cross-backend divergence | ZX-calculus equivalence (`compare --formal`), randomized equivalence to ~20 qubits (`compare`, polynomial identity testing), differential Aer-vs-numpy distribution test | statistical/exact |

Confidence scores and false-positive probabilities are attached to every finding; the built-in
corpus evaluates to **215/215 attacks detected, 0/202 clean-circuit false positives** (synthetic
Phase-1 corpus of 417 circuits — see `benchmarks/evaluate.py` and `benchmarks/generate_corpus.py`;
real-world calibration is Phase 2+ work).

## Project layout

```
src/qshield/
├── core/            # CircuitIR, gate database (101 gates, unitaries), QASM parser, config, framework adapters + exporters
├── static/          # structural analyzer, unitary/density-matrix verifier, dependency scanner
├── dynamic/         # sandboxed NumPy simulator, statistical tests, Aer differential tester
├── formal/          # ZX-calculus equivalence checker (PyZX), property-verification hooks
├── signatures/      # YAML threat signatures ("YARA for quantum"), builtin QSig-2024-0001..0005, community pack (manifest+sha256, opt-in), `qshield sig` toolchain
├── reporting/       # Finding model, SARIF / JSON / HTML exporters
├── runtime/         # API interceptor proxy, circuit-in-transit integrity, result validation, real-time alerting
├── cli/             # typer CLI (scan, compare, verify, audit-deps, db, init-config, runtime)
└── scanner.py       # public API: qshield.Scanner / qshield.scan / ScanResults
tests/               # 447 unit+integration+security benchmark tests (95% coverage)
benchmarks/          # evaluate.py — Phase-1 detection-rate report; hardware_validation.py — M4.2 device noise-twin calibration
examples/            # quickstart for each supported framework
ci-templates/        # GitLab CI template (include + extends .qshield_scan)
editors/vscode/      # VS Code extension (source build; inline diagnostics)
notebooks/           # qshield_audit.ipynb — executed, committed with outputs
```

## Development

```bash
pip install -e '.[dev,qiskit,cirq,formal]'
python -m pytest tests                 # run the suite
python benchmarks/evaluate_ml.py       # ML CV benchmark (needs qshield[ml])
python benchmarks/evasion_evaluate.py --skip-static   # red/blue evasion benchmark
python benchmarks/evaluate.py          # detection-rate table
ruff check src tests benchmarks         # lint (clean)
mypy src                               # type-check (clean)
```

## Roadmap (from the spec)

* **Phase 1 (done):** CircuitIR, QASM parser (100-qubit circuits verified), Qiskit round-trip export (`to_qiskit`, semantics-preserving — acceptance criterion met), gate database with 101 standard gates, structural analyzer, unitary verifier, randomized equivalence (~20 qubits), CLI, SARIF/JSON/HTML/PDF, benchmark suite (202 clean + 215 malicious, TPR 100% / FPR 0%), paper 1 — threat taxonomy ([docs/research/threat_taxonomy_paper.md](docs/research/threat_taxonomy_paper.md)).
* Exact/dynamic equivalence has hardware limits: random testing catches large deviations but not angles of ≲1e-3 rad; use `--formal` or dense verification when feasible.
* **Phase 2 (done):** sandboxed execution with measurement interception (Born-rule collapse logging, ancilla density snapshots with purity, wall-clock limits), noise-aware differential tester (homogeneity chi²; measured TPR 0.958 @ δ≥0.1 rigging, FPR 0.025 ideal, 0.008 across depolarizing+amplitude-damping Aer twins), mutation fuzzer with coverage-guided corpus minimization (camouflage evasion 0.736 → 0.000 after effective-usage analyzer hardening), OpenQASM 3.0 subset parser, paper 2 — detection methods ([docs/research/detection_methods_paper.md](docs/research/detection_methods_paper.md)).
* **Phase 3 (done):** ZX-calculus equivalence engine (proven-equivalence reductions for Clifford fragments; 100/150-qubit identical and camouflaged pairs verified in <0.31s; exact tensor fallback capped at 10 qubits, 'undecidable' beyond that — never a false verdict, never an OOM; `qshield compare --formal`), ML anomaly detection ([benchmarks/evaluate_ml.py](benchmarks/evaluate_ml.py); GNN autoencoder trained on clean only — TPR 0.58 / FPR 0.07, plus a supervised GNN classifier — TPR 0.991 / FPR 0.079 / AUROC 0.978, nested-calibration 5-fold CV; LOO saliency explainability; `pip install 'qshield[ml]'`).
* **Phase 3 (M3.3 done):** evasion-resistance suite — 5 semantics-preserving attack classes (camouflage, synonym rewrites, rotation splitting, identity dead-code, qubit relabeling), adversarial-training hardening lifts the GNN's overall resistance from 0.732 to 0.828 (acceptance ≥ 0.80 met), with attacked-clean FPR ≤ 0.059 ([analysis](docs/research/evasion_analysis.md), [benchmark](benchmarks/evasion_results.json)).
* **Phase 3 (M3.4 done):** community signature ecosystem — signed-by-sha256 community pack (empty by design: two candidate signatures measured on the fixture corpus both scored TPR≈FPR and were rejected; see `src/qshield/signatures/community/CONTRIBUTING.md`), `qshield sig` toolchain (id-suggest / new / validate / test with TPR/FPR gates / update / rollback / status / manifest-build), sha256-verified update with `.bak` rollback and offline install (`sig update --offline`), opt-in via `use_community: true` (spec default config: false).
* **Phase 3 (M3.5 done):** third paper — *Formal Verification of Quantum Circuit Integrity via ZX-Calculus* ([docs/research/formal_verification_paper.md](docs/research/formal_verification_paper.md)): soundness theorems for the verdict contract (no unsound verdicts), a coQMA-completeness limit for general circuit integrity with a Rice-style corollary for extensional trojan properties, fragment-by-fragment decidability, measured 20–150-qubit Clifford proofs (≤ 0.284 s) with adversarial camouflage invariance and honest undecidability elsewhere.
* **Phase 4 (M4.1 done):** runtime monitor — `qshield runtime proxy` intercepts quantum-cloud API traffic (QASM extraction, commitment check via `X-QShield-Expected-Hash`, static scan, ideal-Born result validation with `X-QShield-Result` match/mismatch/unavailable, real-time alerts to stderr/JSONL/webhook); `qshield runtime check` verifies a circuit offline. Acceptance met: <100 ms/call overhead — measured p95 ≈ 1.6 ms (POST) / ≈ 1.1 ms (GET) against a synthetic upstream; 468 tests local. Honest limits: commitment is byte-exact identity (equivalence needs `compare --formal`); ideal-Born validation is goodness-of-fit, not attack detection vs rigged-ideal backends.
* **Phase 4 (M4.2 partial — twins only):** noise-aware calibration measured on **synthetic device twins** (ibm/ionq/rigetti-like depolarizing+readout models via Aer; density-matrix exact reference): ideal-Born result validation false-alarms on honest noisy hardware (FPR→1.0 at ≥4k shots — drift, not attack); twin-Born validation is calibrated (FPR ≈ α; ≤5% at α=0.01–0.05 on all three twins) and detects δ≥0.05 rigging at TPR=1.0 ([benchmark](benchmarks/hardware_validation.py), [results](benchmarks/hardware_validation_results.json), [case study](docs/case_studies/quantum_cloud_audit.md)). **NOT validated on real IBM/IonQ/Rigetti hardware** — no credentials exist; acceptance criterion remains unmet. Also fixed a latent big-endian counts-key reversal in the Aer benchmark adapters (sample-vs-sample B2 FPR and committed metrics unchanged).
* **Phase 4 (M4.3 done, source builds):** CI/CD integrations — composite GitHub Action (`.github/actions/qshield-scan`, verified locally: detects fixture, exits 1 at `fail-on: high`, emits valid SARIF/JSON), GitLab CI template (`ci-templates/gitlab/qshield-scan.yml`, SARIF/JSON as artifacts), VS Code extension (`editors/vscode/qshield`, inline diagnostics on save; not Marketplace-listed), executed Jupyter audit notebook (`notebooks/qshield_audit.ipynb`). Docs: [docs/integrations/ci-cd.md](docs/integrations/ci-cd.md). Nothing is published to a marketplace — all integrations are source builds with explicit manual install steps.
* **Phase 4 (M4.4 done — v1.0.0):** production hardening — 1000-qubit static analysis ≈ 1.5 s / ~75 MB peak (acceptance <300 s met; [benchmark](benchmarks/large_circuit.py)), SVD/cancellation caching, comprehensive docs ([limitations](docs/limitations.md), [runtime monitor](docs/user_guide/runtime_monitor.md), [security self-audit](docs/security/self_audit.md) — ruff-S clean, pip-audit clean), v1.0.0 tagged locally with [CHANGELOG](CHANGELOG.md). **Not published to PyPI/markets (no credentials).**
* **Phase 4 (M4.5 done):** fourth paper — *Securing Quantum Cloud Services: Runtime Monitoring and Result Verification* ([paper](docs/research/runtime_cloud_security_paper.md)); thesis-by-publication compilation ([docs/thesis/qshield_thesis.md](docs/thesis/qshield_thesis.md), ~13.9k words, rebuilt via `docs/thesis/compile_thesis.py`) — a compilation draft, not an examination-ready thesis.
* **Phase 4 (remaining):** real-hardware M4.2 runs (needs device access); post-1.0: release provenance, community pack signatures.

## License

Apache 2.0 — see [LICENSE](LICENSE). The threat taxonomy and specification are part of an
ongoing PhD research programme; contributions (signatures, analyzers, corpus circuits) are welcome.
