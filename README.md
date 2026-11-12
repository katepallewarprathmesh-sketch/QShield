# 🛡 QSHIELD — Quantum Software Supply Chain Security Framework

> Detect, analyze and prevent security vulnerabilities in **quantum software supply chains**:
> backdoor gates, trojan unitaries, covert channels and malicious circuit modifications in
> quantum programs, libraries and cloud services.

**Status: Phase 1 (Foundation) — working vertical slice.** QSHIELD parses OpenQASM 2.0
and Qiskit/Cirq/PennyLane circuits into a framework-agnostic IR, runs structural static
analysis, exact unitary/density-matrix verification, ZX-calculus equivalence checking,
differential simulation testing, quantum supply-chain audits, and emits CI-ready reports
(SARIF / JSON / HTML). See [docs/spec/QSHIELD.md](docs/spec/QSHIELD.md) for the full
specification-driven roadmap (4 phases, 2024–2029 research plan).

```
┌─────────────────────────────────────────────────────────────────┐
│ LAYER 1 · STATIC          │ LAYER 2 · DYNAMIC      │ LAYER 3    │
│ structural analyzer        │ sandbox simulator      │ runtime    │
│ unitary verifier           │ differential testing   │ monitor    │
│ dependency scanner         │ statistical tests      │ (roadmap)  │
│ formal ZX check (pyzx)     │                        │            │
└──────────────┬─────────────┴───────────┬────────────┴────────────┘
               │     LAYER 4 · REPORTING & POLICY                  │
               │ SARIF · JSON · HTML · CI gate (GitHub Actions)   │
               └────────────────────────────────────────────────────┘
```

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
├── cli/             # typer CLI (scan, compare, verify, audit-deps, db, init-config)
└── scanner.py       # public API: qshield.Scanner / qshield.scan / ScanResults
tests/               # 389 unit+integration+security benchmark tests (95% coverage)
benchmarks/          # evaluate.py — Phase-1 detection-rate report
examples/            # quickstart for each supported framework
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
* **Phase 4:** cloud runtime monitor (API proxy, result validation), hardware validation, CI/CD marketplace integration, v1.0.

## License

Apache 2.0 — see [LICENSE](LICENSE). The threat taxonomy and specification are part of an
ongoing PhD research programme; contributions (signatures, analyzers, corpus circuits) are welcome.
