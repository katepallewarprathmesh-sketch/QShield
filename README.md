# 🛡 QSHIELD — Quantum Software Supply Chain Security Framework

**Offline security checks for quantum circuits and the software that ships them** — catch backdoor gates, trojan unitaries and tampered dependencies in OpenQASM circuits before they reach a run.

> **v2.0 — software-only, by design and forever.** No QPU, no device SDK, no cloud account,
> no hardware in any acceptance criterion. Detection, verification and scoring all run
> offline on files. See the live interactive demo at `katepallewarprathmesh-sketch.github.io/QShield/`.

## What it does

| Command / surface | What it gives you |
|---|---|
| `qshield scan` | Severity-ranked findings for a circuit (structural analysis + builtin threat signatures); `--fail-on high` as a CI gate |
| `qshield compare` | Equivalence of two circuits — exact ZX-calculus proof or randomized identity testing |
| `qshield verify` | Unitary check of a circuit against an expected matrix (≤12 qubits) |
| `qshield audit-deps` | Quantum supply-chain audit of a `requirements.txt` (typosquatting, vulnerable pins) |
| `qshield sig` | Manage the built-in threat signature pack (offline, sha256-verified) |
| `qshield ui` | **Workbench** — local web UI: scan, compare, Policy Studio (score policies against the fixture corpus when available), Robustness Probe (does a finding survive semantics-preserving camouflage?) |
| Reports | SARIF (GitHub Security tab) · JSON · HTML · PDF |

Everything runs offline: no hardware, no cloud, no accounts, no network calls.

## Why

Everyone is busy with post-quantum cryptography (PQC) — security for *classical* data against
quantum attacks. Almost nobody is securing **quantum software itself**. Classical SAST/DAST/SCA
tools cannot analyze quantum circuits: gates are unitary matrices, states can't be copied for
inspection, and measurement is destructive. QSHIELD is purpose-built for this territory.

## Install

```bash
pip install qshield                     # core (OpenQASM parser, static analysis, CLI)
pip install 'qshield[qiskit,cirq]'     # + framework parsers (qiskit-aer used by --full)
pip install 'qshield[braket]'           # + Amazon Braket Circuit parser
pip install 'qshield[formal]'          # + ZX-calculus verification (PyZX, Z3)
```

Docker: `docker pull ghcr.io/katepallewarprathmesh-sketch/qshield:1.3.0` (or build from source: `docker build -t qshield .`). Run it with `docker run --rm -p 127.0.0.1:8765:8765 qshield` to keep the unauthenticated Workbench available only on host loopback. The container binds internally with an explicit non-loopback opt-in; keep the host port mapping on loopback. Do not publish the Workbench beyond localhost without network restrictions and an authenticated TLS proxy. For source installs, a non-loopback bind requires `qshield ui --host 0.0.0.0 --allow-remote` and prints a security warning.

From source: `git clone https://github.com/katepallewarprathmesh-sketch/QShield.git && cd QShield && pip install -e '.[dev]'`

Requires Python ≥ 3.10.

The Workbench's Policy Studio requires the fixture corpus, which is available in a source
checkout and the Docker image but is not included in the PyPI wheel. For a wheel install,
point `QSHIELD_FIXTURES_DIR` at a directory containing `clean_circuits/` and
`malicious_circuits/` to enable corpus scoring; scan and compare work without it.

## Quickstart

```bash
qshield scan circuit.qasm                       # scan (text report)
qshield scan circuit.qasm --fail-on high        # CI gate: exit 1 on high+ findings
qshield scan . --recursive --format sarif -o out.sarif   # GitHub Security tab
qshield compare original.qasm suspicious.qasm --formal   # ZX-calculus equivalence proof
qshield audit-deps --requirements requirements.txt       # quantum supply-chain audit
qshield ui                                      # Workbench at http://127.0.0.1:8765
```

Python API:

```python
import qshield

results = qshield.scan("circuit.qasm")          # quick static scan
print(results.is_clean, results.summary.total)
```

Amazon Braket circuits can be converted explicitly or via `parse_any` after installing
`qshield[braket]`. Supported standard gates map into the shared IR; unsupported operators
raise an error rather than being silently approximated. Braket qubit labels are normalized
to dense indices and retained in IR metadata.

```python
from braket.circuits import Circuit
from qshield.core.parsers import parse_any

circuit_ir = parse_any(Circuit().h(4).cnot(4, 6).rz(6, 0.5))
```

### Pre-commit hook

Install `pre-commit`, then add QSHIELD to `.pre-commit-config.yaml`. Pin `rev` to a QSHIELD commit or release that contains the hook (the v1.3.0 tag predates it):

```yaml
repos:
  - repo: https://github.com/katepallewarprathmesh-sketch/QShield
    rev: 4ce54275c9344dc5939ad5a2adbbcf9571596260
    hooks:
      - id: qshield-scan
        # Optional: default threshold is high.
        args: [--fail-on, medium]
```

For a source checkout with QSHIELD installed in the active environment, the equivalent local hook is:

```yaml
repos:
  - repo: local
    hooks:
      - id: qshield-scan
        name: QSHIELD OpenQASM scan
        entry: python -m qshield.pre_commit
        language: system
        types: [file]
        files: '(?i)\.(qasm|qasm2|qasm3)$'
```

Then run `pre-commit install` and `pre-commit run --all-files`. The hook scans staged `.qasm`, `.qasm2`, and `.qasm3` files; parse errors fail closed. It runs static and supply-chain checks and blocks findings at or above `--fail-on` (default: `high`).

## Optional detector plugins (WebAssembly/WASI)

The plugin API is implemented on `main` but is not included in the v1.3.0 release. In a source checkout, install the optional `.[plugins]` extra; plugin execution is explicit and separate from the default scan pipeline. Call `WasmPluginRunner().run(plugin_dir, circuit_ir)`. Plugins use the versioned JSON contract in `qshield/plugins/*schema.json`; the host verifies the module hash and tags findings with the manifest identity. WASI receives no preopened directories or environment variables, and the runner limits memory, fuel, wall time, input, and output. Only WASI Preview 1 imports are accepted; socket-capable imports are explicitly denied. The manifest hash is integrity checking, not publisher authentication; only run plugins you choose to trust. Plugin findings remain separate evidence and do not silently change core scan results or gate decisions.

A Rust example and build steps are in [`examples/plugins/identity-pair`](examples/plugins/identity-pair/README.md).

```python
from qshield.core.parsers import parse_file
from qshield.plugins import WasmPluginRunner

circuit = parse_file("circuit.qasm")
result = WasmPluginRunner().run("path/to/plugin-directory", circuit)
```

## Optional AI assistance (cloud, advisory)

```bash
pip install sarvamai
export SARVAM_API_KEY=...        # or gitignored .env
qshield ai triage circuit.qasm   # plain-English findings + remediation priority (sends finding summaries, not the raw circuit)
qshield ai report circuit.qasm --to hi-IN   # audit report in Hindi/Marathi/etc.
qshield ai speak "text"          # Bulbul text-to-speech
qshield ai listen clip.wav       # Saaras speech-to-text
```

Advisory only, never a verdict — the offline core never touches the network; `qshield ai` is opt-in. The **Workbench** surfaces the same features (AI Triage tab + the `qshield ui` page, key stays server-side).

## What it detects

| Threat | Example | Verdict |
|---|---|---|
| Parameter perturbation / drift | `rz(π/4 + 0.001)` | catches cumulative drift |
| Extra gate injection | cancelling `cx … cx` pairs, count anomalies | immediate |
| Ancilla information leakage | ancilla copied out before mixing | deterministic |
| Parameter-encoded payloads | angles = bytes on a grid | deterministic |
| Measurement basis manipulation | `h` right before `measure` | immediate |
| Package tampering | typosquatting, vulnerable pins, direct URLs | immediate |
| Compromised compiler / backend | pre/post-compile or cross-backend divergence | statistical / exact |

## Honest limits

For assumptions, trust boundaries, and non-goals, see the [public QSHIELD threat model](https://katepallewarprathmesh-sketch.github.io/QShield/threat-model.html).

- Detection is **evidence, never proof** that a circuit is honest. Measured on the bundled
  synthetic fixture corpus (202 clean / 215 malicious) — **fixture-corpus rates, not field rates**.
- Randomized equivalence catches large deviations, not angles ≲ 1e-3 rad; use `--formal` or dense
  matrix verification where feasible.
- The community signature pack ships **empty by design** (candidates that measured
  TPR ≈ FPR were rejected).
- **Published to PyPI** and as a GHCR image; Apache-2.0. Detection rates above are fixture-corpus measurements, not field rates.

## Status & license

**v1.3.0** — software-only. See `CHANGELOG.md` for release notes.
Apache 2.0 — see [LICENSE](LICENSE). Contributions (signatures, analyzers, corpus circuits) welcome.

## Development

```bash
pip install -e '.[dev,qiskit,cirq,formal]'
python -m pytest tests
ruff check src tests benchmarks
mypy src
```
