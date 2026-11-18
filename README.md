<div align="center">

# QSHIELD

### Security analysis for quantum circuits and the software that ships them.

Find suspicious circuit behavior, check equivalence, and audit dependencies—with evidence your team can review before a circuit reaches a run.

[![PyPI version](https://img.shields.io/pypi/v/qshield?color=77e3bd)](https://pypi.org/project/qshield/)
[![Python versions](https://img.shields.io/pypi/pyversions/qshield)](https://pypi.org/project/qshield/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-77e3bd)](LICENSE)

[Live Workbench](https://katepallewarprathmesh-sketch.github.io/QShield/workbench.html)
· [Install from PyPI](https://pypi.org/project/qshield/)
· [Threat model](https://katepallewarprathmesh-sketch.github.io/QShield/threat-model.html)
· [Changelog](CHANGELOG.md)

</div>

> **Software-only by design.** No QPU, device SDK, or hardware acceptance path. Core analysis runs offline; the browser Workbench runs the real engine locally. Findings are evidence for human review—not proof that a circuit is safe or malicious.

## At a glance

| Surface | Use it for |
|---|---|
| **CLI & CI** | Scan OpenQASM, compare circuits, audit dependencies, emit SARIF / JSON / HTML / PDF |
| **Python API** | Parse and analyze circuits from Qiskit, Cirq, PennyLane, Amazon Braket, and pytket |
| **Workbench** | Interactive browser-local or local-server review: scan, compare, robustness probe, and policy scoring |
| **WASI plugins** | Add explicit, resource-limited detector extensions without changing core verdicts |

**Measured scope:** 417 bundled fixtures (202 clean / 215 malicious); fixture-corpus rates, not field rates. See [limits and threat model](https://katepallewarprathmesh-sketch.github.io/QShield/threat-model.html).

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
pip install 'qshield[qiskit,cirq]'     # + Qiskit and Cirq parsers (qiskit-aer used by --full)
pip install 'qshield[pennylane]'        # + PennyLane tape parser
pip install 'qshield[braket]'           # + Amazon Braket Circuit parser
pip install 'qshield[pytket]'            # + pytket Circuit parser
pip install 'qshield[formal]'            # + ZX-calculus verification (PyZX, Z3)
```

Docker: `docker pull ghcr.io/katepallewarprathmesh-sketch/qshield:1.4.0` (or build from source: `docker build -t qshield .`). Run it with `docker run --rm -p 127.0.0.1:8765:8765 qshield` to keep the unauthenticated Workbench available only on host loopback. The container binds internally with an explicit non-loopback opt-in; keep the host port mapping on loopback. Do not publish the Workbench beyond localhost without network restrictions and an authenticated TLS proxy. For source installs, a non-loopback bind requires `qshield ui --host 0.0.0.0 --allow-remote` and prints a security warning.

From source: `git clone https://github.com/katepallewarprathmesh-sketch/QShield.git && cd QShield && pip install -e '.[dev]'`

Requires Python ≥ 3.10.

For releases produced after the provenance workflow change, verify a downloaded wheel or sdist
against GitHub's signed build provenance before installing (requires GitHub CLI with `gh attestation`):

```bash
gh attestation verify "$WHEEL_OR_SDIST" --repo katepallewarprathmesh-sketch/QShield
```

The Workbench's Policy Studio includes the bundled fixture corpus in wheel and Docker
installs (202 clean + 215 malicious circuits). For a custom corpus, point
`QSHIELD_FIXTURES_DIR` at a directory containing `clean_circuits/` and
`malicious_circuits/`; scan and compare work independently of corpus scoring.

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

pytket circuits are accepted by `parse_any` or `parse_pytket` after installing
`qshield[pytket]`. Numeric pytket angles (specified in multiples of pi) are converted to
radians. Supported gate operations map into the shared IR; unsupported or classically
conditioned operations fail closed. Measurement assignments and register labels are retained.
Reset operations and global phase cannot be represented by the current IR and are reported
in parser warnings rather than silently treated as represented.

```python
from braket.circuits import Circuit
from qshield.core.parsers import parse_any

circuit_ir = parse_any(Circuit().h(4).cnot(4, 6).rz(6, 0.5))
```

### Pre-commit hook

Install `pre-commit`, then add QSHIELD to `.pre-commit-config.yaml`. Pin `rev` to a QSHIELD commit or release that contains the hook:

```yaml
repos:
  - repo: https://github.com/katepallewarprathmesh-sketch/QShield
    rev: v1.4.0
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

## Runtime gate policy and overload behavior

The runtime proxy supports `--policy observe|enforce` for findings and `--failure-mode open|closed` when a circuit cannot be checked. By default, `observe` uses `open` and `enforce` uses `closed`; set the mode explicitly for production. `--max-workers` and `--request-queue-size` bound concurrency and pending connections. On overload, `closed` returns an explicit 503 block; `open` forwards the request without inspection and logs coverage as skipped. Gate-decision audit events include the policy version, decision, circuit digest(s), and coverage, independent of the alert severity threshold. Set `--policy-version` to the identifier used by your deployment.

The proxy binds to loopback by default. It can terminate TLS 1.2+ itself and optionally require verified client certificates (mTLS). Scoped bearer tokens are loaded from a JSON file whose POSIX permissions must be `0600` or stricter; keep it outside source control and rotate it through your secret-management process. Token scopes are `proxy:read` (GET/HEAD/OPTIONS), `proxy:submit` (other non-DELETE methods), `proxy:manage` (DELETE), and `proxy:admin` (all methods). The proxy compares tokens in constant time and does not relay configured client-auth bearer tokens to the upstream.

A non-loopback listener requires TLS plus bearer-token or mTLS authentication, unless `--trusted-front-proxy` explicitly delegates both TLS and client authentication to a trusted front proxy/service mesh. That flag is a trust assertion, not a mechanism that verifies the connecting peer. Do not expose a delegated plain-HTTP listener to an untrusted network. Token file format:

```json
{"tokens":[{"token":"replace-with-a-random-secret-of-at-least-32-characters","scopes":["proxy:read","proxy:submit"]}]}
```

Example TLS listener with bearer tokens:

```bash
qshield runtime proxy --upstream https://provider.example/api \
  --host 0.0.0.0 --tls-cert /etc/qshield/server.pem --tls-key /etc/qshield/server-key.pem \
  --tokens-file /etc/qshield/proxy-tokens.json \
  --policy enforce --failure-mode closed --policy-version release-2026-11
```

For mTLS instead, provide `--client-ca /etc/qshield/client-ca.pem` with the TLS cert and key; clients must present a certificate chaining to that CA. On a loopback-only listener TLS and client authentication are optional. The token-file JSON schema is packaged at `qshield.runtime/proxy-token-file.schema.json`.

## Optional detector plugins (WebAssembly/WASI)

The plugin API is included in v1.4.0 behind the optional `.[plugins]` extra; plugin execution is explicit and separate from the default scan pipeline. Call `WasmPluginRunner().run(plugin_dir, circuit_ir)`. Plugins use the versioned JSON contract in `qshield/plugins/*schema.json`; the host verifies the module hash and tags findings with the manifest identity. WASI receives no preopened directories or environment variables, and the runner limits memory, fuel, wall time, input, and output. Only WASI Preview 1 imports are accepted; socket-capable imports are explicitly denied. The manifest hash is integrity checking, not publisher authentication; only run plugins you choose to trust. Plugin findings remain separate evidence and do not silently change core scan results or gate decisions.

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

**v1.4.0** — software-only. See `CHANGELOG.md` for release notes.
Apache-2.0 — see [LICENSE](LICENSE). Contributions to parsers, integrations, tests, and documentation are welcome. The community signature pack is intentionally empty; signature submissions are not being solicited.

## Development

```bash
pip install -e '.[dev,qiskit,cirq,formal]'
python -m pytest tests
ruff check src tests benchmarks
mypy src
```

The Workbench, static-site bootstrap, and VS Code extension are authored in TypeScript. To rebuild their checked-in/runtime JavaScript outputs after editing UI sources:

```bash
cd frontend
npm ci
npm run build
```
