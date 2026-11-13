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
| `qshield ui` | **Workbench** — local web UI: scan, compare, Policy Studio (your policies scored against the bundled fixture corpus), Robustness Probe (does a finding survive semantics-preserving camouflage?) |
| Reports | SARIF (GitHub Security tab) · JSON · HTML · PDF |

Everything runs offline: no hardware, no cloud, no accounts, no network calls.

## Why

Everyone is busy with post-quantum cryptography (PQC) — security for *classical* data against
quantum attacks. Almost nobody is securing **quantum software itself**. Classical SAST/DAST/SCA
tools cannot analyze quantum circuits: gates are unitary matrices, states can't be copied for
inspection, and measurement is destructive. QSHIELD is purpose-built for this territory.

## Install

```bash
pip install -e .                       # core (OpenQASM parser, static analysis, CLI)
pip install -e '.[qiskit,cirq]'        # + framework parsers (qiskit-aer used by --full)
pip install -e '.[formal]'             # + ZX-calculus verification (PyZX, Z3)
pip install -e '.[dev]'                # + test/lint tooling
```

Requires Python ≥ 3.10.

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

- Detection is **evidence, never proof** that a circuit is honest. Measured on the bundled
  synthetic fixture corpus (202 clean / 215 malicious) — **fixture-corpus rates, not field rates**.
- Randomized equivalence catches large deviations, not angles ≲ 1e-3 rad; use `--formal` or dense
  matrix verification where feasible.
- The community signature pack ships **empty by design** (candidates that measured
  TPR ≈ FPR were rejected).
- **Not published to PyPI / marketplaces.** Apache-2.0; source build only.

## Status & license

**v1.1.0** — software-only. See `CHANGELOG.md` for release notes.
Apache 2.0 — see [LICENSE](LICENSE). Contributions (signatures, analyzers, corpus circuits) welcome.

## Development

```bash
pip install -e '.[dev,qiskit,cirq,formal]'
python -m pytest tests
ruff check src tests benchmarks
mypy src
```
