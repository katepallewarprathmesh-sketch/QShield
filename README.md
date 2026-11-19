<div align="center">

# QSHIELD

### Security analysis for quantum circuits and the software that ships them.

[![PyPI version](https://img.shields.io/pypi/v/qshield?color=77e3bd&label=PyPI)](https://pypi.org/project/qshield/)
[![Python versions](https://img.shields.io/pypi/pyversions/qshield)](https://pypi.org/project/qshield/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-77e3bd)](LICENSE)

[Workbench](https://katepallewarprathmesh-sketch.github.io/QShield/workbench.html) · [Threat model](https://katepallewarprathmesh-sketch.github.io/QShield/threat-model.html) · [Changelog](CHANGELOG.md)

</div>

> **Software-only.** QSHIELD has no QPU or hardware acceptance path. Core analysis runs offline. Findings are evidence for human review—not proof that a circuit is safe or malicious.

## Features

- Scan OpenQASM circuits and emit text, JSON, SARIF, HTML, or PDF reports.
- Compare circuits using exact or randomized methods; verify unitaries up to 12 qubits.
- Audit quantum-package dependencies for issues such as typosquatting and vulnerable pins.
- Use the browser Workbench or Python APIs for Qiskit, Cirq, PennyLane, Amazon Braket, and pytket.
- Add explicit, resource-limited detector plugins using WASI.

The bundled corpus has 417 synthetic fixtures (202 clean, 215 malicious). These are fixture-corpus measurements, **not field rates**.

## Install

```bash
pip install qshield
pip install 'qshield[qiskit,cirq]'  # optional parsers
pip install 'qshield[braket]'       # Amazon Braket
pip install 'qshield[pytket]'       # pytket
pip install 'qshield[formal]'       # PyZX and Z3 verification
pip install 'qshield[plugins]'      # optional WASI plugins
```

Requires Python 3.10 or later. To run the v1.6.0 container with the Workbench exposed only on host loopback:

```bash
docker run --rm -p 127.0.0.1:8765:8765 ghcr.io/katepallewarprathmesh-sketch/qshield:1.6.0
```

For released wheels and source archives, verify GitHub build provenance before installing:

```bash
gh attestation verify "$WHEEL_OR_SDIST" --repo katepallewarprathmesh-sketch/QShield
```

## Quickstart

```bash
qshield scan circuit.qasm --fail-on high
qshield scan . --recursive --format sarif -o results.sarif
qshield compare original.qasm candidate.qasm --formal
qshield audit-deps --requirements requirements.txt
qshield ui
```

Python API:

```python
import qshield

results = qshield.scan("circuit.qasm")
print(results.is_clean, results.summary.total)
```

## Workbench

Run `qshield ui` and open `http://127.0.0.1:8765`. The browser Workbench accepts local `.qasm`, `.qasm2`, and `.qasm3` files up to 1 MiB. A selected file is read and analyzed in the browser only after you choose **Scan**. Only a supported OpenQASM subset is modeled; parse errors stop analysis, and unmodeled gates may make findings incomplete.

The Workbench server has no built-in authentication. It binds to loopback by default. Do not expose it to an untrusted network without network restrictions and an authenticated TLS proxy. A non-loopback source install requires `qshield ui --host 0.0.0.0 --allow-remote` and prints a warning.

## Runtime proxy and audit chain

The runtime proxy connects to its configured upstream. It binds to loopback by default; non-loopback use requires TLS and bearer-token or mutual-TLS authentication. `--trusted-front-proxy` delegates TLS and client authentication—it does not verify the connecting peer. Never expose a delegated plain-HTTP listener to an untrusted network.

The proxy supports `--policy observe|enforce` and `--failure-mode open|closed`. In `open` mode, an unchecked circuit may be forwarded and logged as skipped; `closed` mode blocks when checks cannot be completed. Choose these settings for your deployment's risk tolerance.

For a local hash-chained audit log:

```bash
qshield runtime proxy --upstream https://provider.example/api \
  --audit-chain /var/log/qshield/audit.jsonl
qshield runtime audit-verify /var/log/qshield/audit.jsonl
```

The sink is local and single-writer. Keep its reported head hash independently and supply it later with `--expected-head` to detect tail truncation. Without that external anchor, truncation cannot be detected. The log contains event metadata and circuit hashes, not circuit source; it is not a central audit service.

Keep bearer-token files out of source control and set POSIX permissions to `0600` or stricter. Tokens are compared in constant time and configured client-auth tokens are not forwarded upstream. Scopes are `proxy:read`, `proxy:submit`, `proxy:manage`, and `proxy:admin`.

## Optional integrations

- **WASI plugins:** The plugin API was introduced in v1.4.0 and is enabled with `qshield[plugins]`. Plugins have resource limits, no preopened directories or environment, and no socket-capable imports. Their findings do not change core verdicts. A module hash checks integrity, not publisher identity; run only plugins you trust.
- **AI assistance:** Install `sarvamai` and set `SARVAM_API_KEY` to use opt-in cloud commands. Triage sends finding summaries, not raw circuits; other commands send their supplied text, audio, or report to the provider. Output is advisory, never a verdict; the offline core is unchanged.

## Limits and security

- Detection findings are evidence, not proof of maliciousness or safety. The bundled synthetic corpus does not establish field performance.
- Randomized equivalence may miss small deviations, including angles near or below `1e-3` radians; use `--formal` or dense-matrix verification where feasible.
- See the [threat model](https://katepallewarprathmesh-sketch.github.io/QShield/threat-model.html) for trust boundaries, assumptions, and non-goals.
- The community signature pack is empty by design.

## Development

```bash
pip install -e '.[dev]'
pytest -q
ruff check src tests benchmarks
mypy src
```

See [CHANGELOG.md](CHANGELOG.md) for release history and [LICENSE](LICENSE) for license terms.
