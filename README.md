<div align="center">

# QSHIELD

### Security analysis for quantum circuits and the software that ships them.

[![PyPI version](https://img.shields.io/pypi/v/qshield?color=77e3bd&label=PyPI)](https://pypi.org/project/qshield/)
[![Python versions](https://img.shields.io/pypi/pyversions/qshield)](https://pypi.org/project/qshield/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache--2.0-77e3bd)](LICENSE)

[Workbench](https://katepallewarprathmesh-sketch.github.io/QShield/workbench.html) · [Security architecture](https://katepallewarprathmesh-sketch.github.io/QShield/security-architecture.html) · [Changelog](CHANGELOG.md)

</div>

> **Purpose-built for quantum software.** Scan circuits, verify equivalence, audit dependencies, and enforce runtime policy from one open-source toolkit.

## Features

- Scan OpenQASM circuits and emit text, JSON, SARIF, HTML, or PDF reports.
- Compare circuits using exact or randomized methods; verify unitaries up to 12 qubits.
- Audit quantum-package dependencies for issues such as typosquatting and vulnerable pins.
- Use the browser Workbench or Python APIs for Qiskit, Cirq, PennyLane, Amazon Braket, and pytket.
- Add sandboxed detector plugins using WASI.
- Verify quantum contextuality with the Mermin–Peres magic square and CHSH.

Score the bundled corpus yourself and check the published numbers: `qshield benchmark`.

## Install

```bash
pip install qshield
pip install 'qshield[qiskit,cirq]'  # optional parsers
pip install 'qshield[braket]'       # Amazon Braket
pip install 'qshield[pytket]'       # pytket
pip install 'qshield[formal]'       # PyZX and Z3 verification
pip install 'qshield[plugins]'      # optional WASI plugins
```

Requires Python 3.10 or later. To run the v1.6.0 container with the Workbench on host loopback:

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
qshield benchmark
qshield contextuality
qshield ui
```

Python API:

```python
import qshield

results = qshield.scan("circuit.qasm")
print(results.is_clean, results.summary.total)
```

## Workbench

Run `qshield ui` and open `http://127.0.0.1:8765`. The browser Workbench analyzes local `.qasm`, `.qasm2`, and `.qasm3` files in the browser after you choose **Scan**.

For deployment configuration and the Workbench's security architecture, see the [security architecture](https://katepallewarprathmesh-sketch.github.io/QShield/security-architecture.html).

## Runtime proxy and audit chain

The runtime proxy adds TLS, bearer-token or mutual-TLS authentication, observe/enforce policies, open/closed failure modes, bounded concurrency, and audit logging. It works with a configured upstream and can be paired with a trusted front proxy. See the [security architecture](https://katepallewarprathmesh-sketch.github.io/QShield/security-architecture.html) for deployment guidance.

For a local hash-chained audit log:

```bash
qshield runtime proxy --upstream https://provider.example/api \
  --audit-chain /var/log/qshield/audit.jsonl
qshield runtime audit-verify /var/log/qshield/audit.jsonl
```

Verify records with `qshield runtime audit-verify`; use `--expected-head` to check against an independently retained chain head. See the [security architecture](https://katepallewarprathmesh-sketch.github.io/QShield/security-architecture.html) for audit and credential-handling details.

## Integrations

- **WASI plugins:** Extend analysis with sandboxed detector plugins. The plugin API was introduced in v1.4.0; install `qshield[plugins]`.
- **AI assistance:** Add opt-in triage, translation, and speech tools with `sarvamai` and `SARVAM_API_KEY`.

## Open benchmark

The corpus, labels, scoring rule, and scorer are public, so any number QSHIELD reports can be reproduced or challenged:

```bash
qshield benchmark                                   # score the bundled corpus
qshield benchmark --threshold high --format json    # own operating point, machine-readable
python benchmarks/benchmark.py --check              # verify published results match a fresh run
```

Corpus v1 holds 417 circuits (202 clean, 215 malicious) across five labelled attack families. Results ship as `benchmarks/results/benchmark-v1.json`, validated against `benchmarks/benchmark-v1.schema.json`, and CI fails if they drift from a fresh run. The protocol is in [benchmarks/benchmark-v1.md](benchmarks/benchmark-v1.md); the published numbers are on the [open benchmark page](https://katepallewarprathmesh-sketch.github.io/QShield/benchmark.html).

### Readout manipulation (T2.3) needs a baseline

T2.3 is a **differential** check, not a gate pattern. A basis rotation before measurement is what a correct Deutsch or Bernstein–Vazirani circuit does, so matching the pattern flagged 68 clean circuits while adding no real discrimination.

The check now compares a candidate readout against an approved, signed reference and reports one of four states — `PASS`, `FINDING`, `INDETERMINATE`, `ERROR`. With no baseline it returns `INDETERMINATE`; it never guesses. T2.3 findings therefore require a baseline:

```python
from qshield import Scanner
from qshield.integrity.baseline import BaselineRegistry, load_baseline_file

scanner = Scanner()
scanner.add_circuit("candidate.qasm")
scanner.set_baselines(BaselineRegistry(), public_key_pem=pem_bytes, workload_id="my-workload")
results = scanner.run()
```

Design, baseline format, and measured before/after figures: [specs/t2-3-differential-design.md](specs/t2-3-differential-design.md), [specs/t2-3-baseline-format.md](specs/t2-3-baseline-format.md), [specs/t2-3-before-after.md](specs/t2-3-before-after.md).

## Contextuality verification

`qshield contextuality` checks that a modelled circuit realises a genuinely non-classical strategy:

```
Magic square: 1.0000 (9/9) vs classical ceiling 0.8889
CHSH:         S = 2.8284 vs classical bound 2.0 (quantum limit 2.8284)
Verdict:      contextual
```

The magic square is the Mermin–Peres grid: every row of two-qubit Pauli observables multiplies to `+I`, and the columns multiply to `+I, +I, −I`. Those products are both the product of the same nine values, so they must agree — and they don't. No pre-assigned table can satisfy all nine constraints, which caps every classical strategy at 8/9; entangled qubits win 9/9. CHSH reaches the Tsirelson bound of 2√2 on a Bell state.

This is a verification primitive for circuits, not a device benchmark: it runs on the simulator and confirms the circuit's claimed quantum behaviour.

## Annealer model audit

Annealing workflows submit a QUBO or Ising model to a solver rather than a circuit. `qshield audit-qubo` audits that model before it reaches the solver:

```bash
qshield audit-qubo model.qubo                                   # structure, coefficients, digest
qshield audit-qubo model.qubo --hardware-variables 5000         # check the target annealer budget
qshield audit-qubo model.qubo --expected-digest <hex>           # confirm nothing changed since review
```

Every model gets a SHA-256 digest over its coefficients at full precision, so you can commit to a model when you approve it and detect any later edit — including a perturbation far smaller than a solver would visibly notice. The audit also reports malformed terms, couplings below the control-error floor, extreme dynamic range, unconstrained variables, and a starting chain strength from uniform torque compensation.

`.qubo` and `.json` model files are discovered by `qshield scan` alongside circuits, and model findings flow into JSON, SARIF, HTML, and PDF output under the same severity gates. The format and check definitions are in [specs/qubo-model-audit-v1.md](specs/qubo-model-audit-v1.md).

## Security architecture

QSHIELD combines local analysis, runtime controls, provenance, and extensible detectors. Read the [public security architecture](https://katepallewarprathmesh-sketch.github.io/QShield/security-architecture.html) for the system's design, evaluation, and deployment details.

## Development

```bash
pip install -e '.[dev]'
pytest -q
ruff check src tests benchmarks
mypy src
```

See [CHANGELOG.md](CHANGELOG.md) for release history and [LICENSE](LICENSE) for license terms.
