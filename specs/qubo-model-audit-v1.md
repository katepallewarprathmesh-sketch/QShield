# QSHIELD Annealer Model Audit v1

**Spec ID:** `qshield-qubo-v1`
**Status:** Implemented in the source tree. Audits a user-supplied QUBO or Ising model file; it does not generate models, embed them, or solve them.

## Scope

Annealing workflows submit a **quadratic binary model** to a solver, not a circuit. The published supply-chain literature in this area follows the same shape: a routing or scheduling problem is encoded as a QUBO, handed to a hybrid solver or a QPU, and the returned bitstring is decoded back into an operational decision.

QSHIELD audits the artifact at the point where it is least visible and most consequential — between the model generator and the solver. A model that is malformed, silently rescaled, or edited after review produces a confident answer to a different question.

## Accepted input

| Form | Example |
|---|---|
| QUBO matrix | `[[0, 2.0], [0, 0]]`, upper- or lower-triangular, or symmetric |
| QUBO term map | `{"qubo": {"0,1": 2.0, "0,0": -1.0}}` |
| Ising model | `{"linear": {"0": -1.0}, "quadratic": {"0,1": 0.5}}` |
| Declared size | `{"num_variables": 64, ...}` accepted alongside any of the above |

Diagonal entries are linear terms and off-diagonal entries are couplings, which is the convention every annealer API accepts. A symmetric matrix is read from whichever triangle carries the coefficient; the two triangles are never summed, and a matrix that disagrees with itself is rejected rather than repaired.

`num_variables` may exceed the number of variables carrying a term. It may not be smaller, because that would put a declared term outside the model.

## Digest commitment

`digest` is a SHA-256 over a canonical form of the model:

- terms sorted by index and hashed at full IEEE-754 precision via `float.hex()`, never rounded
- `-0.0` normalised to `0.0`
- the spec identifier and the variable count included in the hashed payload

Full precision is the point. A commitment that rounds coefficients hides exactly the edit it exists to catch: a perturbation smaller than the rounding step yields an identical digest.

Record the digest when the model is approved, pass it back with `--expected-digest`, and any later edit — however small — is reported.

```bash
qshield audit-qubo model.qubo                      # print the digest to commit
qshield audit-qubo model.qubo --expected-digest eac7…
```

## Findings

| Category | Severity | Condition |
|---|---|---|
| `integrity` | high | coefficient is `NaN` or infinite |
| `integrity` | high | term references a variable outside the declared count |
| `integrity` | high | digest does not match the committed value |
| `feasibility` | high | variable count exceeds the stated solver budget |
| `coefficients` | medium | coupling below the `1e-3` control-error floor |
| `coefficients` | low | largest/smallest coupling ratio at or above `1e6` |
| `coefficients` | low | variable carries no linear or quadratic term |
| `coefficients` | info | Ising document exceeds the conventional `[-1, 1]` range |

The unit-range check applies to Ising documents, where coefficients are conventionally normalised before embedding. A QUBO is expressed on the caller's own cost scale, so magnitude alone is not reported there.

## Chain strength estimate

`chain_strength` reports a starting value from uniform torque compensation, the default strategy in Ocean's embedding tools:

```
J_chain = 1.414 * sqrt( (Σ J_ij² + Σ h_i²) / n_variables )
```

This is an estimate to tune from. It depends on the embedding and chain lengths, neither of which a model file carries, so it is reported as a statistic rather than raised as a finding.

## Threat mapping

Model findings reuse the published threat taxonomy so they travel through the same reports, SARIF rules, and severity gates as circuit findings.

| Code | Meaning |
|---|---|
| `T3.1` | Model and dependency integrity: the artifact differs from what was reviewed |
| `T3.2` | Model feasibility: the instance does not match the stated solver |
| `T1.4` | Coefficient tampering or numeric degradation of the objective |

## Reporting

```bash
qshield audit-qubo model.qubo --format json --hardware-variables 5000
qshield scan ./models --fail-on high
```

`scan` discovers `.qubo` files alongside `.qasm` circuits and routes model findings into JSON, SARIF, HTML, and PDF output. `--fail-on` applies to the model findings by the same severity ordering as circuit findings.

## Limits

The audit is structural and numeric. It does not solve the model, so it cannot tell you whether the encoded problem is the intended one, whether the ground state is correct, or whether the decoded bitstring is feasible in the real system. It establishes that the artifact is well formed, internally consistent, matching what you approved, and within the numeric range of the target solver.
