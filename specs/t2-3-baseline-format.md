# Baseline Record Format

**Version:** `qshield-baseline-v1`
**Canonicalisation:** `qshield-circuit-c14n-v1`

## 1. What a baseline is

A baseline is a signed statement that a specific readout was approved for a
specific workload. It is the reference against which the T2.3 differential
compares a candidate.

A baseline is **not** a claim that a circuit is safe. It records that someone
with authority approved one artifact.

## 2. Fields

| Field | Type | Purpose |
|---|---|---|
| `baseline_id` | string | Stable identifier for this approval |
| `workload_id` | string | The workload this baseline governs |
| `circuit_digest` | hex | `qshield-circuit-c14n-v1` digest of the approved circuit |
| `readout_digest` | hex | Digest of the approved readout profile |
| `version` | int | Monotonic; drives rollback refusal |
| `approved_by` | string | Identity of the approver |
| `approved_at` | ISO-8601 Z | Approval time |
| `canonicalization_spec` | string | Must match the running parser's spec |
| `signature` | object | `{algorithm, key_id, value}` |
| `revoked_at` / `revoked_by` / `revoke_reason` | optional | Revocation record |
| `expires_at` | optional | Expiry, `YYYY-MM-DDTHH:MM:SSZ` |
| `metadata` | object | Free-form, **not** covered by the signature |

## 3. What the signature covers

The signed payload is the canonical JSON of every field above **except**
`signature` and `metadata`, serialised with sorted keys and no whitespace.

Binding the circuit *and* readout digests matters: signing only the circuit
would let an attacker keep the approved circuit while changing which qubits are
measured.

`metadata` is deliberately outside the signature — it cannot influence the
verdict, so signing it would only invite confusion about its authority.

## 4. Trust rules

### Substitution

A modified `circuit_digest`, `readout_digest`, `workload_id`, `version` or
`approved_by` changes the signed bytes, so verification fails. The registry
refuses such a record outright.

A registered record whose `reference_circuit` does not hash to the signed
`circuit_digest` is also refused — this catches a reference swapped in after
registration, behind a valid signature.

### Rollback

Versions are monotonic per workload. Registering a version that is not strictly
greater than the currently approved version is refused:

```
BaselineError: rollback refused: version 1 is not newer than the approved version 1
```

This stops an attacker who holds an old, validly signed baseline from
reinstating it to legitimise a circuit that was since superseded.

### Revocation

A revoked baseline is never usable, even if its signature is valid. Revocation
is permanent in the record; the history keeps the approval chain.

### Expiry

An expired baseline is `EXPIRED`, not `PASS`. Expiry is evaluated against a
supplied `now`, so the behaviour is testable.

### Parser compatibility

If `canonicalization_spec` differs from the running parser's spec, the baseline
is `PARSER_INCOMPATIBLE`. Digest comparison across incompatible canonical forms
would be meaningless, and silently re-deriving digests would break the signature.

## 5. States

`APPROVED`, `REVOKED`, `EXPIRED`, `UNVERIFIED`, `MISSING`, `WRONG_WORKLOAD`,
`PARSER_INCOMPATIBLE`.

Only `APPROVED` is usable. Every other state produces `INDETERMINATE` from the
evaluator — never a pass.

In practice `WRONG_WORKLOAD` surfaces as `MISSING` when the lookup is by
workload name, because there is nothing under that name. The distinction is kept
for callers that resolve by `baseline_id`.

## 6. On-disk form

JSON, one record per file. The loader rejects duplicate keys and unknown fields:

```
BaselineError: duplicate key 'version' in baseline file
BaselineError: unknown baseline field 'extra'
```

Duplicate-key rejection matters because a parser that silently keeps the last
value can be used to smuggle a field past a reviewer.

## 7. Example

```json
{
  "baseline_id": "bl-0001",
  "workload_id": "portfolio-optimiser",
  "circuit_digest": "9f2c…",
  "readout_digest": "41ab…",
  "version": 3,
  "approved_by": "security@example.com",
  "approved_at": "2026-11-12T09:00:00Z",
  "canonicalization_spec": "qshield-circuit-c14n-v1",
  "signature": {"algorithm": "ed25519", "key_id": "sha256:…", "value": "…"},
  "metadata": {}
}
```
