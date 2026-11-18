# QSHIELD Circuit Canonicalization v1

**Spec ID:** `qshield-circuit-c14n-v1`  
**Status:** Implemented; structural identity only, not semantic equivalence.

## Canonical object

The canonical JSON object contains exactly these fields:

```json
{
  "spec": "qshield-circuit-c14n-v1",
  "num_qubits": 2,
  "num_classical_bits": 2,
  "gates": [
    {"name": "h", "qubits": [0], "parameters": []},
    {"name": "cx", "qubits": [0, 1], "parameters": []}
  ],
  "measurements": [[0, 0], [1, 1]]
}
```

The object is serialized as UTF-8 JSON with keys sorted lexicographically, no insignificant whitespace, Unicode preserved, and non-finite JSON numbers forbidden. The exact field set and order of arrays are significant.

### Included identity

- Number of quantum and classical bits.
- Ordered gates, including gate name, ordered qubit operands, and ordered parameters.
- Ordered `(qubit, classical_bit)` measurements.

Circuit name, source framework and source text/hash, gate IDs, annotations, unitary caches, and arbitrary metadata are excluded. Framework importers that produce the same normalized structure therefore produce the same v1 payload.

### Gate names and parameters

Gate names are normalized to Unicode NFC and otherwise preserved. Each parameter is converted to a finite IEEE-754 double, rendered as decimal, then rounded to nine fractional digits using decimal `ROUND_HALF_EVEN`. The resulting parameter is encoded as a fixed-nine-decimal string; negative zero is encoded as positive zero. Parameter order is preserved. NaN and infinities are rejected.

Qubit and classical-bit counts and indices must be non-negative integers; operands and measurements must be within their corresponding widths. Invalid structures fail closed with `ValueError`.

## Digest

The digest is lowercase hexadecimal SHA-256 over:

```text
ASCII("qshield-circuit-c14n-v1") || 0x00 || canonical_json_utf8
```

The spec identifier is part of the payload and also used as a domain-separation prefix. Consumers storing a digest must store its spec ID alongside it. The digest does not mean that two different gate sequences are semantically inequivalent; use QSHIELD's `compare` functionality for equivalence checks.

## Reference implementation and vectors

Implementation: `qshield.core.canonicalization.canonical_circuit_payload` and `canonical_circuit_hash_v1`. Fixed payload/hash vectors are in `tests/vectors/canonicalization-v1.json` and are verified by `tests/unit/test_canonicalization.py`.

The existing runtime proxy's legacy `canonical_circuit_hash` is intentionally unchanged for compatibility. It is not a v1 alias. Future changes to this contract require a new spec ID and new vectors; v1 vectors must remain stable.
