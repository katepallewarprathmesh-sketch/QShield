# QSHIELD Offline Provenance Manifest v1

**Spec ID:** `qshield-provenance-v1`  
**Status:** Included in QSHIELD 1.5.0 for OpenQASM 2/3 source files; offline Ed25519 signatures are available with the optional `provenance` extra.

## Scope and limits

A manifest records the exact source-file SHA-256, the v1 canonical circuit SHA-256, source format, QSHIELD/Python tool versions, and UTC creation time. It does not embed circuit source or local file paths. The canonical digest is structural identity, not a semantic-equivalence result. The manifest does not claim dependency closure, policy evaluation, scan coverage, compiler-pass history, or provider execution evidence; those fields are not collected by this v1 implementation.

This format is offline-verifiable. It does not require a registry, transparency service, cloud account, or signature-pack workflow. It does not authenticate a publisher unless the verifier independently trusts the supplied public key.

## JSON schema

The machine-readable schema is [`provenance-v1.schema.json`](../src/qshield/provenance/provenance-v1.schema.json) and is included in the Python package. The root object is:

- `spec_version`: exactly `qshield-provenance-v1`.
- `created_utc`: UTC ISO 8601 timestamp ending in `Z`.
- `subject`: source format, raw source SHA-256, canonicalization spec ID, and canonical circuit SHA-256.
- `toolchain`: QSHIELD and Python names/versions.
- `signature`: absent on creation; present after signing, with Ed25519 algorithm, key ID, and base64 signature.

Unknown root fields are rejected in v1. Future fields that change the signed contract require a new spec version.

## Signature input

Before signing or verification, remove the top-level `signature` field. Serialize the remaining object as UTF-8 JSON with lexicographically sorted keys, no insignificant whitespace, Unicode preserved, and non-finite numbers forbidden. The signed message is:

```text
ASCII("qshield-provenance-v1") || 0x00 || canonical_json_utf8
```

The `key_id` is `sha256:` followed by the lowercase SHA-256 of the signer's 32-byte raw Ed25519 public key. Verifiers must check the signature and that the supplied public key produces the declared key ID. If a circuit file is supplied to `verify`, both its raw source digest and canonical circuit digest/format must match the signed subject.

## CLI workflow

From a source checkout, install the optional signing dependency (the core package remains usable without it):

```bash
pip install -e '.[provenance]'
qshield provenance keygen --private-key qshield-ed25519-private.pem --public-key qshield-ed25519-public.pem
qshield provenance create circuit.qasm --output circuit.provenance.json
qshield provenance sign circuit.provenance.json --private-key qshield-ed25519-private.pem
qshield provenance verify circuit.provenance.json --public-key qshield-ed25519-public.pem --circuit circuit.qasm
```

Key generation prompts for a passphrase by default. `--no-passphrase` is an explicit opt-out; protect any unencrypted private key accordingly. Key files are never overwritten. Keep the private key secret and distribute the public key through a channel the verifier trusts.

Implementation: `qshield.provenance`; canonicalization contract: [`circuit-canonicalization-v1.md`](circuit-canonicalization-v1.md).
