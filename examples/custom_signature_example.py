"""Writing and loading a custom signature."""

from pathlib import Path

from qshield.signatures import SignatureMatcher, load_signature

YAML = """id: "QSig-2026-9001"
name: "Suspicious Repeated Hadamard"
version: "1.0"
author: "you"
date: "2026-11-12"
severity: "low"
threat_type: "T1.3"
description: "Repeated H-H pairs on the same qubit (identity obfuscation)."
detection:
  method: "structural"
  structural_pattern:
    type: "gate_sequence_inverse"
    window: 4
    tolerance: 1.0e-8
references: []
false_positive_probability: 0.5
remediation: "Remove redundant H pairs."
"""

ROOT = Path(__file__).resolve().parent.parent

if __name__ == "__main__":
    path = Path("my_sig.yaml")
    path.write_text(YAML)
    sig = load_signature(path)
    print("loaded:", sig.id, sig.name)
    matcher = SignatureMatcher([sig])
    with open(ROOT / "tests/fixtures/clean_circuits/bell_state.qasm") as fh:
        print(fh.read()[:80])
    path.unlink()  # don't litter the repo with the demo signature
