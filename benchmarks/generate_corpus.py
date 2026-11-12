"""Deterministic generator for the QSHIELD benchmark fixture corpus.

Writes *generated* fixtures (prefix ``gen_``) into ``tests/fixtures/`` and a
machine-readable index at ``benchmarks/corpus_index.json`` mapping every
generated malicious fixture to its expected threat type.

The hand-written fixtures (no prefix) are curated proofs of concept; the
generated ones are parameterised variants across the same attack families.
Re-run to regenerate:  python benchmarks/generate_corpus.py
"""

from __future__ import annotations

import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CLEAN = ROOT / "tests" / "fixtures" / "clean_circuits"
MAL = ROOT / "tests" / "fixtures" / "malicious_circuits"
INDEX = Path(__file__).resolve().parent / "corpus_index.json"
PI = math.pi

HEADER = 'OPENQASM 2.0;\ninclude "qelib1.inc";\n'


def qasm(body: str) -> str:
    return HEADER + body


# ---------------------------------------------------------------- clean
def gen_clean() -> dict[str, str]:
    out: dict[str, str] = {}

    for n in [3, 4, 5, 6, 7, 8, 10, 12, 16, 20]:
        gates = "".join(f"cx q[{i}], q[{i + 1}];\n" for i in range(n - 1))
        out[f"gen_ghz_{n}qubit.qasm"] = qasm(
            f"qreg q[{n}];\ncreg c[{n}];\nh q[0];\n{gates}measure q -> c;\n"
        )

    for n in [4, 5, 6, 7, 8, 9]:
        gates = "".join(f"cx q[{i}], q[{i + 1}];\n" for i in range(n - 1))
        out[f"gen_cascade_{n}qubit.qasm"] = qasm(
            f"qreg q[{n}];\ncreg c[{n}];\nh q[0];\n{gates}measure q -> c;\n"
        )

    for n in [3, 4, 5, 6, 7, 8]:
        body = "".join(f"h q[{i}];\n" for i in range(n))
        for i in range(n - 1):
            body += f"cx q[{i}], q[{i + 1}];\nrz({0.5 + 0.1 * (n - 3):.3f}) q[{i + 1}];\ncx q[{i}], q[{i + 1}];\n"
        out[f"gen_ising_{n}qubit.qasm"] = qasm(
            f"qreg q[{n}];\ncreg c[{n}];\n{body}measure q -> c;\n"
        )

    for n in [2, 3, 5, 6, 7, 8]:
        body = "h q[0];\n"
        for i in range(n):
            body += f"h q[{i}];\n" if i else ""
            for j in range(i + 1, n):
                angle = PI / (2 ** (j - i))
                body += f"crz({angle:.16f}) q[{j}], q[{i}];\n"
        body += "".join(f"swap q[{i}], q[{n - 1 - i}];\n" for i in range(n // 2))
        out[f"gen_qft_{n}qubit.qasm"] = qasm(
            f"qreg q[{n}];\ncreg c[{n}];\n{body}measure q -> c;\n"
        )

    for n in [2, 3]:
        body = f"x q[{n - 1}];\n" + "".join(f"h q[{i}];\n" for i in range(n))
        for i in range(n - 1):
            body += f"cz q[{i}], q[{n - 1}];\n"
        out[f"gen_phase_estimation_{n}qubit.qasm"] = qasm(
            f"qreg q[{n}];\ncreg c[{n}];\n{body}measure q -> c;\n"
        )

    return out


# ------------------------------------------------------------ malicious
EXPECTED: dict[str, str] = {}


def gen_malicious() -> dict[str, str]:
    out: dict[str, str] = {}

    # micro-rotation flood (T1.1): seven variants, angles well below 0.01 rad
    for k in range(7):
        base = 0.002 + 0.0007 * k
        body = "h q[0];\n"
        for i in range(6):
            gate = "rx" if i % 2 == 0 else "rz"
            body += f"{gate}({base:.4f}) q[{i % 2}];\n"
            if i == 2:
                body += "cx q[0], q[1];\n"
        name = f"gen_micro_rot_{k}.qasm"
        out[name] = qasm(f"qreg q[2];\ncreg c[2];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T1.1"

    # steganographic payloads on the pi/4096 grid (T2.2)
    for payload in ["EXFILTRATE", "MALICIOUS", "TROJAN12", "EV1L!!", "K3RN3L", "SUPPLY"]:
        body = "h q[0];\n"
        for i, b in enumerate(payload.encode()):
            body += f"rz({b * PI / 4096:.18f}) q[{i % 4}];\n"
        body += "cx q[0], q[1];\n"
        name = f"gen_stego_{payload.encode().hex()}.qasm"
        out[name] = qasm(f"qreg q[4];\ncreg c[4];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T2.2"

    # cancelling identity pairs separated by unrelated-qubit gates (T1.3)
    pairs = [
        ("h", "h"),
        ("cx q[0], q[1]", "cx q[0], q[1]"),
        ("z", "z"),
        ("y", "y"),
        ("s", "sdg"),
        ("t", "tdg"),
    ]
    for k, (first, second) in enumerate(pairs):
        f = first if " " in first else f"{first} q[0]"
        s = second if " " in second else f"{second} q[0]"
        pair_qubits = {0, 1} if "q[1]" in first else {0}
        # intervening gates must not touch the pair's qubits (window rule)
        intervening = "h q[2];\ns q[2];\n" if pair_qubits == {0, 1} else "h q[2];\ns q[2];\ncx q[1], q[2];\n"
        body = f"{f};\n{intervening}{s};\n"
        name = f"gen_cancel_{k}.qasm"
        out[name] = qasm(f"qreg q[3];\ncreg c[3];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T1.3"

    # basis change immediately before measurement (T2.3)
    for k, gate in enumerate(["h", "x", "s", "sdg", "t", "y"]):
        body = f"h q[0];\ncx q[0], q[1];\n{gate} q[{k % 2}];\n"
        name = f"gen_basis_{k}_{gate}.qasm"
        out[name] = qasm(f"qreg q[2];\ncreg c[2];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T2.3"

    # ancilla leaf leakage (T2.1): fresh ancilla receives input, is measured
    for k, (gate, nq) in enumerate([("cx", 3), ("swap", 3), ("cx", 4), ("swap", 4), ("swap", 5)]):
        body = "h q[0];\n"
        body += "cx q[0], q[1];\n" if nq > 3 else ""
        body += f"{gate} q[0], q[{nq - 1}];\n"
        name = f"gen_leaf_{k}_{gate}{nq}.qasm"
        out[name] = qasm(f"qreg q[{nq}];\ncreg c[{nq}];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T2.1"

    return out


def main() -> int:
    clean = gen_clean()
    malicious = gen_malicious()

    for name, text in clean.items():
        (CLEAN / name).write_text(text)
    for name, text in malicious.items():
        (MAL / name).write_text(text)

    INDEX.write_text(json.dumps({"generated_malicious": EXPECTED}, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(clean)} clean + {len(malicious)} malicious generated fixtures")
    print(f"index → {INDEX}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
