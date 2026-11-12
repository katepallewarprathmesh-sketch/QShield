"""Deterministic generator for the QSHIELD benchmark fixture corpus.

Regenerates *generated* fixtures (prefix ``gen_``) into ``tests/fixtures/`` and a
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

    for n in [2, 3, 4, 5, 6]:
        body = f"x q[{n - 1}];\n" + "".join(f"h q[{i}];\n" for i in range(n))
        for i in range(n - 1):
            body += f"cz q[{i}], q[{n - 1}];\n"
        out[f"gen_phase_estimation_{n}qubit.qasm"] = qasm(
            f"qreg q[{n}];\ncreg c[{n}];\n{body}measure q -> c;\n"
        )

    import random

    # seeded random Clifford circuits (no parameters -> cannot trigger param rules)
    for k in range(25):
        rng = random.Random(20_000 + k)
        n = 4 + (k % 5)
        lines = [f"qreg q[{n}];", f"creg c[{n}];"]
        for _ in range(3 * n):
            gate = rng.choice(["h", "s", "x", "z"])
            lines.append(f"{gate} q[{rng.randrange(n)}];")
            if rng.random() < 0.6:
                a = rng.randrange(n)
                b = (a + 1 + rng.randrange(n - 1)) % n
                lines.append(f"cx q[{a}], q[{b}];")
        lines.append("measure q -> c;")
        out[f"gen_random_clifford_{k}.qasm"] = qasm("\n".join(lines) + "\n")

    # QAOA MaxCut-style ansätze with benign angles
    for k in range(16):
        rng = random.Random(30_000 + k)
        n = 4 + (k % 4)
        p = 1 + (k % 2)
        lines = [f"qreg q[{n}];", f"creg c[{n}];"] + [f"h q[{i}];" for i in range(n)]
        edges = [(i, (i + 1) % n) for i in range(n)]
        for _ in range(p):
            gamma = 0.4 + 0.1 * rng.random()
            beta = 0.2 + 0.1 * rng.random()
            for a, b in edges:
                lines.append(f"rzz({gamma:.4f}) q[{a}], q[{b}];")
            for i in range(n):
                lines.append(f"rx({beta:.4f}) q[{i}];")
        lines.append("measure q -> c;")
        out[f"gen_qaoa_{k}.qasm"] = qasm("\n".join(lines) + "\n")

    # repetition-code encode/syndrome pattern (Clifford-only)
    for k in range(10):
        n = 3 + 2 * (k % 4)  # 3, 5, 7, 9
        lines = [f"qreg q[{n}];", f"creg c[{n}];", "h q[0];"]
        lines += [f"cx q[0], q[{i}];" for i in range(1, n)]
        lines += ["measure q -> c;"]
        out[f"gen_repetition_{k}.qasm"] = qasm("\n".join(lines) + "\n")

    # dense Clifford ansätze (deep, high connectivity)
    for k in range(25):
        rng = random.Random(40_000 + k)
        n = 4 + (k % 4)
        lines = [f"qreg q[{n}];", f"creg c[{n}];"]
        for layer in range(4):
            lines += [f"h q[{i}];" for i in range(n)]
            for i in range(n - 1):
                if rng.random() < 0.8:
                    lines.append(f"cz q[{i}], q[{i + 1}];")
            lines.append(f"s q[{layer % n}];")
        lines.append("measure q -> c;")
        out[f"gen_dense_clifford_{k}.qasm"] = qasm("\n".join(lines) + "\n")

    # Bell ladders with Pauli flips
    for k in range(20):
        n = 3 + (k % 8)
        lines = [f"qreg q[{n}];", f"creg c[{n}];", "h q[0];"]
        lines += [f"cx q[{i}], q[{i + 1}];" for i in range(n - 1)]
        lines += [f"{chr(120 + (k % 3))} q[{k % n}];"]  # x/y/z flip
        lines.append("measure q -> c;")
        out[f"gen_bell_ladder_{k}.qasm"] = qasm("\n".join(lines) + "\n")

    # GHZ swapped orientation variants
    for n in [4, 6, 8, 10, 12, 14, 18, 24]:
        lines = [f"qreg q[{n}];", f"creg c[{n}];", f"h q[{n - 1}];"]
        lines += [f"cx q[{i}], q[{i - 1}];" for i in range(n - 1, 0, -1)]
        lines.append("measure q -> c;")
        out[f"gen_ghz_rev_{n}qubit.qasm"] = qasm("\n".join(lines) + "\n")

    # QAOA at higher depth with benign angles
    for k in range(15):
        rng = random.Random(60_000 + k)
        n = 4 + (k % 3)
        lines = [f"qreg q[{n}];", f"creg c[{n}];"] + [f"h q[{i}];" for i in range(n)]
        for _ in range(3):
            gamma = 0.3 + 0.2 * rng.random()
            beta = 0.15 + 0.15 * rng.random()
            for i in range(n):
                lines.append(f"rzz({gamma:.4f}) q[{i}], q[{(i + 1) % n}];")
            lines += [f"rx({beta:.4f}) q[{i}];" for i in range(n)]
        lines.append("measure q -> c;")
        out[f"gen_qaoa_hi_{k}.qasm"] = qasm("\n".join(lines) + "\n")

    # GHZ-style with cz chains (CZ-connected graphs)
    for k in range(20):
        n = 4 + (k % 6)
        lines = [f"qreg q[{n}];", f"creg c[{n}];", f"h q[{k % n}];"]
        lines += [f"cz q[{i}], q[{(i + 2) % n}];" for i in range(n)]
        lines.append("measure q -> c;")
        out[f"gen_ghz_cz_{k}.qasm"] = qasm("\n".join(lines) + "\n")

    # phase estimation with y-before-cz structure
    for k in range(10):
        n = 3 + (k % 3)
        body = "h q[0];\n" + "".join(f"h q[{i}];\n" for i in range(n))
        for i in range(n - 1):
            body += f"crz({PI / (2 ** (i + 1)):.16f}) q[{n - 1}], q[{i}];\n"
        lines = [f"qreg q[{n}];", f"creg c[{n}];", body + "measure q -> c;"]
        out[f"gen_qpe_cz_{k}.qasm"] = qasm("\n".join(lines) + "\n")

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

    # micro-rotation flood, wider qubit spread (T1.1)
    for k in range(20):
        n = 4
        base = 0.0012 + 0.0004 * k
        body = "h q[0];\n"
        for i in range(8):
            gate = ["rx", "ry", "rz"][i % 3]
            body += f"{gate}({base:.4f}) q[{i % n}];\n"
            if i == 3:
                body += "cx q[0], q[2];\n"
        name = f"gen_micro_rot2_{k}.qasm"
        out[name] = qasm(f"qreg q[{n}];\ncreg c[{n}];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T1.1"

    # micro-rotation with dense entanglement (T1.1)
    for k in range(15):
        n = 3
        base = 0.003 + 0.0004 * k
        body = "h q[0];\n" + "cx q[0], q[1];\n" + "cx q[1], q[2];\n"
        for i in range(6):
            body += f"rz({base:.4f}) q[{i % n}];\n"
        name = f"gen_micro_ent_{k}.qasm"
        out[name] = qasm(f"qreg q[{n}];\ncreg c[{n}];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T1.1"

    # steganographic payloads, longer messages (T2.2)
    import random

    rng = random.Random(50_000)
    for k in range(20):
        payload = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for _ in range(12))
        body = "h q[0];\n"
        for i, b in enumerate(payload.encode()):
            body += f"rz({b * PI / 4096:.16f}) q[{i % 4}];\n"
        body += "cx q[0], q[3];\n"
        name = f"gen_stego2_{k}.qasm"
        out[name] = qasm(f"qreg q[4];\ncreg c[4];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T2.2"

    # separated cancelling pairs on qubit 1/2 (T1.3)
    for k in range(10):
        body = f"h q[1];\ncx q[0], q[2];\nh q[2];\ns q[2];\nh q[1];\n"
        name = f"gen_cancel3_{k}.qasm"
        out[name] = qasm(f"qreg q[3];\ncreg c[3];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T1.3"

    # cancelling pairs with sdg/tdg/cx on qubit 0 (T1.3)
    pair_sets = [
        ("sdg q[0]", "s q[0]"),
        ("tdg q[0]", "t q[0]"),
        ("x q[0]", "x q[0]"),
        ("y q[0]", "y q[0]"),
        ("cx q[0], q[1]", "cx q[0], q[1]"),
    ]
    for k in range(15):
        first, second = pair_sets[k % len(pair_sets)]
        intervening = "h q[2];\ns q[2];\n"
        body = f"{first};\n{intervening}{second};\n"
        name = f"gen_cancel4_{k}.qasm"
        out[name] = qasm(f"qreg q[3];\ncreg c[3];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T1.3"

    # fanout shadow channels: one ancilla collecting input (T2.1)
    for k in range(15):
        nq = 3 + (k % 3)
        body = "h q[0];\nh q[1];\n"
        for i in range(1, nq - 1):
            body += f"cx q[{i - 1}], q[{i}];\n"
        body += f"cx q[{nq - 2}], q[{nq - 1}];\n"
        name = f"gen_fanout_{k}.qasm"
        out[name] = qasm(f"qreg q[{nq}];\ncreg c[{nq}];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T2.1"

    # basis change immediately before measurement (T2.3)
    for k in range(10):
        gate = ["h", "y", "s", "sdg", "t", "tdg"][k % 6]
        body = f"h q[0];\ncx q[0], q[1];\n{gate} q[{k % 2}];\n"
        name = f"gen_basis2_{k}_{gate}.qasm"
        out[name] = qasm(f"qreg q[2];\ncreg c[2];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T2.3"

    # micro-rotation along a cx chain (T1.1)
    for k in range(20):
        n = 3
        base = 0.0025 + 0.00035 * k
        body = "h q[0];\n" + "cx q[0], q[1];\n" + "cx q[1], q[2];\n"
        for i in range(6):
            body += f"rx({base:.4f}) q[{i % n}];\n"
        name = f"gen_micro3_{k}.qasm"
        out[name] = qasm(f"qreg q[{n}];\ncreg c[{n}];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T1.1"

    # short ASCII stego payloads (T2.2)
    for k, payload in enumerate(["ABCDEF", "TROJAN", "EXFIL1", "SECRET7", "PASS99", "ROOTK1", "SHELLS", "HACKED1", "INJECT9", "SPY123", "STEALTH", "BACKDOOR", "EXPLO1T", "CRYPTOX", "MZEROTH"]):
        body = "h q[0];\n"
        for i, b in enumerate(payload.encode()):
            body += f"rz({b * PI / 4096:.16f}) q[{i % 4}];\n"
        body += "cx q[0], q[2];\n"
        name = f"gen_stego3_{k}.qasm"
        out[name] = qasm(f"qreg q[4];\ncreg c[4];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T2.2"

    # separated cancelling pairs on qubit 1 (T1.3)
    for k in range(15):
        first, second = [("x q[1]", "x q[1]"), ("s q[1]", "sdg q[1]"), ("y q[1]", "y q[1]")][k % 3]
        body = f"h q[0];\n{first};\ncz q[0], q[2];\n{second};\nh q[2];\n"
        name = f"gen_cancel5_{k}.qasm"
        out[name] = qasm(f"qreg q[3];\ncreg c[3];\n{body}measure q -> c;\n")
        EXPECTED[name.removesuffix(".qasm")] = "T1.3"

    # fanout via cz chains to a measured ancilla (T2.1)
    for k in range(10):
        n = 3 + (k % 2)
        body = "h q[0];\n"
        for i in range(n - 2):
            body += f"cz q[{i}], q[{i + 1}];\n"
        body += f"cx q[{n - 2}], q[{n - 1}];\n"
        name = f"gen_fanout2_{k}.qasm"
        out[name] = qasm(f"qreg q[{n}];\ncreg c[{n}];\n{body}measure q -> c;\n")
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
