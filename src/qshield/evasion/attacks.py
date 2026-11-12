"""Adversarial attack suite against the QSHIELD detection stack (M3.3).

Each attack transforms a malicious circuit in a way intended to dodge
detection.  Attacks fall into two families; only semantics-preserving
transforms are included (an attack that changes what the circuit *computes*
is not evasion, it is a different circuit):

* ``camouflage``      — insert identity pairs (s/sdg, t/tdg, h/h, cx/cx)
* ``synonyms``        — semantics-exact gate rewrites (e.g. ``s`` ->
  ``rz(pi/2)`` up to global phase, ``swap`` -> 3x cx, ``x`` -> h-z-h)
* ``rotation_split``  — ``rz(t)`` -> ``rz(t/2) rz(t/2)`` (exact)
* ``dead_code``       — append a random block A immediately followed by
                        its exact inverse A^dagger (an identity), doubling node
                        count to dilute mean-per-node anomaly scores
* ``qubit_relabel``   — apply a global qubit permutation to gates,
                        measurements AND classical bits consistently; preserves
                        Born-rule statistics up to classical-bit relabeling
                        (a graph-isomorphism attack)

Every attack is seeded and deterministic.  ``ATTACKS`` maps name -> spec;
``apply_attack`` dispatches.  All attacks preserve circuit semantics
exactly (up to global phase for the synonym rewrites, and up to classical
bit relabeling for qubit_relabel).
"""

from __future__ import annotations

import copy
import math
import random
from collections.abc import Callable
from typing import Any

from qshield.core.circuit_ir import CircuitIR, GateNode, GateType

ATTACK_NAMES = ("camouflage", "synonyms", "rotation_split", "dead_code", "qubit_relabel")

# ---------------------------------------------------------------------------
# synonym table: replacement gates are applied as exact identities
# ---------------------------------------------------------------------------
_SINGLE_REWRITES: dict[str, list[list[tuple[str, tuple[float, ...]]]]] = {
    # name: list of (sequence of (gate, params)) — global phase only
    "s": [[("rz", (math.pi / 2,))]],
    "sdg": [[("rz", (-math.pi / 2,))]],
    "t": [[("rz", (math.pi / 4,))]],
    "tdg": [[("rz", (-math.pi / 4,))]],
    "z": [[("s", ()), ("s", ())]],
    "x": [[("h", ()), ("z", ()), ("h", ())]],           # hzh = x (exact)
    "y": [[("s", ()), ("x", ()), ("sdg", ())]],        # s x sdg = y (exact)
}

_SPLIT_ROTATIONS = {"rz", "rx", "ry", "p", "u1"}


def _new_gate(ir_counter, name, qubits, params=()):
    return GateNode(gate_id=f"atk{ir_counter}", gate_name=name, gate_type=GateType.STANDARD,
                    qubits=list(qubits), parameters=list(params), unitary=None)


def attack_camouflage(ir: CircuitIR, *, k: int = 2, seed: int = 0) -> CircuitIR:
    """Insert k identity pairs (exact identity, any position)."""
    rng = random.Random(seed)  # noqa: S311 - benchmark determinism, not crypto
    gates = list(ir.gates)
    counter = [0]

    def fresh():
        counter[0] += 1
        return counter[0]

    for _ in range(k):
        q = rng.randrange(ir.num_qubits)
        pos = rng.randrange(len(gates) + 1)
        choice = rng.choice([("s", "sdg"), ("t", "tdg"), ("h", "h"), ("cx", "cx")])
        if choice[0] == "cx" and ir.num_qubits >= 2:
            q2 = rng.randrange(ir.num_qubits)
            while q2 == q:
                q2 = rng.randrange(ir.num_qubits)
            gates[pos:pos] = [_new_gate(fresh(), "cx", [q, q2]), _new_gate(fresh(), "cx", [q, q2])]
        else:
            gates[pos:pos] = [_new_gate(fresh(), choice[0], [q]), _new_gate(fresh(), choice[1], [q])]
    out = copy.copy(ir)
    out.gates = gates
    return out


def attack_synonyms(ir: CircuitIR, *, rate: float = 0.5, seed: int = 0) -> CircuitIR:
    """Rewrite single-gate ops with exact identities (global-phase tolerated).

    Two-qubit exact rewrites included:
      * ``swap(a, b)`` -> ``cx(a, b) cx(b, a) cx(a, b)``
      * ``cx(c, t)``   -> ``h(t) cz(c, t) h(t)``
    """
    rng = random.Random(seed)  # noqa: S311 - benchmark determinism, not crypto
    gates: list[GateNode] = []
    counter = [0]

    def fresh():
        counter[0] += 1
        return f"atk{counter[0]}"

    for gate in ir.gates:
        roll = rng.random()
        if gate.gate_name == "swap" and roll < rate:
            a, b = gate.qubits
            for qa, qb in ((a, b), (b, a), (a, b)):
                gates.append(GateNode(fresh(), "cx", GateType.STANDARD, [qa, qb], [], None))
            continue
        if gate.gate_name == "cx" and len(gate.qubits) == 2 and roll < rate:
            c, t = gate.qubits
            gates.append(GateNode(fresh(), "h", GateType.STANDARD, [t], [], None))
            gates.append(GateNode(fresh(), "cz", GateType.STANDARD, [c, t], [], None))
            gates.append(GateNode(fresh(), "h", GateType.STANDARD, [t], [], None))
            continue
        rewrite = _SINGLE_REWRITES.get(gate.gate_name)
        if rewrite and roll < rate:
            for name, params in rng.choice(rewrite):
                gates.append(GateNode(fresh(), name, GateType.STANDARD, list(gate.qubits),
                                      list(params), None))
            continue
        gates.append(copy.copy(gate))
    out = copy.copy(ir)
    out.gates = gates
    return out


def attack_rotation_split(ir: CircuitIR, *, rate: float = 0.5, seed: int = 0) -> CircuitIR:
    """Split parametrized rotations exactly in half: rz(t) -> rz(t/2) rz(t/2)."""
    rng = random.Random(seed)  # noqa: S311 - benchmark determinism, not crypto
    gates: list[GateNode] = []
    counter = [0]

    def fresh():
        counter[0] += 1
        return f"atk{counter[0]}"

    for gate in ir.gates:
        if gate.gate_name in _SPLIT_ROTATIONS and gate.parameters and rng.random() < rate:
            half = gate.parameters[0] / 2.0
            gates.append(GateNode(fresh(), gate.gate_name, GateType.STANDARD, list(gate.qubits),
                                  [half], None))
            gates.append(GateNode(fresh(), gate.gate_name, GateType.STANDARD, list(gate.qubits),
                                  [half], None))
        else:
            gates.append(copy.copy(gate))
    out = copy.copy(ir)
    out.gates = gates
    return out


def attack_dead_code(ir: CircuitIR, *, depth: int = 10, seed: int = 0) -> CircuitIR:
    """Append a random block A followed by its exact inverse (identity).

    Net semantics: identity — the circuit computes the same unitary.
    Node count roughly doubles with benign-looking Clifford structure,
    diluting mean-per-node anomaly scores.
    """
    rng = random.Random(seed)  # noqa: S311 - benchmark determinism, not crypto
    gates = list(ir.gates)
    counter = len(gates)
    _INVERSE = {"h": "h", "s": "sdg", "sdg": "s", "t": "tdg", "tdg": "t",
                "x": "x", "y": "y", "z": "z", "cx": "cx"}

    def fresh():
        nonlocal counter
        counter += 1
        return f"atk{counter}"

    block: list[GateNode] = []
    for _ in range(depth):
        name = rng.choice(list(_INVERSE))
        if name == "cx" and ir.num_qubits >= 2:
            q = rng.sample(range(ir.num_qubits), 2)
        else:
            q = [rng.randrange(ir.num_qubits)]
        block.append(GateNode(fresh(), name, GateType.STANDARD, q, [], None))
    inverse_block = [GateNode(fresh(), _INVERSE[g.gate_name], GateType.STANDARD,
                              list(g.qubits), [], None)
                     for g in reversed(block)]
    out = copy.copy(ir)
    out.gates = gates + block + inverse_block
    return out


def attack_qubit_relabel(ir: CircuitIR, *, seed: int = 0) -> CircuitIR:
    """Apply a global qubit permutation (consistent on gates + measurements)."""
    rng = random.Random(seed)  # noqa: S311 - benchmark determinism, not crypto
    perm = list(range(ir.num_qubits))
    rng.shuffle(perm)

    def remap(q: int) -> int:
        return perm[q]

    gates = [GateNode(g.gate_id, g.gate_name, g.gate_type, [remap(q) for q in g.qubits],
                      list(g.parameters), g.unitary) for g in ir.gates]
    if ir.num_classical_bits:
        measurements = [(remap(q), remap(c) if c < ir.num_classical_bits else c)
                        for (q, c) in ir.measurements]
    else:
        measurements = [(remap(q), c) for (q, c) in ir.measurements]
    out = copy.copy(ir)
    out.gates = gates
    out.measurements = measurements
    out.ancilla_qubits = [remap(q) for q in ir.ancilla_qubits]
    return out


ATTACKS: dict[str, tuple[Callable[..., CircuitIR], dict[str, Any]]] = {
    "camouflage": (attack_camouflage, {"k": 2, "seed": 0}),
    "synonyms": (attack_synonyms, {"rate": 0.5, "seed": 0}),
    "rotation_split": (attack_rotation_split, {"rate": 0.5, "seed": 0}),
    "dead_code": (attack_dead_code, {"depth": 10, "seed": 0}),
    "qubit_relabel": (attack_qubit_relabel, {"seed": 0}),
}


def apply_attack(ir: CircuitIR, name: str, **overrides) -> CircuitIR:
    if name not in ATTACKS:
        raise KeyError(f"unknown attack {name!r}; known: {sorted(ATTACKS)}")
    fn, defaults = ATTACKS[name]
    params = {**defaults, **overrides}
    return fn(ir, **params)
