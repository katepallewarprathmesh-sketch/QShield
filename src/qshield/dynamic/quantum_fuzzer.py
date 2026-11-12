"""Mutation-based quantum circuit fuzzer (spec M2.3).

Mutations operate on :class:`CircuitIR` and are split into two families:

* **semantics-breaking** — gate deletion, parameter perturbation, gate
  replacement, qubit permutation: change what the circuit computes
* **semantics-preserving-ish camouflage** — identity-pair insertion, benign
  gate insertion: attempt to hide a circuit from the analyzer

``CircuitFuzzer`` samples mutants from a base circuit, evaluates them with a
caller-supplied (or default static-analysis) evaluator, and keeps a corpus of
mutants that exercise *new coverage buckets* — finding categories or the
``clean`` bucket — atheris-style.  Exceptions raised while analysing a mutant
are recorded as **crashes** (they should not happen; each one is a bug).

``fuzz_input_states`` implements the "random input state preparation" axis:
Haar-random initial statevectors executed through the sandbox, for circuits
whose behaviour should depend smoothly on the input.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass

import numpy as np

from qshield.core.circuit_ir import CircuitIR, GateNode, GateType
from qshield.core.gate_database import GATE_DB

# pools used by mutation operators
_SINGLE_QUBIT_POOL = ["h", "x", "y", "z", "s", "sdg", "t", "tdg"]
_ROTATION_POOL = ["rx", "ry", "rz"]
_TWO_QUBIT_POOL = ["cx", "cz"]
_IDENTITY_PAIRS = [("s", "sdg"), ("t", "tdg"), ("h", "h")]


@dataclass
class MutationRecord:
    operator: str
    detail: str


@dataclass
class MutantResult:
    mutant: CircuitIR
    mutations: list[MutationRecord]
    buckets: set[str]
    num_findings: int
    error: str | None = None

    def mutation_summary(self) -> str:
        return "; ".join(f"{m.operator}({m.detail})" for m in self.mutations)


@dataclass
class FuzzReport:
    base_name: str
    iterations: int
    num_mutants: int
    crashes: list[tuple[str, str]]                # (mutation summary, error)
    coverage: dict[str, int]                      # bucket -> times exercised
    corpus_size: int                              # mutants kept for new coverage
    clean_bucket_hits: int = 0

    def to_dict(self) -> dict:
        return {
            "base_name": self.base_name,
            "iterations": self.iterations,
            "num_mutants": self.num_mutants,
            "crashes": [{"mutation": m, "error": e} for m, e in self.crashes],
            "coverage": dict(sorted(self.coverage.items())),
            "corpus_size": self.corpus_size,
            "clean_bucket_hits": self.clean_bucket_hits,
        }


def _clone_gate(gate: GateNode, **changes) -> GateNode:
    data = dict(gate.__dict__)
    data.update(changes)
    return GateNode(**data)


def _fresh_circuit(base: CircuitIR, gates: list[GateNode], measurements, ancillas, tag: str) -> CircuitIR:
    return CircuitIR(
        circuit_id=f"mut-{uuid.uuid4().hex[:12]}",
        name=f"{base.name}#{tag}",
        num_qubits=base.num_qubits,
        num_classical_bits=base.num_classical_bits,
        gates=gates,
        dag=_rebuild_dag(gates),
        measurements=list(measurements),
        ancilla_qubits=list(ancillas),
        source_framework=base.source_framework,
        source_hash=base.source_hash,
        metadata={**base.metadata, "mutation": tag},
    )


def _rebuild_dag(gates: list[GateNode]) -> dict[str, list[str]]:
    dag: dict[str, list[str]] = {}
    last_on_qubit: dict[int, str] = {}
    for g in gates:
        preds = {last_on_qubit[q] for q in g.qubits if q in last_on_qubit}
        for p in preds:
            dag.setdefault(p, []).append(g.gate_id)
        for q in g.qubits:
            last_on_qubit[q] = g.gate_id
    return dag


def _new_gate(name: str, qubits: list[int], params: list[float] | None = None) -> GateNode:
    params = list(params or [])
    gate_type = GateType.PARAMETERIZED if params else GateType.STANDARD
    unitary = GATE_DB.matrix(name, params) if GATE_DB.has(name) else None
    return GateNode(
        gate_id=f"fz-{uuid.uuid4().hex[:10]}",
        gate_name=name,
        gate_type=gate_type,
        qubits=list(qubits),
        parameters=params,
        unitary=unitary,
    )


# ----------------------------------------------------------------------
# mutation operators: (circuit, rng) -> (mutant, record) | None
# ----------------------------------------------------------------------

def mutate_gate_deletion(circuit: CircuitIR, rng: np.random.Generator):
    if not circuit.gates:
        return None
    idx = int(rng.integers(len(circuit.gates)))
    record = MutationRecord("gate_deletion", f"removed {circuit.gates[idx].gate_name} at {idx}")
    gates = [g for i, g in enumerate(circuit.gates) if i != idx]
    return _fresh_circuit(circuit, gates, circuit.measurements, circuit.ancilla_qubits, "del"), record


def mutate_gate_insertion(circuit: CircuitIR, rng: np.random.Generator):
    n = circuit.num_qubits
    if n == 0:
        return None
    use_two = n >= 2 and rng.random() < 0.35
    if use_two:
        qs = list(rng.choice(n, size=2, replace=False))
        gate = _new_gate(str(rng.choice(_TWO_QUBIT_POOL)), [int(qs[0]), int(qs[1])])
    else:
        gate = _new_gate(str(rng.choice(_SINGLE_QUBIT_POOL)), [int(rng.integers(n))])
    idx = int(rng.integers(len(circuit.gates) + 1))
    gates = [*circuit.gates[:idx], gate, *circuit.gates[idx:]]
    record = MutationRecord("gate_insertion", f"inserted {gate.gate_name} at {idx}")
    return _fresh_circuit(circuit, gates, circuit.measurements, circuit.ancilla_qubits, "ins"), record


def mutate_parameter_perturbation(circuit: CircuitIR, rng: np.random.Generator):
    candidates = [i for i, g in enumerate(circuit.gates)
                  if g.parameters and GATE_DB.has(g.gate_name)]
    if not candidates:
        return None
    idx = candidates[int(rng.integers(len(candidates)))]
    gate = circuit.gates[idx]
    params = list(gate.parameters)
    j = int(rng.integers(len(params)))
    scale = 1.0 + rng.uniform(-0.1, 0.1)
    params[j] = params[j] * scale + rng.uniform(-1e-3, 1e-3)
    record = MutationRecord("parameter_perturbation", f"gate {idx} {gate.gate_name} param{j} -> {params[j]:.6f}")
    new_gate = _clone_gate(gate, parameters=params, unitary=None)
    gates = [*circuit.gates[:idx], new_gate, *circuit.gates[idx + 1:]]
    return _fresh_circuit(circuit, gates, circuit.measurements, circuit.ancilla_qubits, "param"), record


def mutate_qubit_permutation(circuit: CircuitIR, rng: np.random.Generator):
    n = circuit.num_qubits
    if n < 2:
        return None
    a, b = (int(x) for x in rng.choice(n, size=2, replace=False))
    gates = []
    for g in circuit.gates:
        new_qubits = [a if q == b else (b if q == a else q) for q in g.qubits]
        gates.append(_clone_gate(g, qubits=new_qubits))
    measurements = [(a if q == b else (b if q == a else q), c) for q, c in circuit.measurements]
    ancillas = [a if q == b else (b if q == a else q) for q in circuit.ancilla_qubits]
    record = MutationRecord("qubit_permutation", f"swapped qubits {a}<->{b}")
    return _fresh_circuit(circuit, gates, measurements, ancillas, "perm"), record


def mutate_gate_replacement(circuit: CircuitIR, rng: np.random.Generator):
    if not circuit.gates:
        return None
    idx = int(rng.integers(len(circuit.gates)))
    gate = circuit.gates[idx]
    if len(gate.qubits) == 1:
        replacement = str(rng.choice([g for g in _SINGLE_QUBIT_POOL if g != gate.gate_name]))
        new_gate = _clone_gate(gate, gate_name=replacement, parameters=[], unitary=None,
                               gate_type=GateType.STANDARD)
    elif len(gate.qubits) == 2 and GATE_DB.has(gate.gate_name):
        replacement = str(rng.choice([g for g in _TWO_QUBIT_POOL if g != gate.gate_name]))
        new_gate = _clone_gate(gate, gate_name=replacement, parameters=[], unitary=None,
                               gate_type=GateType.STANDARD)
    else:
        return None
    record = MutationRecord("gate_replacement", f"gate {idx} {gate.gate_name} -> {replacement}")
    gates = [*circuit.gates[:idx], new_gate, *circuit.gates[idx + 1:]]
    return _fresh_circuit(circuit, gates, circuit.measurements, circuit.ancilla_qubits, "repl"), record


def mutate_identity_pair_insertion(circuit: CircuitIR, rng: np.random.Generator):
    n = circuit.num_qubits
    if n < 1:
        return None
    first, second = _IDENTITY_PAIRS[int(rng.integers(len(_IDENTITY_PAIRS)))]
    q = int(rng.integers(n))
    gate1 = _new_gate(first, [q])
    gate2 = _new_gate(second, [q])
    idx = int(rng.integers(len(circuit.gates) + 1))
    gates = [*circuit.gates[:idx], gate1, gate2, *circuit.gates[idx:]]
    record = MutationRecord("identity_pair_insertion", f"inserted {first}+{second} at {idx}")
    return _fresh_circuit(circuit, gates, circuit.measurements, circuit.ancilla_qubits, "pair"), record


MUTATORS: dict[str, Callable[[CircuitIR, np.random.Generator], tuple[CircuitIR, MutationRecord] | None]] = {
    "gate_deletion": mutate_gate_deletion,
    "gate_insertion": mutate_gate_insertion,
    "parameter_perturbation": mutate_parameter_perturbation,
    "qubit_permutation": mutate_qubit_permutation,
    "gate_replacement": mutate_gate_replacement,
    "identity_pair_insertion": mutate_identity_pair_insertion,
}


# ----------------------------------------------------------------------
# input-state fuzzing ("random input state preparation")
# ----------------------------------------------------------------------

def random_statevector(num_qubits: int, rng: np.random.Generator) -> np.ndarray:
    """Haar-random normalized statevector (complex Gaussian, normalized)."""
    dim = 1 << num_qubits
    vec = rng.standard_normal(dim) + 1j * rng.standard_normal(dim)
    return vec / np.linalg.norm(vec)


def fuzz_input_states(circuit: CircuitIR, num_states: int = 8, seed: int = 1234) -> list:
    """Execute ``circuit`` from Haar-random input states.

    Returns a list of ExecutionResults — one per random initial state —
    for probing circuits whose behaviour should vary smoothly with input.
    """
    from qshield.dynamic.sandbox_executor import SandboxExecutor

    rng = np.random.default_rng(seed)
    executor = SandboxExecutor()
    results = []
    for _ in range(num_states):
        state = random_statevector(circuit.num_qubits, rng)
        results.append(executor.run(circuit, initial_state=state, rng=rng))
    return results


# ----------------------------------------------------------------------
# coverage-guided fuzzing loop
# ----------------------------------------------------------------------

def _default_evaluate(ir: CircuitIR):
    """Static-analysis findings for a mutant (default evaluator)."""
    from qshield.scanner import Scanner

    scanner = Scanner(config="default", signatures="builtin")
    scanner.add_circuit(ir, name=ir.name)
    return scanner.run_quick().findings


class CircuitFuzzer:
    """Coverage-guided mutational fuzzer for quantum circuits."""

    def __init__(self, base: CircuitIR, seed: int = 1234, max_mutations_per_mutant: int = 2,
                 corpus_limit: int = 64, operators: list[str] | None = None):
        self.base = base
        self.rng = np.random.default_rng(seed)
        self.max_mutations = max_mutations_per_mutant
        self.corpus_limit = corpus_limit
        self.operators = operators or sorted(MUTATORS)
        self.coverage: dict[str, int] = {}
        self.corpus: list[MutantResult] = []
        self.crashes: list[tuple[str, str]] = []

    # ------------------------------------------------------------------
    def mutate(self):
        mutant = self.base
        records: list[MutationRecord] = []
        for _ in range(int(self.rng.integers(1, self.max_mutations + 1))):
            op = self.rng.choice(self.operators)
            applied = MUTATORS[op](mutant, self.rng)
            if applied is None:
                continue
            mutant, record = applied
            records.append(record)
        return mutant, records

    # ------------------------------------------------------------------
    def fuzz(self, iterations: int = 50, evaluate=None) -> FuzzReport:
        evaluate = evaluate or _default_evaluate
        for _ in range(iterations):
            mutant, records = self.mutate()
            if not records:
                continue
            try:
                findings = evaluate(mutant)
            except Exception as exc:  # fuzz crashes are bugs — record, don't hide
                self.crashes.append(("; ".join(f"{m.operator}" for m in records), f"{type(exc).__name__}: {exc}"))
                continue
            buckets = {f.threat_type for f in findings} or {"clean"}
            novel = {b for b in buckets if b not in self.coverage}
            for b in buckets:
                self.coverage[b] = self.coverage.get(b, 0) + 1
            if novel and len(self.corpus) < self.corpus_limit:
                self.corpus.append(MutantResult(mutant, records, set(buckets), len(findings)))
        clean = self.coverage.get("clean", 0)
        return FuzzReport(
            base_name=self.base.name,
            iterations=iterations,
            num_mutants=iterations,
            crashes=list(self.crashes),
            coverage=dict(self.coverage),
            corpus_size=len(self.corpus),
            clean_bucket_hits=clean,
        )
