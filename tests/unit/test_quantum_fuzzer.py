"""M2.3: mutation operators, input-state fuzzing, coverage-guided loop."""

import numpy as np
import pytest

from qshield.core.circuit_ir import CircuitIR
from qshield.core.parsers import parse_qasm
from qshield.dynamic.quantum_fuzzer import (
    MUTATORS,
    CircuitFuzzer,
    fuzz_input_states,
    mutate_qubit_permutation,
    random_statevector,
)

BELL = "OPENQASM 2.0;\nqreg q[2];\ncreg c[2];\nh q[0];\ncx q[0], q[1];\nmeasure q -> c;\n"
RX = "OPENQASM 2.0;\nqreg q[1];\nrx(0.5) q[0];\n"


def _assert_dag_consistent(ir):
    ids = {g.gate_id for g in ir.gates}
    assert set(ir.dag) <= ids
    for targets in ir.dag.values():
        assert set(targets) <= ids


MIXED = "OPENQASM 2.0;\nqreg q[2];\ncreg c[2];\nh q[0];\nrx(0.5) q[0];\ncx q[0], q[1];\n"


def test_every_mutator_produces_valid_circuit():
    ir = parse_qasm(MIXED)
    for name, op in MUTATORS.items():
        rng = np.random.default_rng(0)
        applied = None
        for _ in range(20):  # some ops can legitimately decline (None)
            applied = op(ir, rng)
            if applied is not None:
                break
        assert applied is not None, f"{name} never applied"
        mutant, record = applied
        assert isinstance(mutant, CircuitIR)
        assert mutant.num_qubits == ir.num_qubits
        assert record.operator == name
        _assert_dag_consistent(mutant)


def test_parameter_perturbation_invalidates_embedded_unitary():

    ir = parse_qasm(RX)
    gate = ir.gates[0]
    assert gate.unitary is not None  # parsers embed known-gate matrices
    from qshield.dynamic.quantum_fuzzer import mutate_parameter_perturbation

    out, _record = mutate_parameter_perturbation(ir, np.random.default_rng(5))
    assert out.gates[0].unitary is None  # stale matrix dropped after perturbation
    assert out.gates[0].parameters[0] != pytest.approx(0.5)


def test_qubit_permutation_remaps_measurements():
    ir = parse_qasm(BELL)
    rng = np.random.default_rng(11)
    for _ in range(10):
        out, _record = mutate_qubit_permutation(ir, rng)
        swapped = {0 if q == 1 else 1 for q in (0, 1)}
        for q, _ in out.measurements:
            assert q in swapped
        _assert_dag_consistent(out)


def test_fuzz_deterministic_under_seed():
    ir = parse_qasm(BELL)
    r1 = CircuitFuzzer(ir, seed=7).fuzz(iterations=15)
    r2 = CircuitFuzzer(ir, seed=7).fuzz(iterations=15)
    assert r1.coverage == r2.coverage
    assert r1.corpus_size == r2.corpus_size


def test_fuzz_records_crashes_without_raising():
    ir = parse_qasm(BELL)

    def boom(mutant):
        raise RuntimeError("analyzer exploded")

    report = CircuitFuzzer(ir, seed=3).fuzz(iterations=8, evaluate=boom)
    assert len(report.crashes) == 8
    assert all("analyzer exploded" in err for _, err in report.crashes)


def test_fuzz_coverage_and_corpus_novelty():
    ir = parse_qasm(BELL)
    calls = {"n": 0}

    def fake_evaluate(mutant):
        calls["n"] += 1
        threat = "T9.9" if calls["n"] % 2 else "T8.8"
        finding = type("F", (), {"threat_type": threat})()
        return [finding]

    fuzzer = CircuitFuzzer(ir, seed=13)
    report = fuzzer.fuzz(iterations=10, evaluate=fake_evaluate)
    assert report.coverage.get("T9.9", 0) >= 1
    assert report.coverage.get("T8.8", 0) >= 1
    # corpus holds only mutants introducing NEW buckets: T9.9 and T8.8 -> 2 kept
    assert report.corpus_size == 2


def test_fuzz_no_crashes_on_small_corpus_fixtures():
    from pathlib import Path

    base = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
    samples = [base / "clean_circuits" / "bell_state.qasm",
               base / "malicious_circuits" / "ancilla_leakage.qasm"]
    for path in samples:
        ir = parse_qasm(path.read_text())
        report = CircuitFuzzer(ir, seed=99).fuzz(iterations=10)
        assert report.crashes == [], f"{path.name}: analyzer crashed on mutants: {report.crashes}"


def test_random_statevector_normalized():
    vec = random_statevector(3, np.random.default_rng(2))
    assert vec.shape == (8,)
    assert np.linalg.norm(vec) == pytest.approx(1.0)


def test_fuzz_input_states_runs_and_normalizes():
    ir = parse_qasm(BELL.replace("measure q -> c;", ""))
    results = fuzz_input_states(ir, num_states=4, seed=17)
    assert len(results) == 4
    for res in results:
        assert np.linalg.norm(res.final_state) == pytest.approx(1.0, abs=1e-9)
