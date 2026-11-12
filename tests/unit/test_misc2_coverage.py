"""Branch-coverage tests, batch 2 (scanner paths, formal hook, differential tester)."""

import sys
from types import SimpleNamespace

import numpy as np
import pytest

from qshield.core.circuit_ir import CircuitIR, GateNode, GateType
from qshield.core.parsers.qasm_parser import parse_qasm
from qshield.scanner import Scanner
from qshield.static.randomized_equivalence import (
    RandomizedVerificationError,
    apply_gates_to_state,
    randomized_equivalence,
)

BELL = """OPENQASM 2.0;
qreg q[2];
h q[0];
cx q[0], q[1];
"""


def _gate(name, qubits, params=(), unitary=None):
    return GateNode(
        gate_id=f"g_{name}_{abs(hash(str(qubits)))}",
        gate_name=name,
        gate_type=GateType.PARAMETERIZED if params else GateType.STANDARD,
        qubits=list(qubits),
        parameters=list(params),
        unitary=unitary,
    )


def _circuit(gates, num_qubits=2):
    return CircuitIR(
        circuit_id="coverage-test",
        name="coverage-test",
        num_qubits=num_qubits,
        num_classical_bits=0,
        gates=list(gates),
    )


def _basis(dim, index):
    state = np.zeros(dim, dtype=complex)
    state[index] = 1.0
    return state


# -- randomized_equivalence: gate DB fallback + error branches ---------------

def test_apply_gates_gate_db_fallback():
    gate = _gate("h", [0])  # unitary=None -> GATE_DB fallback path
    state = _basis(4, 0)
    out = apply_gates_to_state(state, _circuit([gate]))
    assert abs(out[0] - 1 / np.sqrt(2)) < 1e-9
    assert abs(out[2] - 1 / np.sqrt(2)) < 1e-9


def test_apply_gates_unknown_gate_raises():
    gate = _gate("definitely_not_a_gate_xyz", [0])
    with pytest.raises(RandomizedVerificationError, match="no known unitary"):
        apply_gates_to_state(_basis(4, 0), _circuit([gate]))


def test_verdict_and_summary_properties():
    a = parse_qasm(BELL)
    eq = randomized_equivalence(a, a, num_samples=2, seed=3)
    assert eq.verdict == "equivalent"
    assert "EQUIVALENT" in eq.summary()

    different = parse_qasm(BELL + "rz(0.7) q[0];\n")
    diff = randomized_equivalence(a, different, num_samples=4, seed=5)
    assert diff.verdict == "different"
    assert "DIFFERENT" in diff.summary()


def test_randomized_equivalence_qubit_limit():
    a = parse_qasm(BELL)
    with pytest.raises(RandomizedVerificationError, match="exceeds"):
        randomized_equivalence(a, a, num_samples=1, seed=1, max_qubits=1)


# -- differential tester: missing qiskit / unsupported gate / cu3 ------------

def test_aer_distribution_without_qiskit(monkeypatch):
    monkeypatch.setitem(sys.modules, "qiskit", None)
    from qshield.dynamic import differential_tester

    assert differential_tester.aer_distribution(parse_qasm(BELL), shots=8) is None


def test_aer_distribution_unknown_gate_returns_none():
    from qshield.dynamic.differential_tester import aer_distribution

    circuit = _circuit([_gate("bogus_gate_xyz", [0])], num_qubits=1)
    assert aer_distribution(circuit, shots=8) is None


def test_aer_distribution_cu3_gate():
    from qshield.dynamic.differential_tester import aer_distribution

    circuit = _circuit([_gate("cu3", [0, 1], [0.3, 0.2, 0.1])], num_qubits=2)
    counts = aer_distribution(circuit, shots=16)
    assert counts is not None
    assert sum(counts.values()) == 16


# -- property verifier hook ---------------------------------------------------

def test_verify_ancillas_independent_returns_report():
    from qshield.formal.property_verifier import verify_ancillas_independent

    circuit = parse_qasm("OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n")
    report = verify_ancillas_independent(circuit, [1])
    assert isinstance(report.leaks, bool)


# -- scanner: formal analysis path (pyzx present and absent) -----------------

def test_formal_enabled_pyzx_present(tmp_path):
    cfg = tmp_path / "formal_on.yaml"
    cfg.write_text("analysis:\n  formal: true\n")
    scanner = Scanner(config=str(cfg))
    scanner.add_circuit(BELL, name="bell")
    results = scanner.run()
    assert any("reference circuit" in w for w in results.warnings)


def test_formal_enabled_pyzx_missing(monkeypatch, tmp_path):
    monkeypatch.setattr("qshield.formal.pyzx_available", lambda: False)
    cfg = tmp_path / "formal_no_pyzx.yaml"
    cfg.write_text("analysis:\n  formal: true\n")
    scanner = Scanner(config=str(cfg))
    scanner.add_circuit(BELL, name="bell")
    results = scanner.run()
    assert any("pyzx is not installed" in w for w in results.warnings)


# -- scanner: misc branches ---------------------------------------------------

def test_scanner_backends_override():
    scanner = Scanner(config="default", backends=["qshield_numpy_statevector"])
    assert scanner.config.dynamic_backends == ["qshield_numpy_statevector"]


def test_metadata_merged_into_circuit():
    scanner = Scanner()
    scanner.add_circuit(BELL, name="bell", metadata={"origin": "unit-test"})
    assert scanner._circuits[0].metadata["origin"] == "unit-test"


def test_parse_any_fallback_to_parse_file(monkeypatch, tmp_path):
    qasm_file = tmp_path / "bell.qasm"
    qasm_file.write_text(BELL)
    monkeypatch.setattr(
        "qshield.scanner.parse_any",
        lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")),
    )
    scanner = Scanner()
    scanner.add_circuit(str(qasm_file), name="bell")  # falls back to parse_file
    assert len(scanner._circuits) == 1


def test_parse_any_fallback_failure_raises(monkeypatch):
    monkeypatch.setattr(
        "qshield.scanner.parse_any",
        lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")),
    )
    scanner = Scanner()
    with pytest.raises(ValueError, match="boom"):
        scanner.add_circuit(12345)  # not str/Path: no fallback possible


def test_timeout_skips_remaining_circuits():
    scanner = Scanner()
    scanner.add_circuit(BELL, name="bell-a")
    scanner.add_circuit(BELL, name="bell-b")
    results = scanner.run(analyses=["static"], timeout=-1)
    assert any("Timeout" in w for w in results.warnings)


def test_builtin_signature_load_failure(monkeypatch):
    def boom():
        raise RuntimeError("signature DB corrupt")

    monkeypatch.setattr("qshield.signatures.builtin_signatures", boom)
    scanner = Scanner()
    scanner.add_circuit(BELL, name="bell")
    results = scanner.run_quick()
    assert any("Failed to load builtin signatures" in w for w in results.warnings)


def test_explicit_ancilla_qubits_used():
    scanner = Scanner()
    scanner.add_circuit(BELL, name="bell")
    scanner._circuits[0].circuit.ancilla_qubits = [1]
    results = scanner.run_quick()
    assert results is not None  # exercises the explicit-ancilla branch


def test_dynamic_suspicious_backend_finding(monkeypatch, tmp_path):
    cfg = tmp_path / "dynamic_on.yaml"
    cfg.write_text("analysis:\n  dynamic: true\n")

    comparison = SimpleNamespace(
        suspicious=True,
        verdict="DIVERGENT",
        jensen_shannon=0.42,
        total_variation=0.7,
        chi_square_p=1e-12,
        kl_divergence=0.9,
    )
    fake_report = SimpleNamespace(
        compared=True,
        backend_a="qshield_numpy_statevector",
        backend_b="qiskit_aer",
        shots=16,
        comparison=comparison,
    )
    monkeypatch.setattr(
        "qshield.dynamic.differential_tester.DifferentialTester.cross_check_against_aer",
        lambda self, circuit: fake_report,
    )
    scanner = Scanner(config=str(cfg))
    scanner.add_circuit(BELL, name="bell")
    results = scanner.run()
    assert any(f.threat_type == "T3.3" for f in results.findings)


def test_add_package_without_version_runs():
    scanner = Scanner()
    scanner.add_package("definitely-not-a-real-pkg-xyz123")  # version defaults to 'latest'
    results = scanner.run_quick()
    assert results is not None
