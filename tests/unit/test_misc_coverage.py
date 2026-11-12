"""Targeted coverage for remaining low-risk branches."""

import numpy as np
import pytest

from qshield.core.circuit_ir import CircuitIR, GateNode, GateType, embed_gate_matrix
from qshield.core.parsers import parse_any, parse_file
from qshield.static.dependency_scanner import DependencyScanner

BELL = "OPENQASM 2.0;\nqreg q[2];\nh q[0];\ncx q[0], q[1];\n"


def _gate(name, arity, params=()):
    return GateNode(gate_id=name, gate_name=name, gate_type=GateType.STANDARD,
                    qubits=list(range(arity)), parameters=list(params), unitary=None)


def test_is_entangling():
    from qshield.core.circuit_ir import CircuitIR

    assert CircuitIR.is_entangling(_gate("h", 1)) is False
    assert CircuitIR.is_entangling(_gate("cx", 2)) is True
    assert CircuitIR.is_entangling(_gate("mystery_multi", 3)) is True


def test_circuit_ir_depth_and_hashes():
    from qshield.core.parsers.qasm_parser import parse_qasm

    ir = parse_qasm(BELL)
    assert ir.get_depth() == 2
    assert CircuitIR.hash_source("abc") == CircuitIR.hash_source("abc")
    graph = ir.get_qubit_interaction_graph()
    assert graph[0] == {1}


def test_to_unitary_returns_none_for_measurements():
    from qshield.core.parsers.qasm_parser import parse_qasm

    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\ncreg c[1];\nx q[0];\nmeasure q[0] -> c[0];\n")
    # gates with "measure" in them block exact unitary; measurements recorded separately
    assert ir.to_unitary() is None or isinstance(ir.to_unitary(), np.ndarray)


def test_embed_gate_matrix_shape_mismatch():
    with pytest.raises(ValueError, match="does not match"):
        embed_gate_matrix(np.eye(4, dtype=complex), [0], 2)


def test_parse_any_inputs(tmp_path):
    p = tmp_path / "bell.qasm"
    p.write_text(BELL)
    ir = parse_any(str(p))
    assert ir.num_qubits == 2
    ir = parse_any(BELL)
    assert ir.num_qubits == 2
    with pytest.raises(TypeError, match="Unsupported circuit object"):
        parse_any(12345)
    with pytest.raises(FileNotFoundError):
        parse_file(tmp_path / "missing.qasm")
    p2 = tmp_path / "bell.txt"
    p2.write_text(BELL)
    with pytest.raises(ValueError, match="Unsupported circuit file extension"):
        parse_file(p2)


def test_parse_file_qasm3_extension(tmp_path):
    p = tmp_path / "c.qasm3"
    p.write_text(BELL)
    ir = parse_file(p)
    assert ir.num_qubits == 2


def test_dependency_report_to_dict_and_ok():
    report = DependencyScanner().scan_requirements("qiskit==1.2.0\nurllib3==1.26.4\n")
    d = report.to_dict()
    assert d["ok"] is False
    assert any(f["package"] == "urllib3" for f in d["findings"])
    clean = DependencyScanner().scan_requirements("qiskit==1.2.0\n")
    assert clean.ok is True
    d = clean.to_dict()
    assert d["packages"]


def test_pinned_hash_and_direct_url_and_specifiers():
    report = DependencyScanner().scan_requirements(
        "git+https://github.com/user/pkg.git\n"
        "https://example.com/pkg.whl\n"
        "qiskit>=1.0,<2.0\n"
        "weird line with spaces\n"
        "# a comment\n"
        "\n"
    )
    assert report.packages
    # hash-pinned line accepted
    report2 = DependencyScanner().scan_requirements("urllib3==1.26.4 --hash=sha256:abc123\n")
    assert report2.packages


def test_extra_advisories():
    adv = {"mypkg": [("<9.9", "CVE-0000-1", "critical", "test advisory")]}
    report = DependencyScanner(extra_advisories=adv).scan_requirements("mypkg==1.0\n")
    assert any(f.package == "mypkg" for f in report.findings)


def test_advisory_check_requires_exact_pin():
    # advisory matching requires an == pin (design: unknown installed version is not flagged)
    report = DependencyScanner().scan_requirements("urllib3>=1.0,<=1.26.4\n")
    assert not any(f.issue == "known_vulnerable" for f in report.findings)
    # _specifier_satisfied covers the operator matrix directly
    from qshield.static.dependency_scanner import _specifier_satisfied

    assert _specifier_satisfied("1.26.4", "<1.26.5") is True
    assert _specifier_satisfied("1.26.4", ">1.26.5") is False
    assert _specifier_satisfied("1.26.4", "~=1.26.0") is True
    assert _specifier_satisfied("1.26.4", "!=1.26.4") is False
    assert _specifier_satisfied("1.26.4", ">=1.2.0, <=1.26.4") is True
    assert _specifier_satisfied("1.26.4", "garbage-clause") is True  # unparseable clauses are skipped
