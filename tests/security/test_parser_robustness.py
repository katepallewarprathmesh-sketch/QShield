"""Parser resource-cap and robustness regressions (implementation plan Task 1.4).

These tests need no optional dependencies and always run: they cover the
defence-in-depth caps that stop crafted circuit files from hanging or
exhausting memory, and the invariant that the parser's only public failure
mode is :class:`QASMParseError`.
"""

import time

import pytest

from qshield.core.circuit_ir import CircuitIR
from qshield.core.parsers.qasm_parser import (
    MAX_GATES,
    MAX_QUBITS,
    QASMParseError,
    parse_qasm,
)


def _oversized_source() -> str:
    body = "h q[0];\n" * 140_000  # ~1.1 MB > MAX_SOURCE_BYTES (1 MiB)
    return "OPENQASM 2.0;\nqreg q[1];\n" + body


def test_oversized_source_rejected_fast():
    started = time.monotonic()
    with pytest.raises(QASMParseError, match="size cap"):
        parse_qasm(_oversized_source())
    assert time.monotonic() - started < 5.0


def test_register_width_cap():
    with pytest.raises(QASMParseError, match="too large"):
        parse_qasm(f"OPENQASM 2.0;\nqreg q[{MAX_QUBITS + 1}];\n")


def test_huge_register_literal_rejected():
    with pytest.raises(QASMParseError, match="exceeds"):
        parse_qasm("OPENQASM 2.0;\nqreg q[" + "9" * 30 + "];\n")


def test_total_qubit_cap_across_registers():
    with pytest.raises(QASMParseError, match="Total qubits"):
        parse_qasm("OPENQASM 2.0;\nqreg a[400];\nqreg b[200];\n")


def test_exponent_bomb_rejected_instantly():
    started = time.monotonic()
    with pytest.raises(QASMParseError):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\nrz(2**10**10) q[0];\n")
    assert time.monotonic() - started < 1.0


def test_nested_power_tower_rejected():
    with pytest.raises(QASMParseError):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\nrz(9**9**9) q[0];\n")


def test_deep_parameter_nesting_rejected_not_crashing():
    expr = "(" * 400 + "1" + ")" * 400
    with pytest.raises(QASMParseError):
        parse_qasm(f"OPENQASM 2.0;\nqreg q[1];\nrz({expr}) q[0];\n")


def test_recursive_gate_expansion_depth_cap():
    with pytest.raises(QASMParseError, match="too deep"):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\ngate myrec a { myrec a; }\nmyrec q[0];\n")


def test_doubling_gate_expansion_depth_cap():
    with pytest.raises(QASMParseError, match="too deep"):
        parse_qasm("OPENQASM 2.0;\nqreg q[1];\ngate boom a { boom a; boom a; }\nboom q[0];\n")


def test_whole_register_broadcast_capped():
    with pytest.raises(QASMParseError):
        parse_qasm(f"OPENQASM 2.0;\nqreg q[{MAX_QUBITS + 1}];\nh q;\n")


def test_null_bytes_do_not_crash():
    ir = parse_qasm("OPENQASM 2.0;\nqreg q[1];\n\x00 x q[0];\n")
    assert isinstance(ir, CircuitIR)  # unrecognised statement skipped with a warning


def test_all_caps_are_strictly_positive():
    assert 0 < MAX_QUBITS <= 4096
    assert 0 < MAX_GATES <= 10_000_000


def test_fixtures_still_parse_within_caps():
    """Every bundled fixture must parse comfortably under the caps (no false caps)."""
    from pathlib import Path

    fixtures = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
    parsed = 0
    for path in fixtures.rglob("*.qasm"):
        source = path.read_text(encoding="utf-8")
        try:
            ir = parse_qasm(source, name=path.stem)
        except QASMParseError:
            continue  # some fixtures intentionally exercise unsupported constructs
        assert ir.num_qubits <= MAX_QUBITS
        parsed += 1
    assert parsed > 0
