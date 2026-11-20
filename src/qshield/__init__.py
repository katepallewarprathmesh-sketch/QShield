"""QSHIELD: Quantum Software Supply Chain Security Framework.

Detects, analyzes and prevents security vulnerabilities in quantum
software supply chains: backdoor gates, trojan unitaries, covert
channels and malicious circuit modifications.
"""

from __future__ import annotations

# Single source of truth is the installed distribution metadata, which comes
# from pyproject.toml. A checked-in fallback keeps source-tree imports working
# and is asserted against pyproject.toml by tests/unit/test_version_consistency.py
# so the two can never drift apart again.
__version__ = "1.6.0"

try:  # pragma: no cover - exercised on installed distributions
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _dist_version

    __version__ = _dist_version("qshield")
except PackageNotFoundError:  # pragma: no cover
    pass
__all__ = [
    "CircuitIR",
    "CircuitLocation",
    "Evidence",
    "Finding",
    "GateNode",
    "GateType",
    "QuboModel",
    "QuboReport",
    "ScanResults",
    "ScanSummary",
    "Scanner",
    "ThreatLevel",
    "UnsupportedGateError",
    "__version__",
    "analyse_qubo",
    "from_dict",
    "from_matrix",
    "parse_qubo",
    "scan",
    "to_qiskit",
]

from qshield.core.circuit_ir import CircuitIR, GateNode, GateType, ThreatLevel
from qshield.core.exporters import UnsupportedGateError, to_qiskit
from qshield.qubo import QuboModel, QuboReport, analyse_qubo, from_dict, from_matrix, parse_qubo
from qshield.reporting.finding import CircuitLocation, Evidence, Finding
from qshield.scanner import Scanner, ScanResults, ScanSummary, scan
