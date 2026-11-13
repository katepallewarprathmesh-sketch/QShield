"""QSHIELD: Quantum Software Supply Chain Security Framework.

Detects, analyzes and prevents security vulnerabilities in quantum
software supply chains: backdoor gates, trojan unitaries, covert
channels and malicious circuit modifications.
"""

from __future__ import annotations

__version__ = "1.1.1"
__all__ = [
    "CircuitIR",
    "CircuitLocation",
    "Evidence",
    "Finding",
    "GateNode",
    "GateType",
    "ScanResults",
    "ScanSummary",
    "Scanner",
    "ThreatLevel",
    "UnsupportedGateError",
    "__version__",
    "scan",
    "to_qiskit",
]

from qshield.core.circuit_ir import CircuitIR, GateNode, GateType, ThreatLevel
from qshield.core.exporters import UnsupportedGateError, to_qiskit
from qshield.reporting.finding import CircuitLocation, Evidence, Finding
from qshield.scanner import Scanner, ScanResults, ScanSummary, scan
