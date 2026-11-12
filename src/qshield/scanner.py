"""QSHIELD public scanning API.

Usage::

    import qshield

    results = qshield.scan("my_circuit.qasm")

    scanner = qshield.Scanner(config="strict")
    scanner.add_circuit(my_qiskit_circuit)
    results = scanner.run()
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from qshield import __version__
from qshield.core.circuit_ir import MAX_EXACT_QUBITS, CircuitIR
from qshield.core.config import QShieldConfig, load_config
from qshield.core.parsers import parse_any, parse_file
from qshield.reporting.finding import SEVERITY_ORDER, CircuitLocation, Evidence, Finding
from qshield.reporting.html_exporter import render_html
from qshield.reporting.json_exporter import render_json
from qshield.reporting.sarif_exporter import render_sarif

SEVERITY_FAIL_LEVELS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "never": 99}


@dataclass
class ScanSummary:
    total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    circuits_scanned: int
    analyses_run: list[str]
    generated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total, "critical": self.critical, "high": self.high,
            "medium": self.medium, "low": self.low, "info": self.info,
            "circuits_scanned": self.circuits_scanned,
            "analyses_run": list(self.analyses_run),
            "generated_at": self.generated_at,
        }


class ScanResults:
    """Container for scan results."""

    def __init__(
        self,
        findings: list[Finding],
        circuits: list[CircuitIR],
        analyses_run: list[str] | None = None,
        warnings: list[str] | None = None,
        elapsed_seconds: float = 0.0,
    ):
        self._circuits = circuits
        self._findings = list(findings)
        self.analyses_run = analyses_run or ["static"]
        self.warnings = warnings or []
        self.elapsed_seconds = elapsed_seconds

    # -- findings -------------------------------------------------------
    @property
    def findings(self) -> list[Finding]:
        return sorted(self._findings, key=lambda f: (f.severity_rank, f.confidence), reverse=True)

    @property
    def circuits(self) -> list[CircuitIR]:
        return self._circuits

    @property
    def summary(self) -> ScanSummary:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in self._findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return ScanSummary(
            total=len(self._findings),
            circuits_scanned=len(self._circuits),
            analyses_run=list(self.analyses_run),
            generated_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            **counts,
        )

    @property
    def is_clean(self) -> bool:
        return not any(f.severity_rank >= SEVERITY_ORDER["high"] for f in self._findings)

    def exceeds_fail_on(self, fail_on: str) -> bool:
        threshold = SEVERITY_FAIL_LEVELS.get(fail_on.lower(), 3)
        return any(f.severity_rank >= threshold for f in self._findings)

    # -- filtering ------------------------------------------------------
    def filter(
        self,
        severity: str | None = None,
        threat_type: str | None = None,
        analysis_type: str | None = None,
    ) -> ScanResults:
        findings = self._findings
        if severity:
            findings = [f for f in findings if f.severity == severity.lower()]
        if threat_type:
            findings = [f for f in findings if f.threat_type == threat_type]
        if analysis_type:
            findings = [f for f in findings if f.analysis_type == analysis_type]
        return ScanResults(findings, self._circuits, self.analyses_run, self.warnings, self.elapsed_seconds)

    # -- export ---------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "QSHIELD", "version": __version__},
            "summary": self.summary.to_dict(),
            "is_clean": self.is_clean,
            "warnings": list(self.warnings),
            "circuits": [c.to_dict() for c in self._circuits],
            "findings": [f.to_dict() for f in self.findings],
            "elapsed_seconds": round(self.elapsed_seconds, 3),
        }

    def to_json(self) -> str:
        return render_json(self.to_dict())

    def to_sarif(self) -> str:
        return render_sarif(self.findings, tool_version=__version__)

    def to_html(self) -> str:
        report = {
            "name": ", ".join(c.name for c in self._circuits) or "scan",
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
            "source_hash": (self._circuits[0].source_hash if self._circuits else ""),
            "num_qubits": max((c.num_qubits for c in self._circuits), default=0),
            "num_gates": sum(len(c.gates) for c in self._circuits),
        }
        summary = {
            "total": self.summary.total, "critical": self.summary.critical,
            "high": self.summary.high, "medium": self.summary.medium,
            "low": self.summary.low,
        }
        return render_html(self.findings, summary, report, version=__version__)

    # spec calls this to_pdf; we expose it but raise a clear error if the
    # optional dependency is missing.
    def to_pdf(self, output_path: str) -> None:
        try:
            from weasyprint import HTML
        except ImportError as exc:
            raise RuntimeError(
                "PDF export requires the optional 'weasyprint' package: pip install weasyprint"
            ) from exc
        HTML(string=self.to_html()).write_pdf(output_path)

    def __bool__(self) -> bool:
        return self.is_clean

    def __len__(self) -> int:
        return len(self._findings)

    def __repr__(self) -> str:
        return f"<ScanResults findings={len(self._findings)} clean={self.is_clean}>"


@dataclass
class _RegisteredCircuit:
    circuit: CircuitIR
    expected_unitary: np.ndarray | None
    metadata: dict


@dataclass
class _RegisteredPackage:
    package_name: str
    version: str
    registry: str


class Scanner:
    """Main entry point for QSHIELD analysis."""

    def __init__(
        self,
        config: str | QShieldConfig = "default",
        signatures: str = "builtin",
        backends: list[str] | None = None,
        parallel: bool = True,
        verbose: bool = False,
    ):
        self.config = config if isinstance(config, QShieldConfig) else load_config(config)
        if backends is not None:
            self.config.dynamic_backends = list(backends)
        self.signatures_mode = signatures
        self.parallel = parallel
        self.verbose = verbose
        self._circuits: list[_RegisteredCircuit] = []
        self._packages: list[_RegisteredPackage] = []
        self._requirements: list[str] = []
        self._extra_signature_paths: list[str] = []

    # ------------------------------------------------------------------
    def add_circuit(
        self,
        circuit: Any,
        name: str | None = None,
        expected_unitary=None,
        metadata: dict | None = None,
    ) -> str:
        """Add a circuit for analysis. Returns the internal circuit_id."""
        ir: CircuitIR
        try:
            ir = parse_any(circuit, name=name)
        except Exception:
            fallback = parse_file(circuit, name=name) if isinstance(circuit, (str, Path)) else None
            if fallback is None:
                raise
            ir = fallback
        if metadata:
            ir.metadata = {**ir.metadata, **metadata}
        if expected_unitary is not None:
            expected_unitary = np.asarray(expected_unitary, dtype=complex)
        self._circuits.append(_RegisteredCircuit(ir, expected_unitary, metadata or {}))
        return ir.circuit_id

    def add_package(self, package_name: str, version: str = "latest", registry: str = "pypi") -> str:
        """Add a quantum package for supply-chain analysis."""
        package_id = f"pkg-{uuid.uuid4().hex[:10]}"
        self._packages.append(_RegisteredPackage(package_name, version, registry))
        return package_id

    def add_requirements(self, text: str) -> str:
        """Register raw requirements.txt content for dependency auditing."""
        req_id = f"req-{uuid.uuid4().hex[:10]}"
        self._requirements.append(text)
        return req_id

    def add_signatures(self, path: str) -> Scanner:
        self._extra_signature_paths.append(path)
        return self

    # ------------------------------------------------------------------
    def run(
        self,
        analyses: Sequence[str] | None = None,
        timeout: int = 3600,
        dynamic_shots: int = 10_000,
    ) -> ScanResults:
        analyses = list(analyses) if analyses else self._default_analyses()
        start = time.monotonic()
        findings: list[Finding] = []
        warnings: list[str] = []
        circuits_out = [rc.circuit for rc in self._circuits]

        # signature matcher built once
        matcher = self._build_matcher(warnings)

        for rc in self._circuits:
            circuit = rc.circuit
            if time.monotonic() - start > timeout:
                warnings.append(f"Timeout after {timeout}s; remaining circuits skipped")
                break
            if "static" in analyses:
                findings += self._run_static(circuit, rc, matcher, warnings)
            if "dynamic" in analyses:
                findings += self._run_dynamic(circuit, dynamic_shots, warnings)
            if "formal" in analyses:
                findings += self._run_formal(circuit, warnings)

        if "supply_chain" in analyses:
            findings += self._run_supply_chain(warnings)

        elapsed = time.monotonic() - start
        return ScanResults(findings, circuits_out, analyses, warnings, elapsed)

    def run_quick(self) -> ScanResults:
        """Static analysis only; designed for CI (<30s typical)."""
        return self.run(analyses=["static", "supply_chain"])

    # ------------------------------------------------------------------
    def _default_analyses(self) -> list[str]:
        analyses = ["static", "supply_chain"]
        if self.config.dynamic_enabled:
            analyses.append("dynamic")
        if self.config.formal_enabled:
            analyses.append("formal")
        return analyses

    def _build_matcher(self, warnings: list[str]):
        from qshield.signatures import SignatureMatcher, builtin_signatures, load_directory
        sigs = []
        if self.signatures_mode == "builtin":
            try:
                sigs = builtin_signatures()
            except Exception as exc:
                warnings.append(f"Failed to load builtin signatures: {exc}")
        for path in self._extra_signature_paths:
            try:
                sigs.extend(load_directory(path))
            except Exception as exc:
                warnings.append(f"Failed to load signatures from {path}: {exc}")
        return SignatureMatcher(sigs) if sigs else None

    # ------------------------------------------------------------------
    def _run_static(self, circuit, rc, matcher, warnings):
        from qshield.static.structural_analyzer import StructuralAnalyzer
        from qshield.static.unitary_verifier import UnitaryVerifier

        findings: list[Finding] = []
        analyzer = StructuralAnalyzer(self.config)
        findings += analyzer.analyze(circuit)

        if matcher is not None:
            matched = matcher.match(circuit)
            findings += matched
            warnings += matcher.warnings

        # Unitary equivalence vs expected unitary (if supplied)
        if rc.expected_unitary is not None:
            verifier = UnitaryVerifier(max_qubits=min(self.config.unitary_max_qubits, MAX_EXACT_QUBITS))
            report = verifier.verify_equivalence(circuit, rc.expected_unitary, self.config.unitary_tolerance)
            if not report.ok:
                findings.append(Finding(
                    severity="critical" if report.result.value == "different" else "medium",
                    threat_type="T1.2",
                    title="Circuit does not match expected unitary",
                    description=(
                        f"Unitary verification failed for circuit {circuit.name!r}: {report.message}. "
                        "The circuit may have been modified in transit or in the supply chain."
                    ),
                    circuit_id=circuit.circuit_id,
                    evidence=Evidence(
                        evidence_type="unitary_mismatch",
                        details={"distance": report.distance, "tolerance": report.tolerance,
                                 "result": report.result.value},
                    ),
                    confidence=0.9 if report.result.value == "different" else 0.5,
                    remediation="Re-fetch the circuit from a trusted source and re-verify; compare against a known-good build.",
                    false_positive_probability=0.1,
                    analysis_type="static",
                ))

        # Ancilla independence (small circuits only)
        candidates = self._ancilla_candidates(circuit)
        if candidates and circuit.num_qubits <= 8:
            from qshield.static.unitary_verifier import UnitaryVerifier
            verifier = UnitaryVerifier(max_qubits=8)
            leak = verifier.check_ancilla_independence(circuit, candidates)
            if leak.leaks:
                findings.append(Finding(
                    severity="high",
                    threat_type="T2.1",
                    title="Ancilla carries information about the computation",
                    description=(
                        f"Partial-trace analysis shows ancilla qubit(s) {candidates} are NOT independent "
                        f"of the data qubits ({leak.details}). Information is leaking out of the computation."
                    ),
                    circuit_id=circuit.circuit_id,
                    location=CircuitLocation(qubit_indices=candidates),
                    evidence=Evidence(
                        evidence_type="unitary_mismatch",
                        details={"max_trace_distance": leak.max_trace_distance,
                                 "tested_inputs": leak.tested_inputs},
                    ),
                    confidence=0.85,
                    remediation="Remove or re-derive the ancilla; audit what it is entangled with and where it is measured.",
                    false_positive_probability=0.15,
                    analysis_type="static",
                ))

        # min-confidence filter (same semantics as the structural analyzer)
        min_conf = self.config.threshold("min_confidence")
        return [f for f in findings if f.confidence >= min_conf]

    def _ancilla_candidates(self, circuit: CircuitIR) -> list[int]:
        if circuit.ancilla_qubits:
            return list(circuit.ancilla_qubits)
        usage = circuit.get_qubit_usage()
        measured = {q for q, _ in circuit.measurements}
        return sorted(q for q in measured if usage.get(q, 0) == 1)

    def _run_dynamic(self, circuit, dynamic_shots, warnings):
        findings: list[Finding] = []
        try:
            from qshield.dynamic.differential_tester import DifferentialTester
            tester = DifferentialTester(shots=dynamic_shots, significance_level=self.config.significance_level)
            report = tester.cross_check_against_aer(circuit)
            if report.compared and report.comparison is not None and report.comparison.suspicious:
                findings.append(Finding(
                    severity="high",
                    threat_type="T3.3",
                    title="Output distribution diverges across backends",
                    description=(
                        f"Differential testing between {report.backend_a} and {report.backend_b}: "
                        f"{report.comparison.verdict} "
                        f"(JS={report.comparison.jensen_shannon:.3f}, "
                        f"TV={report.comparison.total_variation:.3f}, "
                        f"chi2 p={report.comparison.chi_square_p:.2e})."
                    ),
                    circuit_id=circuit.circuit_id,
                    evidence=Evidence(
                        evidence_type="statistical",
                        details={
                            "jensen_shannon": report.comparison.jensen_shannon,
                            "total_variation": report.comparison.total_variation,
                            "chi_square_p": report.comparison.chi_square_p,
                            "kl_divergence": report.comparison.kl_divergence,
                        },
                    ),
                    confidence=0.75,
                    remediation="Re-run on independent hardware/simulators; treat divergent backends as compromised until proven otherwise.",
                    false_positive_probability=0.2,
                    analysis_type="dynamic",
                ))
        except Exception as exc:
            warnings.append(f"Dynamic analysis skipped for {circuit.name}: {exc}")
        return findings

    def _run_formal(self, circuit, warnings):
        from qshield.formal import pyzx_available
        if not pyzx_available():
            warnings.append("Formal analysis requested but pyzx is not installed; skipping (pip install 'qshield[formal]')")
            return []
        warnings.append(
            "Formal ZX-calculus equivalence needs a reference circuit; "
            "use `qshield compare --formal A B` or the verify API. No expected artifact supplied; skipping."
        )
        return []

    def _run_supply_chain(self, warnings):
        from qshield.static.dependency_scanner import DependencyScanner

        scanner = DependencyScanner()
        findings: list[Finding] = []
        texts = list(self._requirements)
        for pkg in self._packages:
            if pkg.version and pkg.version != "latest":
                texts.append(f"{pkg.package_name}=={pkg.version}")
            else:
                texts.append(pkg.package_name)
        for text in texts:
            report = scanner.scan_requirements(text)
            for dep in report.findings:
                severity = dep.severity if dep.severity in SEVERITY_ORDER else "medium"
                findings.append(Finding(
                    severity=severity,
                    threat_type="T3.1",
                    title=f"Supply-chain: {dep.issue.replace('_', ' ')} in {dep.package}",
                    description=dep.detail,
                    circuit_id="supply-chain",
                    location=CircuitLocation(),
                    evidence=Evidence(evidence_type="structural",
                                      details={"package": dep.package, "version": dep.version, "issue": dep.issue}),
                    confidence=0.7 if dep.issue == "known_vulnerable" else 0.6,
                    remediation="Pin exact versions with hashes; verify against trusted registries; review the package's provenance.",
                    false_positive_probability=0.3,
                    analysis_type="supply_chain",
                ))
        return findings


def scan(source, name: str | None = None, config: str = "default") -> ScanResults:
    """One-shot scan: ``qshield.scan("circuit.qasm")``."""
    scanner = Scanner(config=config)
    scanner.add_circuit(source, name=name)
    return scanner.run_quick()
