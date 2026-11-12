"""QSHIELD command-line interface (typer + rich)."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from qshield import __version__
from qshield.core.config import load_config
from qshield.core.parsers import parse_file
from qshield.reporting.finding import SEVERITY_ORDER
from qshield.scanner import Scanner, ScanResults

app = typer.Typer(
    name="qshield",
    help="QSHIELD — Quantum Software Supply Chain Security Framework",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()

SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
}


def _severity_badge(sev: str) -> Text:
    return Text(sev.upper(), style=SEVERITY_STYLE.get(sev, "white"))


def _render_text_summary(results: ScanResults) -> None:
    summary = results.summary
    console.print()
    console.rule("[bold]QSHIELD Scan Results[/bold]")
    console.print(
        f"Circuits scanned: [bold]{summary.circuits_scanned}[/bold]  |  "
        f"Findings: [bold]{summary.total}[/bold]  |  "
        f"([red]critical {summary.critical}[/red] / [red]high {summary.high}[/red] / "
        f"[yellow]medium {summary.medium}[/yellow] / [blue]low {summary.low}[/blue] / info {summary.info})  |  "
        f"{results.elapsed_seconds:.2f}s"
    )
    if results.warnings:
        for w in results.warnings:
            console.print(f"[dim]warning: {w}[/dim]")
    if not results.findings:
        console.print("[bold green]✓ Clean — no findings above threshold[/bold green]")
        return
    table = Table(show_header=True, header_style="bold", show_lines=False)
    table.add_column("Severity", width=10)
    table.add_column("Threat", width=6)
    table.add_column("Title", overflow="fold")
    table.add_column("Conf", justify="right", width=5)
    for f in results.findings:
        table.add_row(_severity_badge(f.severity), f.threat_type, f.title, f"{f.confidence:.2f}")
    console.print(table)


def _fail_exit_code(results: ScanResults, fail_on: str) -> int:
    return 1 if results.exceeds_fail_on(fail_on) else 0


# ==================================================================
# scan
# ==================================================================
@app.command()
def scan(
    path: Path = typer.Argument(..., help="Circuit file (.qasm) or directory to scan recursively", exists=True),
    quick: bool = typer.Option(False, "--quick", help="Static analysis only (<30s)"),
    full: bool = typer.Option(False, "--full", help="Include dynamic analysis"),
    config: str = typer.Option("default", "--config", "-c", help="Profile: default|strict|permissive|path to .qshield.yaml"),
    framework: str | None = typer.Option(None, "--framework", help="Hint: qiskit|cirq|pennylane (default: auto from extension)"),
    output_format: str = typer.Option("text", "--format", "-f", help="text|json|sarif|html|pdf"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to file instead of stdout"),
    fail_on: str = typer.Option("high", "--fail-on", help="critical|high|medium|low|never — exit 1 at/above this severity"),
    shots: int = typer.Option(10_000, "--shots", help="Shots for dynamic analysis"),
    signatures: Path | None = typer.Option(None, "--signatures", help="Directory of custom YAML signatures"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Scan directory recursively for .qasm files"),
    github_actions: bool = typer.Option(False, "--github-actions", help="Emit GitHub Actions annotations"),
) -> None:
    """Scan a quantum circuit (or project) for vulnerabilities."""
    scanner = Scanner(config=config)
    files: list[Path] = []
    if path.is_dir():
        pattern = "**/*.qasm" if recursive else "*.qasm"
        files = sorted(path.glob(pattern))
        if not files:
            console.print(f"[yellow]No .qasm files found under {path}[/yellow]")
            raise typer.Exit(code=0)
    else:
        if path.suffix.lower() in (".py",):
            console.print("[yellow]Direct .py scanning is not supported (executing untrusted code is unsafe).[/yellow]")
            console.print("Use the Python API instead: qshield.Scanner().add_circuit(circuit_object)")
            raise typer.Exit(code=2)
        if framework and framework not in ("qasm", "qasm2", "auto"):
            console.print(f"[yellow]--framework {framework!r} is informational for .qasm files; only OpenQASM parsing is applied.[/yellow]")
        files = [path]

    for f in files:
        try:
            scanner.add_circuit(str(f), name=f.stem)
        except Exception as exc:
            console.print(f"[red]Failed to parse {f}: {exc}[/red]")
            raise typer.Exit(code=2) from exc

    if signatures:
        scanner.add_signatures(str(signatures))

    analyses = ["static", "supply_chain"]
    if full:
        analyses.append("dynamic")
    results = scanner.run(analyses=analyses, dynamic_shots=shots)

    if github_actions:
        for finding in results.findings:
            level = "error" if finding.severity_rank >= SEVERITY_ORDER["high"] else "warning"
            file = finding.location.source_file or str(files[0])
            line = (finding.location.gate_indices[0] + 1) if finding.location.gate_indices else 1
            print(f"::{level} file={file},line={line}::{finding.threat_type} {finding.title}")

    if output_format == "text":
        _render_text_summary(results)
        text_out = None
    elif output_format == "json":
        text_out = results.to_json()
    elif output_format == "sarif":
        text_out = results.to_sarif()
    elif output_format == "html":
        text_out = results.to_html()
    elif output_format == "pdf":
        if not output:
            console.print("[red]--format pdf requires -o/--output[/red]")
            raise typer.Exit(code=2)
        try:
            results.to_pdf(str(output))
        except RuntimeError as exc:
            console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code=2) from exc
        console.print(f"[green]Wrote {output}[/green]")
        raise typer.Exit(code=_fail_exit_code(results, fail_on))
    else:
        console.print(f"[red]Unknown format {output_format!r}[/red]")
        raise typer.Exit(code=2)

    if text_out is not None:
        if output:
            output.write_text(text_out, encoding="utf-8")
            console.print(f"[green]Wrote {output}[/green]")
        else:
            print(text_out)

    raise typer.Exit(code=_fail_exit_code(results, fail_on))


# ==================================================================
# compare
# ==================================================================
@app.command()
def compare(
    original: Path = typer.Argument(..., exists=True, help="Reference (trusted) circuit"),
    suspicious: Path = typer.Argument(..., exists=True, help="Circuit under audit"),
    tolerance: float = typer.Option(1e-6, "--tolerance"),
    formal: bool = typer.Option(False, "--formal", help="Decide equivalence with the ZX-calculus engine (pyzx)"),
    randomized: bool = typer.Option(False, "--randomized", help="Force randomized (high-probability) equivalence checking — practical to ~20 qubits"),
    samples: int = typer.Option(8, "--samples", help="Number of random inputs for --randomized"),
) -> None:
    """Compare two circuits structurally and (when small) unitarily."""
    try:
        a = parse_file(original)
        b = parse_file(suspicious)
    except Exception as exc:
        console.print(f"[red]Parse error: {exc}[/red]")
        raise typer.Exit(code=2) from exc

    table = Table(title="Circuit comparison")
    table.add_column("Metric", style="bold")
    table.add_column(original.name)
    table.add_column(suspicious.name)
    table.add_column("Match", justify="center")
    rows = [
        ("Qubits", a.num_qubits, b.num_qubits),
        ("Classical bits", a.num_classical_bits, b.num_classical_bits),
        ("Gates", len(a.gates), len(b.gates)),
        ("Depth", a.get_depth(), b.get_depth()),
    ]
    for label, va, vb in rows:
        table.add_row(label, str(va), str(vb), "[green]✓[/green]" if va == vb else "[red]✗[/red]")
    console.print(table)

    # gate multiset difference
    from collections import Counter
    ca = Counter((g.gate_name, tuple(g.qubits)) for g in a.gates)
    cb = Counter((g.gate_name, tuple(g.qubits)) for g in b.gates)
    only_a, only_b = ca - cb, cb - ca
    if only_a:
        console.print("[yellow]Only in original:[/yellow] " + ", ".join(f"{n}{list(q)}x{c}" for (n, q), c in sorted(only_a.items())))
    if only_b:
        console.print("[red]Only in suspicious:[/red] " + ", ".join(f"{n}{list(q)}x{c}" for (n, q), c in sorted(only_b.items())))

    if formal:
        from qshield.formal import zx_equivalence_check

        result = zx_equivalence_check(a, b)
        verdict = {True: "[green]EQUIVALENT[/green]", False: "[red]DIFFERENT[/red]", None: "[yellow]UNDECIDED[/yellow]"}[result.equivalent]
        console.print(f"ZX-calculus: {verdict} — {result.message} [{result.method}]")
        raise typer.Exit(code=0 if result.equivalent else 1)

    if randomized:
        from qshield.static import randomized_equivalence

        try:
            report = randomized_equivalence(a, b, num_samples=samples, seed=0)
        except Exception as exc:
            console.print(f"[red]Randomized check failed: {exc}[/red]")
            raise typer.Exit(code=2) from exc
        verdict = "[green]EQUIVALENT[/green]" if report.equivalent else "[red]DIFFERENT[/red]"
        console.print(f"Randomized check ({report.num_samples} samples, {report.num_qubits} qubits): {verdict} — {report.summary()}")
        raise typer.Exit(code=0 if report.equivalent else 1)

    # unitary comparison when feasible
    ua, ub = a.to_unitary(), b.to_unitary()
    if ua is not None and ub is not None and ua.shape == ub.shape:
        dist = float(np.linalg.norm(ua - ub))
        verdict = "[green]EQUIVALENT[/green]" if dist < tolerance else f"[red]DIFFERENT[/red] (‖ΔU‖={dist:.3e})"
        console.print(f"Unitary distance: {dist:.3e} → {verdict}")
        raise typer.Exit(code=0 if dist < tolerance else 1)

    # dense unitary out of reach: fall back to randomized checking (not a proof, but strong evidence)
    if a.num_qubits <= 22:
        from qshield.static import randomized_equivalence

        try:
            report = randomized_equivalence(a, b, num_samples=samples, seed=0)
        except Exception as exc:
            console.print(f"[dim]Randomized fallback unavailable ({exc})[/dim]")
            console.print("[dim]Unitary comparison skipped (too large or non-unitary)[/dim]")
            raise typer.Exit(code=0 if ca == cb else 1) from exc
        verdict = "[green]EQUIVALENT[/green]" if report.equivalent else "[red]DIFFERENT[/red]"
        console.print(f"Randomized check ({report.num_samples} samples, {report.num_qubits} qubits): {verdict} — {report.summary()}")
        console.print("[dim]High-probability equivalence (polynomial identity testing), not a proof — use --formal for a decision procedure.[/dim]")
        raise typer.Exit(code=0 if report.equivalent else 1)
    console.print("[dim]Unitary comparison skipped (too large or non-unitary)[/dim]")
    raise typer.Exit(code=0 if ca == cb else 1)


# ==================================================================
# verify
# ==================================================================
@app.command()
def verify(
    circuit: Path = typer.Argument(..., exists=True),
    expected_unitary: Path = typer.Option(..., "--expected-unitary", help=".npy file with the expected unitary matrix"),
    tolerance: float = typer.Option(1e-6, "--tolerance"),
    config: str = typer.Option("default", "--config", "-c"),
) -> None:
    """Verify a circuit's unitary against an expected matrix."""
    cfg = load_config(config)
    from qshield.static.unitary_verifier import UnitaryVerifier

    try:
        ir = parse_file(circuit)
    except Exception as exc:
        console.print(f"[red]Parse error: {exc}[/red]")
        raise typer.Exit(code=2) from exc
    try:
        expected = np.load(expected_unitary)
    except Exception as exc:
        console.print(f"[red]Cannot load unitary .npy: {exc}[/red]")
        raise typer.Exit(code=2) from exc

    verifier = UnitaryVerifier(max_qubits=cfg.unitary_max_qubits)
    report = verifier.verify_equivalence(ir, expected, tolerance)
    style = {"equivalent": "green", "close": "yellow", "different": "red", "uncomputable": "yellow"}[report.result.value]
    console.print(f"{report.result.value.upper()} — {report.message}", style=style)
    raise typer.Exit(code=0 if report.ok else 1)


# ==================================================================
# supply chain
# ==================================================================
@app.command(name="audit-deps")
def audit_deps(
    requirements: Path = typer.Option(..., "--requirements", help="requirements.txt to audit", exists=True),
    config: str = typer.Option("default", "--config", "-c"),
) -> None:
    """Audit a requirements.txt for quantum supply-chain risks."""
    from qshield.static.dependency_scanner import DependencyScanner

    report = DependencyScanner().scan_requirements(requirements.read_text(encoding="utf-8"))
    console.print(f"Audited {len(report.packages)} package(s)")
    if not report.findings:
        console.print("[bold green]✓ No dependency findings[/bold green]")
        raise typer.Exit(code=0)
    table = Table(title="Dependency findings")
    table.add_column("Severity")
    table.add_column("Package")
    table.add_column("Issue")
    table.add_column("Detail")
    for f in report.findings:
        table.add_row(f.severity.upper(), f"{f.package} {f.version or ''}", f.issue, f.detail)
    console.print(table)
    raise typer.Exit(code=0 if report.ok else 1)


@app.command(name="audit-package")
def audit_package_cmd(
    package_name: str = typer.Argument(..., help="PyPI package name to audit"),
    version: str = typer.Option("latest", "--version"),
) -> None:
    """Audit a single package (typosquatting + embedded advisories)."""
    from qshield.static.dependency_scanner import DependencyScanner

    text = f"{package_name}=={version}" if version != "latest" else package_name
    report = DependencyScanner().scan_requirements(text)
    if not report.findings:
        console.print(f"[green]✓ {package_name}: no findings[/green]")
        raise typer.Exit(code=0)
    for f in report.findings:
        console.print(f"[red]{f.severity.upper()}[/red] {f.package}: {f.detail}")
    raise typer.Exit(code=1)


# ==================================================================
# configuration
# ==================================================================
_CONFIG_TEMPLATE = """# .qshield.yaml — QSHIELD configuration
general:
  verbose: false
  parallel: true
  timeout: 3600

analysis:
  static:
    check_dead_qubits: true
    check_gate_cancellation: true
    check_entanglement_anomaly: true
    check_parameter_anomaly: true
    check_gate_count_heuristic: true
    check_measurement_basis: true
    unitary_verification: true
    unitary_max_qubits: 12
    unitary_tolerance: 1.0e-6
  dynamic: false        # requires simulators
  formal: false         # requires pyzx

thresholds:
  max_parameter_precision: 10
  min_qubit_activity: 2
  gate_count_multiplier: 2.0
  js_divergence_threshold: 0.05
  min_confidence: 0.5

reporting:
  format: json
  output: stdout

ci:
  fail_on: high

license_policy:
  allowed_licenses: [Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Python-2.0, Unlicense, MPL-2.0]

signatures:
  use_builtin: true
  custom_paths: []

profiles:
  strict:
    thresholds:
      max_parameter_precision: 6
      min_qubit_activity: 3
      gate_count_multiplier: 1.5
      min_confidence: 0.3
  permissive:
    thresholds:
      max_parameter_precision: 15
      min_qubit_activity: 1
      gate_count_multiplier: 3.0
      min_confidence: 0.8
"""


@app.command(name="init-config")
def init_config(
    output: Path = typer.Argument(Path(".qshield.yaml"), help="Where to write the template"),
) -> None:
    """Write a .qshield.yaml template to the current directory."""
    output.write_text(_CONFIG_TEMPLATE, encoding="utf-8")
    console.print(f"[green]Wrote {output}[/green]")


# ==================================================================
# signature database (offline)
# ==================================================================
db_app = typer.Typer(help="Interact with the signature database")
app.add_typer(db_app, name="db")


@db_app.command("search")
def db_search(query: str = typer.Argument(..., help="Search term")) -> None:
    from qshield.signatures import builtin_signatures

    q = query.lower()
    hits = [
        s for s in builtin_signatures()
        if q in (s.name + " " + s.description + " " + s.threat_type).lower()
    ]
    if not hits:
        console.print(f"No signatures matching {query!r}")
        raise typer.Exit(code=0)
    table = Table(title=f"Signatures matching {query!r}")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Threat")
    table.add_column("Name")
    for s in hits:
        table.add_row(s.id, s.severity, s.threat_type, s.name)
    console.print(table)


@db_app.command("list")
def db_list() -> None:
    from qshield.signatures import builtin_signatures

    table = Table(title="Built-in QSHIELD signatures")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Threat")
    table.add_column("Name")
    for s in builtin_signatures():
        table.add_row(s.id, s.severity, s.threat_type, s.name)
    console.print(table)


@app.command()
def version() -> None:
    """Print the QSHIELD version."""
    console.print(f"qshield {__version__}")


if __name__ == "__main__":
    app()
