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
  use_community: false  # opt-in: qshield sig update --offline installs the bundled pack first
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


# ==================================================================
# community signature pack (spec M3.4: authoring, testing, auto-update)
# ==================================================================
sig_app = typer.Typer(help="Community signature pack: author, test, update")
app.add_typer(sig_app, name="sig")

runtime_app = typer.Typer(help="Runtime cloud-API monitor (interceptor proxy, M4.1)")
app.add_typer(runtime_app, name="runtime")

_ID_RE = __import__("re").compile(r"^QSig-(\d{4})-(\d{4})$")
_ROOT = Path(__file__).resolve().parents[3]


def _next_community_id() -> str:
    """Next free QSig id across builtin pack, bundled community pack and user pack."""
    import contextlib
    import datetime as _dt

    from qshield.signatures import builtin_signatures

    used: set[str] = set()
    with contextlib.suppress(Exception):
        used.update(s.id for s in builtin_signatures())
    used.update(f.stem for f in pack_dir_globs())
    current_year = _dt.date.today().year
    max_used_year = max((int(m.group(1)) for s in used if (m := _ID_RE.match(s))), default=0)
    year = max(current_year, max_used_year)
    seqs = sorted(int(m.group(2)) for s in used
                  if (m := _ID_RE.match(s)) and int(m.group(1)) == year)
    return f"QSig-{year}-{(seqs[-1] if seqs else 0) + 1:04d}"


def pack_dir_globs():
    from qshield.signatures.updater import bundled_community_dir, user_community_dir

    for pack in (bundled_community_dir(), user_community_dir()):
        if pack.exists():
            yield from pack.glob("*.yaml")
            yield from pack.glob("*.yml")


@sig_app.command("id-suggest")
def sig_id_suggest() -> None:
    """Print the next free community signature id."""
    console.print(_next_community_id())


@sig_app.command("new")
def sig_new(
    threat_type: str = typer.Argument(..., help="Threat type T<1-4>.<1-4>"),
    severity: str = typer.Option("medium", "--severity", help="critical|high|medium|low|info"),
    name: str = typer.Option("", "--name", help="Short human name"),
    out: Path | None = typer.Option(None, "--out", help="Output path (default ./<id>.yaml)"),
    force: bool = typer.Option(False, "--force", help="Overwrite existing file"),
) -> None:
    """Scaffold a new community signature template with a free id."""
    import re as _re

    from qshield.signatures.loader import VALID_SEVERITIES

    if severity.lower() not in VALID_SEVERITIES:
        console.print(f"[red]Invalid severity {severity!r}; expected one of {sorted(VALID_SEVERITIES)}[/red]")
        raise typer.Exit(code=2)
    if not _re.match(r"^T[1-4]\.[1-4]$", threat_type):
        console.print(f"[red]Invalid threat_type {threat_type!r}; expected T<1-4>.<1-4>[/red]")
        raise typer.Exit(code=2)

    sig_id = _next_community_id()
    template = f'''id: "{sig_id}"
name: "{name or 'Describe the pattern'}"
version: "1.0"
author: "Your Name <you@example.org>"
date: "{__import__('datetime').date.today().isoformat()}"
severity: "{severity.lower()}"
threat_type: "{threat_type}"
description: |
  One paragraph: what this detects, why, and why it is NOT a false positive
  generator. State the corpus TPR/FPR you measured with 'qshield sig test'.
detection:
  method: "structural"
  structural_pattern:
    type: "gate_sequence_inverse"   # gate_sequence_inverse | leaf_ancilla | parameter_grid_encoding | measurement_basis | micro_rotation_spread
    window: 8
    tolerance: 1.0e-6
references:
  - "spec://QSHIELD/2.1#{threat_type}"
false_positive_probability: 0.5
remediation: "What the operator should do when this fires."
'''
    out = out or Path(f"./{sig_id}.yaml")
    if out.exists() and not force:
        console.print(f"[red]Refusing to overwrite {out} (use --force)[/red]")
        raise typer.Exit(code=2)
    out.write_text(template, encoding="utf-8")
    console.print(f"[green]Wrote {out}[/green] — fill it in, then:")
    console.print(f"  qshield sig validate {out}")
    console.print(f"  qshield sig test {out} --min-tpr 0.5 --max-fpr 0.1")


@sig_app.command("validate")
def sig_validate(target: Path = typer.Argument(..., help="Signature YAML file or directory")) -> None:
    """Validate one signature or a whole directory against the schema."""
    from qshield.signatures.loader import load_directory, load_signature

    try:
        sigs = load_directory(target) if target.is_dir() else [load_signature(target)]
    except Exception as exc:
        console.print(f"[red]INVALID: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    table = Table(title=f"Validated {len(sigs)} signature(s) in {target}")
    for col in ("ID", "Severity", "Threat", "Method", "Name"):
        table.add_column(col)
    for s in sigs:
        table.add_row(s.id, s.severity, s.threat_type, s.method, s.name)
    console.print(table)


@sig_app.command("test")
def sig_test(
    signature: Path = typer.Argument(..., help="Signature YAML to evaluate"),
    malicious_dir: Path | None = typer.Option(None, "--malicious-dir", help="Defaults to the repo malicious corpus"),
    clean_dir: Path | None = typer.Option(None, "--clean-dir", help="Defaults to the repo clean corpus"),
    min_tpr: float = typer.Option(0.5, "--min-tpr", help="Fail if malicious detection rate is below this"),
    max_fpr: float = typer.Option(0.1, "--max-fpr", help="Fail if clean fire rate exceeds this"),
    json_out: bool = typer.Option(False, "--json", help="Emit JSON instead of a table"),
) -> None:
    """Measure a signature's TPR (malicious) and FPR (clean). The community quality gate."""
    import json as _json

    from qshield.core.parsers import parse_any
    from qshield.signatures.loader import load_signature
    from qshield.signatures.matcher import SignatureMatcher

    sig = load_signature(signature)
    matcher = SignatureMatcher([sig])

    mal_dir = malicious_dir or (_ROOT / "tests/fixtures/malicious_circuits")
    cl_dir = clean_dir or (_ROOT / "tests/fixtures/clean_circuits")

    def run(d: Path):
        n = hit = 0
        errors = 0
        for path in sorted(d.glob("*.qasm")):
            try:
                ir = parse_any(str(path))
            except Exception:
                errors += 1
                continue
            n += 1
            if any(f.signature_id == sig.id for f in matcher.match(ir)):
                hit += 1
        return hit, n, errors

    mal_hit, mal_n, mal_err = run(mal_dir)
    cl_hit, cl_n, cl_err = run(cl_dir)
    tpr = mal_hit / mal_n if mal_n else 0.0
    fpr = cl_hit / cl_n if cl_n else 0.0

    passed = not (tpr < min_tpr or fpr > max_fpr)
    if json_out:
        console.print(_json.dumps({
            "signature": sig.id, "tpr": round(tpr, 4), "fpr": round(fpr, 4),
            "malicious": {"detected": mal_hit, "total": mal_n, "skipped": mal_err},
            "clean": {"flagged": cl_hit, "total": cl_n, "skipped": cl_err},
            "min_tpr": min_tpr, "max_fpr": max_fpr, "result": "PASS" if passed else "FAIL",
        }, indent=2))
    else:
        table = Table(title=f"Signature {sig.id} vs corpus")
        table.add_column("Set")
        table.add_column("Flagged")
        table.add_column("Total")
        table.add_column("Rate")
        table.add_row("malicious", str(mal_hit), str(mal_n), f"{tpr:.3f} (min {min_tpr})")
        table.add_row("clean", str(cl_hit), str(cl_n), f"{fpr:.3f} (max {max_fpr})")
        console.print(table)
        if mal_err or cl_err:
            console.print(f"[yellow]skipped {mal_err} malformed malicious + {cl_err} clean fixtures[/yellow]")

    if not passed:
        if not json_out:
            console.print(f"[red]FAIL: TPR {tpr:.3f} < {min_tpr} or FPR {fpr:.3f} > {max_fpr}[/red]")
        raise typer.Exit(code=1)
    if not json_out:
        console.print("[green]PASS[/green]")


@sig_app.command("update")
def sig_update(
    url: str | None = typer.Option(None, "--url", help="Manifest URL (or QSHIELD_SIGNATURE_REPO; default: canonical pack)"),
    offline: bool = typer.Option(False, "--offline", help="Install the pack bundled with this release (no network)"),
    install_dir: Path | None = typer.Option(None, "--install-dir", help="Defaults to ~/.qshield/signatures/community"),
) -> None:
    """Fetch, verify (sha256 + schema) and install the community pack. Rollback-safe."""
    from qshield.signatures import updater

    try:
        report = updater.update(url=url, install_dir=install_dir, offline=offline)
    except updater.UpdateError as exc:
        console.print(f"[red]Update failed: {exc}[/red]")
        raise typer.Exit(code=1) from exc
    if not report.ok:
        for err in report.errors:
            console.print(f"[red]  - {err}[/red]")
        console.print("[red]Pack rejected; existing installation untouched.[/red]")
        raise typer.Exit(code=1)
    console.print(f"[green]Installed community pack {report.pack_version} "
                  f"({report.installed_files} files) from {report.source}[/green]")
    console.print(f"  into {report.install_dir}")
    console.print("  enable it with [bold]signatures:\n  use_community: true[/bold] in .qshield.yaml (spec default is false)")
    if report.backup_dir:
        console.print(f"  previous pack kept at {report.backup_dir} (rollback: qshield sig rollback)")


@sig_app.command("rollback")
def sig_rollback(
    install_dir: Path | None = typer.Option(None, "--install-dir"),
) -> None:
    """Restore the previous community pack (kept as <dir>.bak)."""
    from qshield.signatures import updater

    if updater.rollback(install_dir):
        console.print("[green]Rolled back to the previous community pack[/green]")
    else:
        console.print("[yellow]No backup to roll back to[/yellow]")
        raise typer.Exit(code=1)


@sig_app.command("status")
def sig_status(
    install_dir: Path | None = typer.Option(None, "--install-dir"),
) -> None:
    """Show which community pack is installed and what it contains."""
    from qshield.signatures import community as _community
    from qshield.signatures import updater

    status = updater.installed_status(install_dir)
    if not status["installed"]:
        console.print(f"[yellow]No community pack installed at {status['install_dir']}[/yellow]")
        console.print("  run: qshield sig update --offline")
        raise typer.Exit(code=0)
    console.print(f"installed pack {status['pack_version']} at {status['install_dir']}")
    console.print(f"  {status['files']} signature(s): {', '.join(status['signatures']) or '(empty pack)'}")
    errors = _community.verify_pack(Path(status["install_dir"]))
    if errors:
        for err in errors:
            console.print(f"[red]  drift: {err}[/red]")
        raise typer.Exit(code=1)
    console.print("[green]  sha256 manifest OK[/green]")


@sig_app.command("manifest-build")
def sig_manifest_build(
    pack_dir: Path = typer.Argument(..., help="Community pack directory"),
    version: str = typer.Option(..., "--version", help="pack_version tag, e.g. 2026.2"),
) -> None:
    """Maintainers: regenerate manifest.json (sha256 of every YAML file)."""
    from qshield.signatures import updater

    try:
        manifest = updater.build_manifest(pack_dir, version)
    except updater.UpdateError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from exc
    console.print(f"[green]Wrote {pack_dir / 'manifest.json'} "
                  f"({len(manifest['files'])} files, pack {version})[/green]")


@runtime_app.command("proxy")
def runtime_proxy(
    upstream: str = typer.Option(..., "--upstream", help="Upstream cloud endpoint, e.g. https://api.quantum.ibm.com"),
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address (0.0.0.0 exposes the proxy to the network)"),
    port: int = typer.Option(8080, "--port"),
    policy: str = typer.Option("observe", "--policy", help="observe (forward+alert) | enforce (403 on violation)"),
    min_severity: str = typer.Option("high", "--min-severity", help="enforce: block threshold for static findings"),
    alert_min_severity: str = typer.Option("medium", "--alert-min-severity", help="minimum severity routed to sinks"),
    alert_file: Path | None = typer.Option(None, "--alert-file", help="JSON-lines alert log (default: stderr)"),
    webhook: str | None = typer.Option(None, "--webhook", help="also POST alerts to this URL"),
    no_validate: bool = typer.Option(False, "--no-validate", help="disable counts-vs-ideal result validation"),
    no_static: bool = typer.Option(False, "--no-static", help="disable static scan in-flight (hash+commitment still run)"),
) -> None:
    """Run the QSHIELD interceptor proxy in front of a quantum cloud endpoint."""
    from qshield.runtime.proxy import ProxyConfig, QShieldProxy, build_alert_router

    if policy not in ("observe", "enforce"):
        console.print("[red]--policy must be 'observe' or 'enforce'[/red]")
        raise typer.Exit(code=2)
    config = ProxyConfig(upstream=upstream, policy=policy, min_severity=min_severity,
                         alert_min_severity=alert_min_severity,
                         validate_results=not no_validate, run_static=not no_static)
    router = build_alert_router(alert_file, webhook, alert_min_severity)
    proxy = QShieldProxy(config, router, host=host, port=port)
    console.print(f"[green]qshield runtime proxy listening on {host}:{proxy.port}[/green]")
    console.print(f"  upstream: {upstream}")
    console.print(f"  policy:   {policy}   (block ≥ {min_severity}, alert ≥ {alert_min_severity})")
    console.print(f"  alerts:   {alert_file or 'stderr'}" + (f" + {webhook}" if webhook else ""))
    console.print("  press Ctrl-C to stop")
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]stopping…[/yellow]")
    finally:
        proxy.stop()
    console.print(f"stats: {proxy.stats_snapshot()}")


@runtime_app.command("check")
def runtime_check(
    circuit: Path = typer.Argument(..., help="QASM circuit file to inspect"),
    expected_hash: str | None = typer.Option(None, "--expected-hash", help="declared sha256 commitment"),
    min_severity: str = typer.Option("high", "--min-severity"),
    json_out: bool = typer.Option(False, "--json"),
) -> None:
    """One-shot in-transit integrity check for a circuit file."""
    import json as _json

    from qshield.core.parsers.qasm_parser import parse_qasm
    from qshield.runtime.integrity import inspect_circuit

    try:
        ir = parse_qasm(circuit.read_text(encoding="utf-8"), name=circuit.name)
    except Exception as exc:
        console.print(f"[red]could not parse {circuit}: {exc}[/red]")
        raise typer.Exit(code=2) from exc
    report = inspect_circuit(ir, expected_hash=expected_hash)
    blocking = report.findings_at_least(min_severity)
    commitment_bad = report.commitment.ok is False
    if json_out:
        console.print(_json.dumps({
            "circuit_hash": report.circuit_hash,
            "commitment": report.commitment.status,
            "max_severity": report.max_severity,
            "findings": [{"threat_type": f.threat_type, "severity": f.severity,
                          "title": f.title, "confidence": f.confidence} for f in report.findings],
            "verdict": "fail" if (blocking or commitment_bad) else "pass",
        }, indent=2))
    else:
        console.print(f"circuit hash: {report.circuit_hash}")
        console.print(f"commitment:   {report.commitment.status}")
        if report.findings:
            for finding in report.findings:
                console.print(f"  [{finding.severity}] {finding.threat_type} {finding.title}")
        else:
            console.print("  no static findings")
        console.print("verdict:      [red]FAIL[/red]" if (blocking or commitment_bad) else "verdict:      [green]PASS[/green]")
    if blocking or commitment_bad:
        raise typer.Exit(code=1)


@app.command()
def ui(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address (127.0.0.1 offline default; 0.0.0.0 only behind explicit flag)"),
    port: int = typer.Option(8765, "--port", "-p", help="Port to bind"),
) -> None:
    """Launch the QSHIELD Workbench — offline, local, no-hardware web UI."""
    from qshield.ui import run_workbench

    run_workbench(host=host, port=port)


@app.command()
def version() -> None:
    """Print the QSHIELD version."""
    console.print(f"qshield {__version__}")


if __name__ == "__main__":
    app()
