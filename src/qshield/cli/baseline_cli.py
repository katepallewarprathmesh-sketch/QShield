"""CLI for approved readout baselines (T2.3 differential).

Without this, the baseline-differential check is reachable only from Python,
which means the README's own example is the only way to use it. These commands
mirror ``qshield provenance``: same key handling, same exit codes, same habit of
writing PEM files and refusing to overwrite them.

The one structural difference is deliberate. A provenance manifest travels with
its circuit; a baseline file holds *digests only*, because the reference circuit
is uploaded separately. So ``baseline attach`` resolves a checked-out circuit
against the digests the signature covers, and refuses if they disagree — the
evaluator does the same check at scan time, and doing it twice is not redundant
when the failure mode is comparing against the wrong artifact.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import typer
from rich.console import Console

console = Console()

baseline_app = typer.Typer(
    help="Approve, sign, and verify readout baselines for the T2.3 differential check"
)

_EXIT_USER_ERROR = 2
_EXIT_VERIFY_FAILED = 1


def _fail(message: str, code: int = _EXIT_USER_ERROR) -> None:
    console.print(f"[red]{message}[/red]")
    raise typer.Exit(code=code)


@baseline_app.command("create")
def baseline_create(
    circuit: Path = typer.Argument(..., exists=True, dir_okay=False, help="Approved OpenQASM circuit"),
    workload_id: str = typer.Option(..., "--workload", help="Workload this baseline governs"),
    approved_by: str = typer.Option(..., "--approved-by", help="Identity approving this artifact"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write record here (default: stdout)"),
    version: int = typer.Option(1, "--version", help="Monotonic version; higher supersedes lower"),
    expires_at: str | None = typer.Option(None, "--expires-at", help="YYYY-MM-DDTHH:MM:SSZ"),
) -> None:
    """Create an unsigned baseline record for a circuit. Sign it before use."""
    from qshield.core.parsers import parse_file
    from qshield.integrity.baseline import BaselineError, create_baseline

    try:
        record = create_baseline(
            parse_file(circuit),
            workload_id=workload_id,
            approved_by=approved_by,
            version=version,
            expires_at=expires_at,
        )
    except (OSError, BaselineError) as exc:
        _fail(str(exc))
        return

    payload = record.to_dict()
    if output is None:
        typer.echo(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
        console.print(
            "[yellow]Unsigned: this record cannot be registered until signed "
            "(qshield baseline sign).[/yellow]"
        )
    else:
        output.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
        console.print(f"[green]Wrote unsigned baseline:[/green] {output}")
        console.print(f"Circuit digest: {record.circuit_digest}")
        console.print(f"Readout digest: {record.readout_digest}")


@baseline_app.command("sign")
def baseline_sign(
    record_path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Unsigned baseline JSON"),
    private_key: Path = typer.Option(..., "--private-key", exists=True, dir_okay=False, help="Ed25519 PEM private key"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Output path (default: replace in place)"),
) -> None:
    """Sign a baseline record offline with an Ed25519 private key."""
    from qshield.integrity.baseline import BaselineError, load_baseline_file, sign_baseline

    try:
        record = load_baseline_file(record_path)
        key_pem = private_key.read_bytes()
        signed = sign_baseline(record, key_pem)
    except OSError as exc:
        _fail(f"cannot read key: {exc}")
        return
    except BaselineError as exc:
        # A passphrase-protected key reports itself here; ask rather than guess.
        if "passphrase" not in str(exc).lower():
            _fail(str(exc))
            return
        entered = typer.prompt("Private-key passphrase", hide_input=True)
        try:
            signed = sign_baseline(record, key_pem, passphrase=entered.encode("utf-8"))
        except BaselineError as inner:
            _fail(str(inner))
            return

    target = output or record_path
    target.write_text(json.dumps(signed.to_dict(), ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    console.print(f"[green]Signed baseline:[/green] {target}")
    console.print(f"Signer: {signed.signature['key_id'] if signed.signature else 'unknown'}")


@baseline_app.command("verify")
def baseline_verify(
    record_path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Signed baseline JSON"),
    public_key: Path = typer.Option(..., "--public-key", exists=True, dir_okay=False, help="Trusted Ed25519 PEM public key"),
    circuit: Path | None = typer.Option(
        None, "--circuit", exists=True, dir_okay=False,
        help="Also check this circuit against the digests the signature covers",
    ),
) -> None:
    """Verify a baseline signature, and optionally that a circuit is the approved one."""
    from qshield.core.parsers import parse_file
    from qshield.integrity.baseline import (
        BaselineError,
        baseline_digest,
        load_baseline_file,
        verify_signature,
    )

    try:
        record = load_baseline_file(record_path)
    except (OSError, BaselineError) as exc:
        _fail(str(exc), _EXIT_VERIFY_FAILED)
        return

    if record.signature is None:
        _fail("baseline is not signed, so there is nothing to trust", _EXIT_VERIFY_FAILED)
        return

    if not verify_signature(record, public_key.read_bytes()):
        _fail("signature does not verify against the supplied public key", _EXIT_VERIFY_FAILED)
        return

    console.print("[green]Signature valid (Ed25519)[/green]")
    console.print(f"Signer: {record.signature['key_id']}")
    console.print(f"Workload: {record.workload_id} (version {record.version})")
    console.print(f"Circuit digest: {record.circuit_digest}")

    if circuit is not None:
        try:
            circuit_digest, readout_digest = baseline_digest(parse_file(circuit))
        except (OSError, Exception) as exc:
            _fail(f"cannot parse {circuit}: {exc}", _EXIT_VERIFY_FAILED)
            return
        if circuit_digest != record.circuit_digest:
            _fail(
                f"{circuit} is NOT the approved artifact: digest {circuit_digest} "
                f"!= {record.circuit_digest}",
                _EXIT_VERIFY_FAILED,
            )
            return
        if readout_digest != record.readout_digest:
            _fail(
                "the circuit matches the approved circuit digest but its readout does not "
                "match the approved readout digest",
                _EXIT_VERIFY_FAILED,
            )
            return
        console.print("[green]Circuit and readout match the approved baseline[/green]")


@baseline_app.command("scan")
def baseline_scan(
    path: Path = typer.Argument(..., exists=True, help="Circuit file or directory to scan"),
    baseline: list[Path] = typer.Option(
        ..., "--baseline", "-b", exists=True, dir_okay=False,
        help="Signed baseline JSON; repeat to supply several",
    ),
    circuit: list[Path] = typer.Option(
        ..., "--circuit", "-c", exists=True, dir_okay=False,
        help="Approved reference circuit for the matching baseline; repeat in the same order",
    ),
    public_key: Path = typer.Option(..., "--public-key", exists=True, dir_okay=False, help="Trusted Ed25519 PEM public key"),
    workload: list[str] = typer.Option(
        [], "--workload", "-w",
        help="Workload the scanned circuit claims to be; repeat for several. "
             "Defaults to the single baseline's workload when only one is supplied.",
    ),
    fail_on: str = typer.Option("medium", "--fail-on", help="critical|high|medium|low|never"),
) -> None:
    """Scan against approved baselines: the T2.3 differential with real references."""
    from qshield.core.parsers import parse_file
    from qshield.integrity.baseline import BaselineError, BaselineRegistry, load_baseline_file
    from qshield.scanner import Scanner

    if len(baseline) != len(circuit):
        _fail(
            f"{len(baseline)} baseline(s) but {len(circuit)} reference circuit(s); "
            "supply them in matching order"
        )
        return

    key_pem = public_key.read_bytes()
    registry = BaselineRegistry()
    try:
        for record_path, circuit_path in zip(baseline, circuit, strict=True):
            record = load_baseline_file(record_path)
            if record.signature is None:
                _fail(f"{record_path} is unsigned; run `qshield baseline sign` first")
                return
            # Bind the reference the user supplied to the record, so the
            # evaluator can confirm it is the artifact the signature covers.
            # Records are frozen; replace rather than mutate.
            record = dataclasses.replace(record, reference_circuit=parse_file(circuit_path))
            registry.register(record, public_key_pem=key_pem)
    except (OSError, BaselineError) as exc:
        _fail(str(exc), _EXIT_VERIFY_FAILED)
        return

    # A candidate must declare which workload it claims to be. Without that the
    # lookup is by filename, which silently yields MISSING -> INDETERMINATE and
    # looks like a clean scan.
    targets = list(workload) or registry.workloads()
    if len(targets) != 1:
        _fail(
            f"{len(targets)} candidate workload(s) resolvable ({', '.join(targets) or 'none'}); "
            "pass --workload to say which one the scanned circuit claims to be"
        )
        return

    scanner = Scanner()
    files = sorted(path.rglob("*.qasm")) if path.is_dir() else [path]
    if not files:
        console.print(f"[yellow]No .qasm files found under {path}[/yellow]")
        raise typer.Exit(code=0)
    for file_path in files:
        # Name each circuit after the workload so the differential resolves.
        # The displayed name keeps the filename for readability.
        scanner.add_circuit(str(file_path), name=file_path.stem)
    # set_baselines maps every already-added circuit to the named workload, so it
    # must be called after add_circuit. Passing the workload here is why no
    # private attribute access is needed.
    scanner.set_baselines(registry, public_key_pem=key_pem, workload_id=targets[0])

    results = scanner.run(analyses=["static"])
    t23 = [f for f in results.findings if f.threat_type == "T2.3"]
    for finding in t23:
        console.print(f"[red]T2.3[/red] {finding.circuit_id}: {finding.description}")

    console.print(f"Baselines loaded: {len(registry.workloads())} ({', '.join(registry.workloads())})")
    console.print(f"Circuits scanned: {len(files)}")
    console.print(f"T2.3 findings: {len(t23)}")

    # INDETERMINATE and PASS are different answers and must never print alike.
    # A reference that does not match the signed digest lands here, not in PASS.
    outcomes = _t23_outcomes(results)
    for circuit_id, outcome, detail in outcomes:
        if outcome == "pass":
            console.print(f"[green]PASS[/green] {circuit_id}: {detail}")
        elif outcome == "finding":
            continue  # already printed above
        else:
            console.print(f"[yellow]{outcome.upper()}[/yellow] {circuit_id}: {detail}")
    if any(o == "indeterminate" for _, o, _ in outcomes):
        console.print(
            "[yellow]Indeterminate is not a pass: the readout was not compared "
            "against a trusted reference.[/yellow]"
        )

    order = ["low", "medium", "high", "critical"]
    if fail_on != "never" and fail_on in order:
        cutoff = order.index(fail_on)
        if any(order.index(f.severity) >= cutoff for f in results.findings if f.severity in order):
            raise typer.Exit(code=1)


def _t23_outcomes(results) -> list[tuple[str, str, str]]:
    """Read the per-circuit T2.3 outcome out of the static coverage checks."""
    out: list[tuple[str, str, str]] = []
    for circuit in results.coverage.get("circuits", []):
        checks = (circuit.get("analyses", {}).get("static", {}) or {}).get("checks", [])
        for check in checks:
            if check.get("id") == "t2_3_readout_differential":
                detail = "; ".join(check.get("reasons", [])) or "no detail"
                out.append((str(circuit.get("name")), str(check.get("outcome")), detail))
    return out


@baseline_app.command("inspect")
def baseline_inspect(
    record_path: Path = typer.Argument(..., exists=True, dir_okay=False, help="Baseline JSON"),
) -> None:
    """Show a baseline record without trusting it. Verification is separate."""
    from qshield.integrity.baseline import BaselineError, load_baseline_file

    try:
        record = load_baseline_file(record_path)
    except (OSError, BaselineError) as exc:
        _fail(str(exc))
        return

    console.print(f"Workload:    {record.workload_id}")
    console.print(f"Version:     {record.version}")
    console.print(f"Approved by: {record.approved_by}")
    console.print(f"Approved at: {record.approved_at}")
    console.print(f"Expires at:  {record.expires_at or '(never)'}")
    console.print(f"Circuit:     {record.circuit_digest}")
    console.print(f"Readout:     {record.readout_digest}")
    if record.revoked_at:
        console.print(f"[red]REVOKED[/red] at {record.revoked_at} by {record.revoked_by}: {record.revoke_reason}")
    if record.signature is None:
        console.print("[yellow]Unsigned — this record cannot be registered.[/yellow]")
    else:
        console.print(f"Signature:   {record.signature['algorithm']} {record.signature['key_id']}")
        console.print("[dim]Signature presence is not verification; run `qshield baseline verify`.[/dim]")
