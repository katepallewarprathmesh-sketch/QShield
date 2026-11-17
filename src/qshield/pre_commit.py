"""Pre-commit runner for scanning staged OpenQASM files."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from qshield import Scanner
from qshield.reporting.finding import SEVERITY_ORDER

_FAIL_LEVELS = ("critical", "high", "medium", "low", "never")
_SUPPORTED_SUFFIXES = {".qasm", ".qasm2", ".qasm3"}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qshield-pre-commit",
        description="Scan staged OpenQASM files with QSHIELD's static checks.",
    )
    parser.add_argument(
        "--fail-on",
        choices=_FAIL_LEVELS,
        default="high",
        help="Fail at or above this finding severity (default: high).",
    )
    parser.add_argument("paths", nargs="*", type=Path, help="OpenQASM files selected by pre-commit.")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Scan each supplied OpenQASM file; parse errors and threshold findings fail closed."""
    args = _parser().parse_args(argv)
    paths = [path for path in args.paths if path.is_file()]
    invalid = [path for path in args.paths if path.exists() and path.suffix.lower() not in _SUPPORTED_SUFFIXES]
    if invalid:
        for path in invalid:
            print(f"QSHIELD pre-commit: unsupported file type: {path}", file=sys.stderr)
        return 2
    if not paths:
        return 0

    failed = False
    parse_failed = False
    for path in paths:
        if path.suffix.lower() not in _SUPPORTED_SUFFIXES:
            print(f"QSHIELD pre-commit: unsupported file type: {path}", file=sys.stderr)
            parse_failed = True
            continue
        try:
            scanner = Scanner(config="default", parallel=False)
            scanner.add_circuit(path, name=path.name)
            results = scanner.run(analyses=["static", "supply_chain"])
        except Exception as exc:
            print(f"QSHIELD pre-commit: could not scan {path}: {exc}", file=sys.stderr)
            parse_failed = True
            continue

        if results.findings:
            for finding in results.findings:
                print(f"{path}: {finding.severity.upper()} {finding.threat_type}: {finding.title}")
        else:
            print(f"{path}: no findings above the configured checks")
        if args.fail_on != "never":
            threshold = SEVERITY_ORDER[args.fail_on]
            failed = failed or any(f.severity_rank >= threshold for f in results.findings)

    if parse_failed:
        return 2
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
