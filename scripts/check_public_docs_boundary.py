#!/usr/bin/env python3
"""Fail if internal docs/ content is committed or shipped in public artifacts."""

from __future__ import annotations

import argparse
import tarfile
import zipfile
from pathlib import Path, PurePosixPath


class BoundaryError(RuntimeError):
    """An internal documentation path crossed the public boundary."""


def _is_docs_path(name: str) -> bool:
    normalized = name.replace("\\", "/").strip("/")
    return "docs" in PurePosixPath(normalized).parts


def check_source_tree(root: Path) -> None:
    if (root / "docs").exists():
        raise BoundaryError(f"internal documentation directory must not exist: {root / 'docs'}")


def check_distributions(dist: Path) -> None:
    for archive in sorted(dist.glob("*.tar.gz")):
        with tarfile.open(archive, "r:gz") as package:
            leaked = [member.name for member in package.getmembers() if _is_docs_path(member.name)]
        if leaked:
            raise BoundaryError(f"internal docs found in {archive.name}: {leaked[:5]}")

    for archive in sorted(dist.glob("*.whl")):
        with zipfile.ZipFile(archive) as package:
            leaked = [name for name in package.namelist() if _is_docs_path(name)]
        if leaked:
            raise BoundaryError(f"internal docs found in {archive.name}: {leaked[:5]}")

    if not list(dist.glob("*.tar.gz")) or not list(dist.glob("*.whl")):
        raise BoundaryError(f"expected an sdist and wheel in {dist}")


def check_public_site(site: Path) -> None:
    page = site / "security-architecture.html"
    if not page.is_file():
        raise BoundaryError(f"public security architecture page missing from site build: {page}")
    html = page.read_text(encoding="utf-8")
    if "QSHIELD Security Architecture" not in html or "__QSHIELD_VERSION__" in html:
        raise BoundaryError("public security architecture page is malformed or has an unresolved version")
    legacy = site / "threat-model.html"
    if legacy.is_file() and "security-architecture.html" not in legacy.read_text(encoding="utf-8"):
        raise BoundaryError("legacy threat-model.html must redirect to security-architecture.html")
    for path in site.rglob("*"):
        if path.is_file() and _is_docs_path(path.relative_to(site).as_posix()):
            raise BoundaryError(f"internal docs path found in public site: {path.relative_to(site)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--dist", type=Path)
    parser.add_argument("--site", type=Path)
    args = parser.parse_args()

    check_source_tree(args.root)
    if args.dist is not None:
        check_distributions(args.dist)
    if args.site is not None:
        check_public_site(args.site)
    print("public docs boundary OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
