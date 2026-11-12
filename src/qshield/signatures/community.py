"""Community signature pack: discovery, loading, verification.

The bundled pack lives in ``qshield/signatures/community/`` (shipped as
package data and treated as the canonical community repository — merging a
signature into that directory and tagging a release publishes it to the
auto-update channel).  Users may install a newer pack fetched over HTTPS
with :func:`qshield.signatures.updater.update`; the scanner prefers the
installed pack over the bundled one.

All pack members are validated through the same loader as builtin
signatures; a broken pack degrades to warnings, never to a crash or to
silently skipped files.
"""

from __future__ import annotations

from pathlib import Path

from qshield.signatures.loader import Signature, load_directory
from qshield.signatures.updater import (
    MANIFEST_NAME,
    bundled_community_dir,
    sha256_bytes,
    user_community_dir,
)


def community_signatures() -> tuple[list[Signature], list[str]]:
    """Bundled community pack. Returns (signatures, errors)."""
    pack = bundled_community_dir()
    if not (pack / MANIFEST_NAME).exists():
        return [], [f"bundled community pack missing manifest: {pack / MANIFEST_NAME}"]
    return load_pack(pack)


def installed_community_signatures() -> tuple[list[Signature], list[str]]:
    """User-installed community pack. Returns (signatures, errors) — ([], []) if not installed."""
    from qshield.signatures.updater import installed_status

    if not installed_status()["installed"]:
        return [], []
    return load_pack(user_community_dir())


def load_pack(pack: Path) -> tuple[list[Signature], list[str]]:
    """Load every YAML signature in ``pack``; errors are collected, not raised."""
    try:
        return load_directory(pack), []
    except Exception as exc:  # loader reports first failure; report and return what loaded
        return [], [f"{pack}: {exc}"]


def preferred_community_signatures() -> tuple[list[Signature], list[str]]:
    """Installed pack when present and valid, else the bundled pack."""
    installed, errors = installed_community_signatures()
    if installed:
        return installed, errors
    return community_signatures()


def verify_pack(pack_dir: Path | None = None) -> list[str]:
    """Check manifest sha256s against files on disk. Returns error list ([] == ok)."""
    pack = Path(pack_dir) if pack_dir else bundled_community_dir()
    errors: list[str] = []
    manifest_path = pack / MANIFEST_NAME
    if not manifest_path.exists():
        return [f"missing {MANIFEST_NAME} in {pack}"]
    import json

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"manifest unreadable: {exc}"]
    for entry in manifest.get("files", []):
        name, want = entry.get("name"), str(entry.get("sha256", "")).lower()
        path = pack / name
        if not path.exists():
            errors.append(f"{name}: listed in manifest but missing on disk")
            continue
        got = sha256_bytes(path.read_bytes()).lower()
        if got != want:
            errors.append(f"{name}: sha256 drift (manifest {want[:12]}… != disk {got[:12]}…)")
    listed = {e.get("name") for e in manifest.get("files", [])}
    for extra in sorted(p.name for p in pack.glob("*.yaml")):
        if extra not in listed:
            errors.append(f"{extra}: present on disk but not in manifest")
    return errors
