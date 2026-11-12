"""Community signature pack auto-update (spec M3.4).

The pack is a set of YAML signature files plus a ``manifest.json``:

.. code-block:: json

    {
      "pack_version": "2026.1",
      "created": "2026-11-12",
      "min_qshield": "0.0.0",
      "files": [{"name": "QSig-2025-0001.yaml", "sha256": "..."}]
    }

Update protocol (deliberately simple, offline-friendly, verifiable):

1. download ``manifest.json`` from ``--url`` / ``QSHIELD_SIGNATURE_REPO`` /
   the bundled default (or use the in-package pack with ``--offline``);
2. download every file listed in the manifest into a staging directory;
3. verify each file's sha256 **and** that it loads as a valid signature —
   one bad file rejects the whole update (never a half-installed pack);
4. move the installed pack aside as ``<dir>.bak`` and atomically install
   the staged pack; on any failure the previous pack is restored;
5. ``rollback`` re-installs the ``.bak`` pack.

No signature content is ever executed; installation means copying files
after validation, nothing more.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_NAME = "manifest.json"
ENV_REPO_URL = "QSHIELD_SIGNATURE_REPO"
# Canonical publication URL for the community pack.  Overridable via
# ``QSHIELD_SIGNATURE_REPO`` — releases build this URL from the pack in
# ``src/qshield/signatures/community/``; until then set the env var or use
# ``--offline`` (installs the bundled pack).
DEFAULT_REPO_URL = (
    "https://raw.githubusercontent.com/qshield-project/qshield/main/"
    "src/qshield/signatures/community/manifest.json"
)


class UpdateError(RuntimeError):
    """Raised when an update cannot be completed (verify/swap failure)."""


@dataclass
class UpdateReport:
    ok: bool
    source: str
    pack_version: str | None
    installed_files: int
    install_dir: str
    backup_dir: str | None
    errors: list[str] = field(default_factory=list)


def user_community_dir() -> Path:
    return Path.home() / ".qshield" / "signatures" / "community"


def bundled_community_dir() -> Path:
    return Path(__file__).resolve().parent / "community"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fetch_bytes(url: str, timeout: int = 30) -> bytes:
    if url.startswith(("http://", "https://", "file://")):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 - URL is explicit/opt-in
                return resp.read()
        except urllib.error.URLError as exc:
            raise UpdateError(f"failed to fetch {url}: {exc}") from exc
    path = Path(url).expanduser()
    if not path.exists():
        raise UpdateError(f"signature source not found: {url}")
    return path.read_bytes()


def _pack_base_url(manifest_url: str) -> str:
    # strip trailing filename (http(s) or file path), keep the directory part
    if manifest_url.endswith(MANIFEST_NAME):
        return manifest_url[: -len(MANIFEST_NAME)]
    return manifest_url.rstrip("/") + "/"


def read_manifest(source: str, timeout: int = 30) -> dict:
    raw = _fetch_bytes(source, timeout=timeout)
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError(f"manifest at {source} is not valid JSON: {exc}") from exc
    if not isinstance(manifest, dict):
        raise UpdateError("manifest must be a JSON object")
    files = manifest.get("files")
    if not isinstance(files, list):
        raise UpdateError("manifest must contain a 'files' array (may be empty)")
    for entry in files:
        if not isinstance(entry, dict) or "name" not in entry or "sha256" not in entry:
            raise UpdateError("each manifest file entry needs 'name' and 'sha256'")
    return manifest


def verify_and_load_files(files: dict[str, bytes]) -> list[str]:
    """Validate every downloaded signature; returns a list of errors."""
    errors: list[str] = []
    import yaml  # local import keeps module import light

    from qshield.signatures.loader import SignatureError, validate_signature

    for name, data in sorted(files.items()):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            errors.append(f"{name}: not valid UTF-8")
            continue
        try:
            doc = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            errors.append(f"{name}: YAML error: {exc}")
            continue
        if not isinstance(doc, dict):
            errors.append(f"{name}: signature must be a YAML mapping")
            continue
        try:
            validate_signature(doc, source_path=name)
        except SignatureError as exc:
            errors.append(f"{name}: {exc}")
    return errors


def install_pack(files: dict[str, bytes], manifest: dict, install_dir: Path) -> UpdateReport:
    """Verify + atomically install ``files`` into ``install_dir``."""
    errors = verify_and_load_files(files)
    if errors:
        return UpdateReport(False, "staged", manifest.get("pack_version"), 0,
                            str(install_dir), None, errors)

    backup_dir = install_dir.with_name(install_dir.name + ".bak")
    install_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix="qshield_sigpack_", dir=str(install_dir.parent)))
    try:
        for name, data in files.items():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        staged_manifest = dict(manifest)
        staged_manifest["installed_at"] = datetime.now(timezone.utc).isoformat()
        (staging / MANIFEST_NAME).write_text(json.dumps(staged_manifest, indent=2), encoding="utf-8")

        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        if install_dir.exists():
            install_dir.rename(backup_dir)
        try:
            staging.rename(install_dir)
        except OSError:
            if backup_dir.exists() and not install_dir.exists():
                backup_dir.rename(install_dir)
            raise
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)

    return UpdateReport(True, "staged", manifest.get("pack_version"), len(files),
                        str(install_dir),
                        str(backup_dir) if backup_dir.exists() else None)


def update(url: str | None = None, install_dir: Path | None = None,
           offline: bool = False, timeout: int = 30) -> UpdateReport:
    """Download, verify and install the community signature pack."""
    install_dir = Path(install_dir) if install_dir else user_community_dir()

    if offline:
        pack = bundled_community_dir()
        manifest_path = pack / MANIFEST_NAME
        if not manifest_path.exists():
            raise UpdateError(f"bundled community pack missing manifest: {manifest_path}")
        manifest = read_manifest(str(manifest_path))
        bundled_files = {entry["name"]: (pack / entry["name"]).read_bytes()
                         for entry in manifest["files"]}
        base_errors = _check_hashes(bundled_files, manifest)
        if base_errors:
            raise UpdateError("bundled pack failed verification: " + "; ".join(base_errors))
        report = install_pack(bundled_files, manifest, install_dir)
        report.source = str(pack)
        return report

    source = url or os.environ.get(ENV_REPO_URL) or DEFAULT_REPO_URL
    manifest = read_manifest(source, timeout=timeout)
    base = _pack_base_url(source)
    files: dict[str, bytes] = {}
    for entry in manifest["files"]:
        files[entry["name"]] = _fetch_bytes(base + entry["name"], timeout=timeout)
    hash_errors = _check_hashes(files, manifest)
    if hash_errors:
        raise UpdateError("downloaded pack failed verification: " + "; ".join(hash_errors))
    report = install_pack(files, manifest, install_dir)
    report.source = source
    return report


def _check_hashes(files: dict[str, bytes], manifest: dict) -> list[str]:
    errors = []
    expected = {entry["name"]: entry["sha256"].lower() for entry in manifest["files"]}
    for name, want in expected.items():
        data = files.get(name)
        if data is None:
            errors.append(f"{name}: missing from download")
        elif sha256_bytes(data).lower() != want:
            errors.append(f"{name}: sha256 mismatch")
    return errors


def rollback(install_dir: Path | None = None) -> bool:
    """Restore the previous pack kept as ``<dir>.bak``.  Returns True on success."""
    install_dir = Path(install_dir) if install_dir else user_community_dir()
    backup_dir = install_dir.with_name(install_dir.name + ".bak")
    if not backup_dir.exists():
        return False
    current_tmp = install_dir.with_name(install_dir.name + ".current_tmp")
    if install_dir.exists():
        install_dir.rename(current_tmp)
    backup_dir.rename(install_dir)
    if current_tmp.exists():
        shutil.rmtree(current_tmp)
    return True


def installed_status(install_dir: Path | None = None) -> dict:
    install_dir = Path(install_dir) if install_dir else user_community_dir()
    if not install_dir.exists():
        return {"installed": False, "install_dir": str(install_dir),
                "files": 0, "pack_version": None}
    manifest_path = install_dir / MANIFEST_NAME
    pack_version = None
    if manifest_path.exists():
        try:
            pack_version = json.loads(manifest_path.read_text(encoding="utf-8")).get("pack_version")
        except (json.JSONDecodeError, OSError):
            pack_version = "unknown"
    files = sorted(p.name for p in install_dir.glob("*.y*ml"))
    return {"installed": True, "install_dir": str(install_dir),
            "files": len(files), "pack_version": pack_version,
            "signatures": files}


def build_manifest(pack_dir: Path, pack_version: str, created: str | None = None,
                   min_qshield: str = "0.0.0") -> dict:
    """Maintainers: regenerate ``manifest.json`` from the YAML files present."""
    pack_dir = Path(pack_dir)
    entries = []
    for path in sorted(pack_dir.glob("*.yaml")) + sorted(pack_dir.glob("*.yml")):
        entries.append({"name": path.name,
                        "sha256": sha256_bytes(path.read_bytes())})
    if not entries:
        import sys
        print(f"note: no signature YAML files in {pack_dir}; manifest will list zero files", file=sys.stderr)
    manifest = {
        "pack_version": pack_version,
        "created": created or datetime.now(timezone.utc).date().isoformat(),
        "min_qshield": min_qshield,
        "files": entries,
    }
    (pack_dir / MANIFEST_NAME).write_text(json.dumps(manifest, indent=2) + "\n",
                                          encoding="utf-8")
    return manifest
