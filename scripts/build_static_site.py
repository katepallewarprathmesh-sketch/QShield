#!/usr/bin/env python3
"""Build the GitHub Pages site — the *real* QSHIELD engine in the browser.

Unlike the old static demo (precomputed responses replayed to look live), the
page built here runs the actual engine: a pinned, self-hosted Pyodide
(CPython 3.12, v0.27.7) runtime plus the QSHIELD wheel built from this
checkout. Every analysis the page serves — scan, compare, robustness probe,
policy scoring, overview, policies — executes locally in the visitor's tab.

  - nothing you paste leaves the machine (no network calls after page load)
  - served 100% from this same origin: pyodide runtime, wheels and the
    fixture corpus are all vendored into the Pages artifact (no CDN)
  - the 417-circuit bundled corpus ships as vendor/fixtures.zip so Policy
    Studio scoring runs on the real corpus in-browser

AI Triage stays honest: a static page cannot hold a Sarvam API key, so the AI
endpoints return precomputed outputs of the real engine + Sarvam AI on the
bundled ancilla fixture — always labeled as such in the UI — or a clear error
for anything else.

Download integrity: the Pyodide core files are pinned by SHA256 below; the
package wheels are verified against the pinned pyodide-lock.json (itself one
of the pinned core files). Builds fail closed on any mismatch.

Usage:
    python3 scripts/build_static_site.py [--out dist-site] [--offline] [--skip-wheel]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CANNED_AI = {
    "triage": REPO / "scripts" / "static_demo_canned" / "ai_triage_ancilla.json",
    "report_hi": REPO / "scripts" / "static_demo_canned" / "ai_report_ancilla_hi-IN.json",
    "report_mr": REPO / "scripts" / "static_demo_canned" / "ai_report_ancilla_mr-IN.json",
}
BOOTSTRAP = REPO / "scripts" / "site" / "bootstrap.js"
FIXTURE_CORPUS = ("clean_circuits", "malicious_circuits")
FIXTURES_ROOT = REPO / "tests" / "fixtures"

PYODIDE_VERSION = "0.27.7"  # ships CPython 3.12.7, inside qshield's tested matrix (3.10-3.13)
PYODIDE_BASE = f"https://cdn.jsdelivr.net/pyodide/v{PYODIDE_VERSION}/full/"
# SHA256 of the Pyodide core files, measured 2026-11-16 from the release
# distribution. Package wheels are verified against this lock file.
PYODIDE_CORE = {
    "pyodide.mjs": "04c052c815abb0bf2981fa38c2dfa58e3120ee5288c956df2b2a15e301782c5f",
    "pyodide.asm.js": "6b4c90de5b7172873f04f21884d0e9d2274e305fe32116558fe3e4fbe3618d51",
    "pyodide.asm.wasm": "a50dd1843f805a0b7c45b61037ee0d7b26dfe85efe0e18ef95a34ad24e401f5f",
    "python_stdlib.zip": "16611534726e5d8ac2bd8f926410b2dcb8d6f49aa24913463533b457a2115c16",
    "pyodide-lock.json": "9c45b916001a750f4102fc287494f3eab215909c7535c626a20db80fd6333e2c",
}
# Packages the engine needs (its only third-party imports): numpy, jinja2
# (+ markupsafe), pyyaml. Hashes come from the pinned lock file.
PYODIDE_PACKAGES = ("numpy", "jinja2", "markupsafe", "pyyaml")

banner_css = """
.demo-banner { background:#131f10; border-bottom:1px solid #2c4a1e; color:#b8e986; font-size:12px; padding:9px 18px; display:flex; gap:12px; align-items:center; justify-content:center; flex-wrap:wrap; text-align:center; }
.demo-banner code { background:#0b141f; padding:2px 7px; border-radius:6px; font-size:11px; color:#8ff0c8; }
.demo-banner button { margin-left:6px; background:none; border:1px solid #2c4a1e; color:#b8e986; border-radius:6px; cursor:pointer; padding:1px 9px; }
"""

banner = """
<div class="demo-banner" id="demo-banner"><span><b>REAL ENGINE</b> — the real QSHIELD engine runs in your browser (CPython via Pyodide, served from this same site). Nothing you paste leaves this tab. <span class="banner-note">loading… first load fetches ~18 MB once, cached afterwards</span> · on this static page the AI tab shows precomputed real outputs (labeled) — live AI runs locally. Full local experience: <code>git clone https://github.com/katepallewarprathmesh-sketch/QShield &amp;&amp; pip install -e . &amp;&amp; qshield ui</code></span><button onclick="document.getElementById('demo-banner').remove()" aria-label="dismiss">&times;</button></div>
"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _download(url: str) -> bytes:
    import urllib.request

    with urllib.request.urlopen(url, timeout=600) as response:  # noqa: S310 — URL is our pinned https PYODIDE_BASE constant
        return response.read()


def _vendor_pyodide(vendor: Path, *, offline: bool, fresh: bool) -> list[Path]:
    target = vendor / "pyodide"
    target.mkdir(parents=True, exist_ok=True)
    assets: list[Path] = []

    if offline:
        missing = [name for name in PYODIDE_CORE if not (target / name).exists()]
        if missing:
            raise RuntimeError(f"--offline but missing core files in {target}: {missing}")
        for name in PYODIDE_CORE:
            assets.append(target / name)
    else:
        for name, expected in PYODIDE_CORE.items():
            if not fresh and (target / name).exists() and _sha256((target / name).read_bytes()) == expected:
                assets.append(target / name)
                continue
            data = _download(PYODIDE_BASE + name)
            got = _sha256(data)
            if got != expected:
                raise RuntimeError(f"sha256 mismatch for {name}: {got} != {expected} — refusing to build")
            (target / name).write_bytes(data)
            assets.append(target / name)

    lock = json.loads((target / "pyodide-lock.json").read_text())
    for name in PYODIDE_PACKAGES:
        info = lock["packages"].get(name)
        if info is None:
            raise RuntimeError(f"package {name!r} not found in pyodide-lock.json")
        fname, expected = info["file_name"], info["sha256"]
        if offline:
            candidate = target / fname
            if not candidate.exists():
                raise RuntimeError(f"--offline but missing package wheel: {fname}")
            assets.append(candidate)
            continue
        if not fresh and (target / fname).exists() and _sha256((target / fname).read_bytes()) == expected:
            assets.append(target / fname)
            continue
        data = _download(PYODIDE_BASE + fname)
        got = _sha256(data)
        if got != expected:
            raise RuntimeError(f"sha256 mismatch for {fname}: {got} != {expected} — refusing to build")
        (target / fname).write_bytes(data)
        assets.append(target / fname)
    return assets


def _build_wheel(vendor: Path, *, skip: bool) -> Path:
    existing = list(vendor.glob("qshield-*.whl"))
    if skip and existing:
        return existing[0]
    for stale in existing:
        stale.unlink()
    cmd = [sys.executable, "-m", "pip", "wheel", "--no-deps", "--wheel-dir", str(vendor), str(REPO)]
    print("+", " ".join(cmd))
    subprocess.run(cmd, check=True)  # noqa: S603 — fixed argv, no shell, sys.executable
    wheels = list(vendor.glob("qshield-*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly one qshield wheel, found {wheels}")
    target = vendor / "qshield.whl"
    wheels[0].rename(target)
    return target


def _zip_fixtures(vendor: Path) -> Path:
    out = vendor / "fixtures.zip"
    if out.exists():
        out.unlink()
    written = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        for corpus in FIXTURE_CORPUS:
            for dirpath, _dirs, files in os.walk(FIXTURES_ROOT / corpus):
                for fname in sorted(files):
                    if not fname.endswith(".qasm"):
                        continue
                    full = Path(dirpath) / fname
                    arc = f"{corpus}/{full.relative_to(FIXTURES_ROOT / corpus)}"
                    info = zipfile.ZipInfo(arc, date_time=(1980, 1, 1, 0, 0, 0))
                    info.external_attr = 0o644 << 16
                    zf.writestr(info, full.read_bytes(), zipfile.ZIP_DEFLATED)
                    written += 1
    if written != 417:
        raise RuntimeError(f"expected 417 fixture .qasm files, archived {written}")
    return out


def _canned_ai_json() -> str:
    canned = {key: json.loads(path.read_text()) for key, path in CANNED_AI.items()}
    return json.dumps(canned, ensure_ascii=False).replace("</", "<\\/")


def _render_index() -> str:
    sys.path.insert(0, str(REPO / "src"))
    from qshield.ui.page import WORKBENCH_HTML

    html = WORKBENCH_HTML
    for needle in ("</style>", "<body>", "</body>"):
        if html.count(needle) != 1:
            raise RuntimeError(f"WORKBENCH_HTML anchor {needle!r} not unique/found")
    html = html.replace("</style>", banner_css + "</style>", 1)
    html = html.replace("<body>", "<body>\n" + banner, 1)
    inject = (
        f"<script>window.__QSHIELD_AI_CANNED__ = {_canned_ai_json()};</script>\n"
        '<script src="./bootstrap.js"></script>\n'
    )
    # Inject BEFORE the page's inline script so window.fetch is already
    # intercepted when the page fires its initial /api/* calls.
    marker = "<script>\n\"use strict\";"
    if html.count(marker) != 1:
        raise RuntimeError("main inline script marker not unique/found in WORKBENCH_HTML")
    return html.replace(marker, inject + marker, 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=REPO / "dist-site", help="output directory")
    parser.add_argument("--offline", action="store_true", help="reuse vendored downloads in --out (no network)")
    parser.add_argument("--skip-wheel", action="store_true", help="reuse the existing vendored qshield wheel")
    parser.add_argument("--incremental", action="store_true", help="keep already-verified downloads (default repacks)")
    args = parser.parse_args()

    out: Path = args.out
    vendor = out / "vendor"
    if out.exists() and not args.offline:
        shutil.rmtree(out)
    out.mkdir(parents=True, exist_ok=True)

    assets = _vendor_pyodide(vendor, offline=args.offline, fresh=not args.incremental)
    wheel = _build_wheel(vendor, skip=args.skip_wheel)
    fixtures = _zip_fixtures(vendor)
    (out / "bootstrap.js").write_bytes(BOOTSTRAP.read_bytes())
    (out / "index.html").write_text(_render_index(), encoding="utf-8")

    import qshield

    manifest = {
        "qshield_version": qshield.__version__,
        "pyodide_version": PYODIDE_VERSION,
        "engine": "real (Pyodide CPython, self-hosted) — no precomputed analysis responses",
        "ai": "precomputed real outputs on the ancilla fixture, labeled; live AI unavailable on static pages",
        "files": [],
    }
    lines: list[str] = []
    for fpath in sorted(out.rglob("*")):
        if not fpath.is_file() or fpath.name in ("manifest.json", "SHA256SUMS"):
            continue
        digest = _sha256(fpath.read_bytes())
        lines.append(f"{digest}  {fpath.relative_to(out)}")
        manifest["files"].append({"path": str(fpath.relative_to(out)), "sha256": digest, "bytes": fpath.stat().st_size})
    (out / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")

    total = sum(f.stat().st_size for f in out.rglob("*") if f.is_file())
    print(f"built {out} — {len(assets)} vendored pyodide assets, wheel={wheel.name}, "
          f"fixtures={fixtures.stat().st_size}B, total ≈ {total / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
