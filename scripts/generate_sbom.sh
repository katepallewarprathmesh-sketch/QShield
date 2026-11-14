#!/usr/bin/env bash
# Generate the CycloneDX SBOM for QSHIELD's runtime dependency closure.
#
#   scripts/generate_sbom.sh [OUTPUT_DIR]     (default: dist/)
#
# Two throwaway venvs: one holding only `qshield` (+ its transitive runtime
# deps), one holding the SBOM tooling — so tooling never leaks into the SBOM.
# qshield itself is marked as the root component (--pyproject, library).
#
# Produces qshield-sbom.json and qshield-sbom.xml in OUTPUT_DIR.
# CI runs this on every push and on tags; the release workflow attaches both
# files to GitHub Releases.
set -euo pipefail

cd "$(dirname "$0")/.."
OUT_DIR="${1:-dist}"
mkdir -p "$OUT_DIR"

export PIP_NO_INPUT=1 PIP_QUIET=1
WORK="$(mktemp -d "${TMPDIR:-/tmp}/qshield-sbom.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

python3 -m venv "$WORK/pkg"
"$WORK/pkg/bin/pip" install --upgrade pip
"$WORK/pkg/bin/pip" install .
"$WORK/pkg/bin/pip" freeze > "$OUT_DIR/requirements-resolved.txt"
# normalize the editable/local path so the published file carries no local paths
python3 - "$OUT_DIR/requirements-resolved.txt" <<'PY'
import re, sys, tomllib
from pathlib import Path
version = tomllib.loads(Path("pyproject.toml").read_text())["project"]["version"]
path = Path(sys.argv[1])
path.write_text(re.sub(r"^qshield @ .*$", f"qshield=={version}", path.read_text(), flags=re.M))
PY
# drop pip/setuptools/wheel so installer tooling is not inventoried as a dependency
"$WORK/pkg/bin/pip" uninstall -y -q pip setuptools wheel || true

python3 -m venv "$WORK/tool"
"$WORK/tool/bin/pip" install --upgrade pip cyclonedx-bom

SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || date +%s)" \
"$WORK/tool/bin/cyclonedx-py" environment "$WORK/pkg/bin/python" \
    --pyproject pyproject.toml --mc-type library --output-reproducible \
    --of JSON -o "$OUT_DIR/qshield-sbom.json"

SOURCE_DATE_EPOCH="$(git log -1 --format=%ct 2>/dev/null || date +%s)" \
"$WORK/tool/bin/cyclonedx-py" environment "$WORK/pkg/bin/python" \
    --pyproject pyproject.toml --mc-type library --output-reproducible \
    --of XML -o "$OUT_DIR/qshield-sbom.xml"

echo "SBOM written to $OUT_DIR/qshield-sbom.{json,xml}"
