#!/usr/bin/env bash
# Trim regenerable artifacts from the QSHIELD workspace.
#
# The workspace snapshot has a soft cap (~10,000 files). Test environments,
# build outputs and tool caches can push a working tree past that, which risks
# losing real files from the snapshot. Everything removed here is either
# gitignored or reproducible in one command.
#
# Usage:
#   scripts/clean_workspace.sh          # show what would be removed
#   scripts/clean_workspace.sh --apply  # actually remove it
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APPLY=0
[ "${1:-}" = "--apply" ] && APPLY=1

# Paths inside the repository that are gitignored and regenerable.
REPO_TARGETS=(
  ".mypy_cache"
  ".pytest_cache"
  ".hypothesis"
  ".ruff_cache"
  "build"
  "dist-site"
  "src/qshield.egg-info"
  ".coverage"
)

echo "QSHIELD workspace"
echo "  repository : $REPO"
echo "  tracked    : $(git -C "$REPO" ls-files | wc -l | tr -d ' ') files"
echo "  on disk    : $(du -sh "$REPO" 2>/dev/null | cut -f1)"

removed=0
for target in "${REPO_TARGETS[@]}"; do
  path="$REPO/$target"
  if [ -e "$path" ]; then
    size=$(du -sh "$path" 2>/dev/null | cut -f1)
    count=$(find "$path" -type f 2>/dev/null | wc -l | tr -d ' ')
    echo "  $target ($size, $count files)"
    if [ "$APPLY" -eq 1 ]; then rm -rf "$path"; fi
    removed=$((removed + 1))
  fi
done

# Byte-compiled caches are always safe to drop.
cache_dirs=$(find "$REPO" -name __pycache__ -type d -not -path "*/node_modules/*" 2>/dev/null | wc -l | tr -d ' ')
if [ "$cache_dirs" -gt 0 ]; then
  echo "  __pycache__ ($cache_dirs directories)"
  if [ "$APPLY" -eq 1 ]; then
    find "$REPO" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
  fi
  removed=$((removed + 1))
fi

# Stray virtualenvs anywhere in the workspace are rebuildable and are the
# single largest source of file-count bloat.
WORKSPACE="$(dirname "$REPO")"
stray=$(find "$WORKSPACE" -maxdepth 3 -name "civenv" -type d 2>/dev/null | wc -l | tr -d ' ')
if [ "$stray" -gt 0 ]; then
  echo "  stray venvs ($stray)"
  if [ "$APPLY" -eq 1 ]; then
    find "$WORKSPACE" -maxdepth 3 -name "civenv" -type d -prune -exec rm -rf {} + 2>/dev/null || true
  fi
  removed=$((removed + 1))
fi

if [ "$removed" -eq 0 ]; then
  echo "  nothing to clean"
elif [ "$APPLY" -eq 1 ]; then
  echo "cleaned — repository is now $(du -sh "$REPO" 2>/dev/null | cut -f1)"
else
  echo "dry run — re-run with --apply to remove the paths above"
fi
