#!/usr/bin/env bash
# Reproduce the CI gate locally, in the same order CI runs it.
#
# Why this exists: CI runs Python 3.10-3.13 and a local sandbox is usually one
# version. `datetime.UTC` shipped green locally and broke both 3.10 jobs. This
# script fails loudly on interpreter drift rather than letting it reach CI.
#
#   ./scripts/verify.sh            # full gate
#   ./scripts/verify.sh --fast     # skip benchmarks and coverage (inner loop)
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

fails=0
step() {
  local name="$1"; shift
  printf '%-46s' "$name"
  if out=$("$@" 2>&1); then
    echo "OK"
  else
    echo "FAIL"
    echo "$out" | tail -25 | sed 's/^/    /'
    fails=$((fails + 1))
  fi
}

# ---------------------------------------------------------------- environment
echo "== environment =="
python -c 'import sys; print(f"  python  {sys.version.split()[0]}  ({sys.executable})")'
python - <<'PY'
import sys
# CI covers 3.10-3.13. Warn only on the floor, which is where syntax breaks.
if sys.version_info < (3, 10):
    print("  ERROR: Python < 3.10 is below the CI floor"); raise SystemExit(1)
if sys.version_info >= (3, 11):
    print("  note: datetime.UTC and similar 3.11+ APIs will pass here but fail CI on 3.10")
PY
echo

# ---------------------------------------------------------------- static gates
echo "== static =="
step "ruff check"            ruff check src tests examples benchmarks
step "mypy src"              mypy src
step "docs boundary"         python scripts/check_public_docs_boundary.py
step "invariants"            python scripts/check_invariants.py
echo

# ---------------------------------------------------------------- tests
echo "== tests =="
if [ "$FAST" -eq 1 ]; then
  step "pytest (fast, no coverage)" pytest -q -x
else
  step "pytest + coverage"    pytest -q --cov=qshield --cov-report=term-missing
fi
echo

# ---------------------------------------------------------------- benchmarks
if [ "$FAST" -eq 0 ]; then
  echo "== benchmarks (reproducibility) =="
  step "corpus TPR/FPR reproducible"   python benchmarks/benchmark.py --check
  step "T2.3 differential reproducible" python benchmarks/t23_baseline_eval.py --check
  echo
fi

# ---------------------------------------------------------------- verdict
if [ "$fails" -eq 0 ]; then
  echo "ALL GATES PASSED"
  exit 0
fi
echo "$fails GATE(S) FAILED"
exit 1
