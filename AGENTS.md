# Working in this repository

Rules for any agent (or human) making changes here, and the verification
commands that decide whether a change is done.

The short version: **a change is complete when `./scripts/verify.sh` passes.**
Not when the code looks right, not when a plausible test was written. Several
failures in this repository's history came from trusting a result instead of
running it.

## Verify before claiming anything

```bash
./scripts/verify.sh          # full gate: lint, types, tests, benchmarks
./scripts/verify.sh --fast   # inner loop: lint, types, tests only
```

`verify.sh` mirrors `.github/workflows/ci.yaml`. Do not report a change as
working without having run it and read the output.

### The interpreter trap

CI runs Python 3.10 through 3.13. A local sandbox is usually one version, often
3.13. APIs such as `datetime.UTC`, `StrEnum`, and `typing.Self` exist only in
3.11+, so they pass locally and fail collection on the 3.10 jobs.

This has already happened once (`6294b4c`). Use `timezone.utc`, not `UTC`. If a
change touches version-sensitive APIs, say which versions you actually ran.

## Hard rules

These are enforced by `scripts/check_invariants.py` and, where noted, by CI.
They exist because each was violated at least once.

1. **No `docs/` or `specs/` directories, and no stray `.md` files.** Internal
   notes, audits and design write-ups stay out of this repository: they expose
   implementation detail that does not belong in a public package. Keep prose in
   the README, the CHANGELOG, and inline docstrings. `.md` files already present
   are pre-existing specs for released formats — do not add more.

2. **One producer per threat type.** T2.3 findings may only be constructed in
   `src/qshield/integrity/evaluate.py`. T2.3 previously had two independent
   emitters; fixing one left the other generating all 68 false positives.
   Adding a pattern-based T2.3 emitter re-introduces that defect.

3. **Never edit benchmark results by hand.** `benchmarks/results/*.json` are
   outputs. Change the code, then `python benchmarks/benchmark.py --write` and
   commit the diff with the code change that caused it.

4. **Never change fixture labels, delete hard examples, or tune a threshold to
   move a number.** If a detector is weak, report the weakness. A benchmark
   improved by relabelling is worse than a benchmark that reports a low score,
   because the low score is at least true.

5. **Historical results stay marked.** Any results file that is not
   `benchmark-v1.json` must carry `"archived": true` and an `archived_note`, so
   it can never be quoted as current.

## Reporting results

State the measurement, the configuration it was measured in, and what it does
not cover. Specifically:

- Give TPR *and* FPR *and* precision together. Quoting only the flattering one
  is the failure mode this repository has actually had.
- Say when a result depends on a configuration. T2.3 detects 20/20 **only when a
  trusted baseline exists**; without one it reports `INDETERMINATE` and detects
  0/20. Both numbers are the honest answer to different questions.
- Distinguish "detected" from "detected independently". 51 of 52 T1.3
  detections turned out to be T2.3-assisted; the published recall was borrowed.
- Never claim physical hardware security, guaranteed detection, or correctness
  of arbitrary algorithms.
- Benchmark figures are fixture-corpus measurements, not production rates.

## Architecture notes that save time

- `src/qshield/ui/static/workbench.js` and `scripts/site/bootstrap.js` are
  **TypeScript build outputs**. Edit `frontend/src/*.ts`, then rebuild. Editing
  the `.js` directly loses the change on the next build.
- Circuit identity uses `core/canonicalization.py` (`qshield-circuit-c14n-v1`).
  Do not hash a circuit with anything else; digests must stay comparable across
  versions.
- `qshield ui` defaults to a port that is often occupied; pass `--port 8899`.
- Signing and verification live in `provenance/manifest.py` and
  `integrity/baseline.py`. Both use real Ed25519; do not stub them in tests that
  claim to test verification.

## Verifying this file's claims

Everything above is checkable. If a command in this file stops working, fix the
file — stale instructions are worse than none, because they get followed.
