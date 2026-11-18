# QSHIELD per-run coverage report v1

Spec ID: `qshield-coverage-v1`.

Every scanner result includes an additive `coverage` object. It describes which analysis pipelines were requested, completed, inconclusive, not started, or not applicable for this run. It is a record of execution scope, not a safety verdict and not a detector-by-detector or gate-by-gate completeness claim.

## Status semantics

- `completed`: the reported pipeline/check executed. This does not mean it detected every possible issue, nor that its result is a pass.
- `inconclusive`: work ran but could not establish its intended result, or the input had explicitly excluded/unsupported constructs. Reasons are mandatory context and must not be mapped to a clean result.
- `skipped`: the requested check could not start or was deliberately omitted because a prerequisite was unavailable (for example, an optional backend or reference artifact). It contributes to the inconclusive overall status and is never a pass.
- `not_run`: the analysis pipeline was not requested, or execution did not start (for example, a scan timeout).
- `not_applicable`: the check has no applicable input (for example, supply-chain analysis without dependency inputs).

## Top-level fields

- `spec_version`: this schema identifier.
- `granularity`: fixed statement of pipeline-level coverage.
- `requested_analyses`: caller-requested pipeline names.
- `overall_status`: `complete` only when every requested pipeline run started without an inconclusive result; otherwise `inconclusive`.
- `summary`: circuit totals, processed totals, inconclusive/not-started pipeline counts, and counts by status and pipeline.
- `circuits`: one record per registered circuit with `circuit_id`, `name`, `processed`, and per-analysis outcomes. Static coverage includes structural analysis, signatures, expected-unitary verification, ancilla analysis, and parser notes.
- `supply_chain`: supply-chain pipeline status/reasons/details.
- `unsupported_analyses`: unknown requested analysis names.
- `limitations`: explicit limits on interpreting this report.

When the caller requests a circuit analysis but no circuits are registered, `overall_status` is `inconclusive`: no circuit pipeline could be executed. A missing optional dependency or reference artifact is also inconclusive, not a pass. Pipeline execution status is distinct from findings and policy decisions; this report does not define pass/fail policy.

## Privacy and compatibility

The report contains circuit names and identifiers already present in scan output. It does not contain source text, circuit gates, telemetry, or network-derived data. Future changes are additive or use a new spec identifier when semantics change.
