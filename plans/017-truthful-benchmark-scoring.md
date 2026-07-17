# Plan 017: Score complete benchmark output and real recorded spend

> Executor: do not run the paid workflow. Corrected metrics are expected to
> invalidate the Cycle 3 mock baseline; regenerate it only from deterministic
> committed fixtures with explicit provenance.

## Status

- **State**: DONE
- **Priority**: P1
- **Effort**: L
- **Risk**: MED
- **Category**: benchmark/tests/product truth
- **Planned at**: commit `775a4134f2cb`, Cycle 4

## Why this matters

Rust emits one SARIF `runs[]` entry per finding tool, while the harness scores
only the first. It maps only ground-truth entries, so unmatched findings never
become false positives. Cost reads a SARIF property Rust never writes and
therefore reports every real provider run as zero. Invalid line tolerance can
also fail open through `NaN`.

## Steps

1. Flatten results and rule metadata across every SARIF run. Deduplicate only
   by a documented stable finding identity; never discard later tools.
2. Perform deterministic one-to-one matching. After matching ground truth,
   count every unmatched in-scope finding as a false positive, with explicit
   tests for duplicates and multiple candidate matches.
3. Choose one canonical spend boundary: aggregate terminal run summaries/spend
   ledger by run ID, or add canonical aggregate spend metadata to Rust SARIF.
   Prove a nonzero recorded spend reaches metrics and the cost regression gate.
4. Validate line tolerance as a finite nonnegative integer within a documented
   maximum. Reject malformed, negative, and oversized values.
5. Regenerate deterministic fixture metrics/baseline/provenance and scoreboard
   expectations. Keep real-model output explicitly unmeasured until authorized.

## Verification

- Multi-run SARIF fixture where later tools add TP and FP; all are scored.
- Off-corpus findings reduce precision, while exact duplicates are counted once
  under the documented identity rule.
- Nonzero spend flows from canonical artifact to metrics and triggers a cost
  regression; missing/ambiguous spend fails honestly rather than becoming zero.
- Line-tolerance invalid cases exit nonzero.
- Run benchmark unit/integration tests, deterministic regression comparison,
  typecheck, workflow static tests, docs, and CRAP gate. Do not invoke provider.

## Done criteria

Benchmark precision, recall, false positives, and cost describe all product
output represented by the run, with no silent zero or first-run-only shortcut.
