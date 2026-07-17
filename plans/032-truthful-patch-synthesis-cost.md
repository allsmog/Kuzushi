# Plan 032: Persist and report actual patch synthesis spend

> Executor: cost comes only from the configured runtime response. Do not
> estimate, invent, clamp, or replace missing provider usage with a model
> default, and do not change the no-silent-fallback policy.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: M
- **Risk**: MED
- **Category**: runtime accounting/product truth
- **Depends on**: Plans 017, 023, and 034
- **Planned at**: commit `775a4134f2cb`, Cycle 7

## Why this matters

Patch synthesis uses the shared structured-output runtime, which already
returns initial and repair-call cost, but `patch:finding` discards it. The
persisted `PatchResult`, top-level tool JSON, nested data, and human output all
hard-code `$0.0000`. A successful paid patch therefore records false spend and
the canonical run ledger cannot attribute the tool's actual cost.

## Steps

1. Switch patch synthesis to the cost-preserving structured-output API and
   carry the reported cost through each successful synthesis attempt without
   coupling validation-only work to model accounting.
2. Accumulate finite non-negative attempt costs with checked semantics. Reject
   NaN, infinity, and negative provider values rather than persisting invalid
   money; preserve exact zero when the provider reports no usage.
3. Store the accumulated value in `PatchResult.cost_usd` and derive every
   machine and human projection from that single field. Remove literal zeroes
   from top-level `costUsd`, `data.costUsd`, and the patch summary line.
4. Ensure outer run finalization consumes the patch tool output once, so the
   durable run receipt reflects the same value without double counting repair
   calls or retries.

## Verification

- A runtime returning two successful patch attempts with distinct costs
  persists their exact sum in SQLite and reports the same value in all output
  projections and the canonical run summary.
- A structured-output repair adds initial plus repair spend exactly once.
- Zero/absent usage remains zero; negative, NaN, and infinite usage fails
  closed with no false successful patch receipt.
- Patch/remediation, structured-output, run-artifact, CLI/TUI dispatch,
  formatting, Clippy, model-safety, and CRAP gates pass.

## Done criteria

Every successful patch receipt exposes one truthful runtime-reported cost from
provider response through persistence, presentation, and run accounting.

## Implementation notes

- Patch synthesis now preserves exact, incomplete-observed, and unavailable
  provider-cost states through repair attempts, SQLite, tool output, and the
  canonical run summary without rounding through legacy micros.
- Focused patch-cost coverage passes 12/12 and the broader core cost filter
  passes 112/112.
- The complete offline workspace, strict Clippy, architecture, model-safety,
  CRAP-risk, and package gates passed without provider calls.
