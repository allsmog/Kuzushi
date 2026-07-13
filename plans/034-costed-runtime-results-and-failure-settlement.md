# Plan 034: Make runtime cost a checked end-to-end result

> Executor: provider-reported usage is authoritative when present; a reserved
> estimate is only a conservative fallback when a paid call cannot report its
> outcome. Do not run a real provider while implementing or testing this plan.

## Status

- **Status**: DONE
- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH
- **Category**: runtime accounting/spend governance
- **Depends on**: Plans 017 and 023
- **Planned at**: commit `775a4134f2cb`, Cycle 8

## Why this matters

The shared structured-output API can preserve initial and repair-call spend,
but 17 production callers use its value-only wrapper. Verification, plugin
adapters, prompt armor, X-ray, variant/ndiff, vendor assessment, offense
planning, taint selection, and other successful paid tools consequently emit
literal `costUsd: 0.0`. Full mode is worse: it reports its deposit estimate as
actual spend, retries a complete query after the helper's own repair pass, and
refunds a failed paid attempt to zero. Tool-loop accumulation also accepts
negative, non-finite, and overflowing cost values. Failed CLI run summaries do
not use the per-call costs already persisted in `trace.jsonl`.

## Steps

1. Introduce one checked runtime-cost value/sum helper for finite,
   non-negative USD. Validate `AgentQueryResponse`, `AgentLoopStep`, repair
   totals, consensus/fan-out sums, and every value before trace, spend-ledger,
   result, or summary persistence; checked overflow is an explicit error.
2. Make structured-output failure preserve observed initial/repair spend in a
   typed error. A provider/transport failure before any response has unknown
   actual spend; keep its reservation conservatively committed instead of
   refunding zero.
3. Migrate every production value-only structured query to return and aggregate
   cost through its domain result. Cover full mode, plugin/shinsa adapters,
   prompt armor, systems hunt subpasses, taint/CWE selection, variant/ndiff,
   vendor assessment, X-ray, offense planning, verification consensus, and
   patch's shared infrastructure. Literal zero remains only for proven
   deterministic/no-model branches.
4. Remove full mode's second whole-query retry; the shared contract already
   performs one bounded repair. Settle each spend ticket with exact observed
   initial-plus-repair cost on success or typed parse failure, and leave the
   estimate charged only when actual provider spend is unknowable.
5. Preserve prior deep-audit/tool-loop spend when a synthesis fallback fails;
   add the fallback call's reported cost when it succeeds. Apply checked sums
   to agentic SAST, Carlini, systems hunt, SAST aggregation, router auto-triage,
   and consensus paths.
6. On failed/canceled/interrupted run terminalization, derive a bounded checked
   fallback total from that run's canonical trace cost steps when no terminal
   result cost exists. Never add a completion step twice or combine another
   run/tool's trace; keep missing cost distinct from known zero.
7. Use the same checked arithmetic in shell session budgets, Activity task
   rollups, phase/header telemetry, PR phase totals, and artifact summaries.
   Overflow or invalid trace material must fail closed or render an explicit
   unavailable/invalid state; it must never become infinity, wrap, or disappear.

## Verification

- A deterministic fake runtime assigns distinct initial, repair, pass, retry,
  and fallback costs. Each affected tool reports the exact sum at top level and
  in nested data, and its canonical run summary matches without double count.
- Full mode makes at most initial plus one repair call, settles actual cost on
  success/parse failure, and keeps the deposit committed on pre-response or
  unknown-cost failure.
- Negative, NaN, infinity, and finite-addition overflow fail before persistence
  in query, tool-loop, fan-out, trace, spend, and run-summary paths.
- A failed CLI/TUI tool with costed trace steps records their exact sum; a
  pre-runtime failure keeps `costUsd` absent, not zero.
- Two individually finite costs that overflow are rejected in shell/session,
  Activity, PR, and report aggregation without weakening the budget halt.
- Benchmark scoreboard publication validates every dataset cost and rejects a
  finite-addition overflow before writing Markdown.
- All runtime/capability/run-artifact tests, formatting, Clippy, architecture,
  model-safety, and CRAP gates pass using fakes only.

## Done criteria

Every runtime-backed path either reports checked observed spend, retains a
conservative unresolved reservation, or truthfully says cost is unavailable.

## Implementation notes

- The benchmark scoreboard now uses explicit finite, non-negative checked cost
  accumulation. Invalid operands and finite overflow stop publication instead
  of rendering `Infinity`.
- Core runtime, structured-output, capability, trace, run-summary, persistence,
  report, and SARIF projections now preserve exact, incomplete-observed, and
  unavailable cost states through checked `RuntimeCostReport` aggregation.
- Focused core cost coverage passes 112/112. The cycle-9 TUI recheck now also
  covers live and terminal settlement, idempotent Activity reconciliation,
  budget-latch enforcement, explicit attempted-versus-unattempted model calls,
  trace-backpressure degradation, and exact scan success/failure/lifecycle
  settlement without cross-run or completion-step double counting.
- Run summaries, trace steps, LLM-call audit rows, Session/Activity ledgers, and
  scan terminalization share checked exact, incomplete-observed, and unavailable
  cost semantics. Conflicting terminal receipts fail closed; a terminal receipt
  cannot erase already observed live spend.
- `cargo check -p kuzushi-core -p kuzushi-tui -p kuzushi-cli --tests` and strict
  Clippy with `-D warnings` pass with `CARGO_INCREMENTAL=0`; focused cost,
  budget, agent, scan-terminal, and phase-cockpit regressions pass using fakes
  only. No provider was called.
- The root final gate passed: complete offline workspace tests, strict
  all-target Clippy, architecture/model-safety checks, and the CRAP-risk proxy
  over 638 changed code files. All cost verification used fakes; no provider
  was called.
