# Performance optimization sweep — status

This sweep launched seven specialised research-and-implement agents in
parallel against `claude/optimize-kuzushi-PsALF`, one per area:

| # | Area                          | Outcome                                              |
| - | ----------------------------- | ---------------------------------------------------- |
| 1 | Cold-start / CLI startup time | Cut short by usage limit; lazy-import draft only     |
| 2 | LLM cost & latency            | Report delivered + 2 default-model fixes (applied)   |
| 3 | DAG concurrency               | Cut short by usage limit; no changes produced        |
| 4 | SQLite hot paths              | 3 pragma additions to findings DB (applied)          |
| 5 | File / AST scanning           | Cut short; orphan helper file only                   |
| 6 | Memory footprint              | Cut short; benchmark scaffold only                   |
| 7 | CI-mode throughput            | Cut short; helper module + buggy ANSI regex draft    |

All seven worker agents hit the same usage cap (`out of extra usage ·
resets 10pm UTC`) and were terminated before completing their research,
implementation, validation, or report writing. Each agent had only
managed 39–59 tool uses when interrupted, far short of what an
end-to-end audit-and-fix pass requires.

## What was applied to this branch

1. **`src/store/schema.ts`** — added `temp_store=MEMORY`,
   `cache_size=-65536` (~64 MiB), `mmap_size=268435456` (256 MiB) to
   `openWithPragmas`. Safe under WAL; does not change durability.
2. **`src/discovery/repo-discovery.ts`** — replaced the stale
   `claude-sonnet-4-20250514` default with `anthropic:claude-sonnet-4-6`
   to match the codebase-wide default model identifier.
3. **`perf/reports/02-llm-cost.md`** — preserved verbatim, the only
   completed agent report. Worth reading: it audits every LLM call
   site, flags two more issues we did not fix here (a forbidden silent
   `?? "claude-sonnet-4-6"` fallback in `agent-runtime/claude.ts`'s
   `queryDirect` / `queryBatch`, and a tier mistake in
   `bus/orchestrator/cheap-verify.ts` — the latter is moot on HEAD since
   `cheap-verify.ts` was hardened to require an explicit model).

## What was deliberately NOT applied

- **Cold-start lazy-loading of agent runtimes** (agent 1) used
  `createRequire` to load `claude.js` / `pi-ai.js` ESM modules. The
  package is `"type": "module"` and the affected files have not been
  audited for top-level await; loading ESM via `require()` is fragile
  across Node versions. Needs a real audit before adoption.
- **CI `interactive.ts`** (agent 7) shipped an `ANSI_PATTERN` regex
  that omits the ESC byte (`\x1b`), so `stripAnsi` would corrupt any
  text containing `[…letter]`. The agent's `// biome-ignore` comment
  even claims the regex requires ESC — but it doesn't. Needs fixing
  before adoption.
- **Orphan files**: agent 5's `src/utils/file-cache.ts` and agent 6's
  `perf/bench-memory.ts` were never wired into anything. `file-cache.ts`
  is dead code; `bench-memory.ts` is a standalone perf script. Skipped
  to keep the diff honest.

## Recommended next step

Re-run the sweep when the Anthropic-side rate limit resets. Each agent
needs roughly 5–10× the tool-use budget it was given to complete the
audit-write-implement-test loop end-to-end.
