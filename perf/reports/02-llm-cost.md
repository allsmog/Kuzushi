# 02 — LLM cost & latency audit

**Scope.** Every prompt site that reaches an Anthropic API in the
Kuzushi runtime. Focus is on Anthropic-side controls: prompt caching,
batch API, model tiering, streaming, and context size.

**Reference.** `claude-api` skill (cache_control, model IDs); CLAUDE.md
"Model & runtime safety" — never silently rewrite operator-configured
models.

## Executive summary

The runtime is in good shape. The high-leverage hot paths
(`agent-runtime/claude.ts`, `verify-gate.ts`, `cheap-verify.ts`,
`scanners/llm-rescore.ts`, `nl-planner.ts`, `threat-model-patch.ts`)
already use the right primitives — Haiku for classification, Sonnet for
analysis, Opus only for synthesis (threat-modeling, randori), batch API
where loops would otherwise serialize, and streaming + `finalMessage()`
on the direct-API fast path. Prompt caching is wired into the direct
path (`queryDirect`) and the batch path (`queryBatch`) with the
`>= minCacheTokens` guard the skill requires.

Remaining issues are concentrated in three areas:

1. **Stale default-model strings** that would silently downgrade to a
   pre-4.6 model:
   - `discovery/repo-discovery.ts` defaults to `claude-sonnet-4-20250514`
     (legacy `claude-sonnet-4-0`).
2. **Tier mistakes** — yes/no classification on Sonnet:
   - `bus/orchestrator/cheap-verify.ts` defaults to Sonnet 4.6 for a
     yes/no verify decision; this is exactly the workload the skill
     calls out for Haiku 4.5.
3. **Forbidden silent fallback** in `agent-runtime/claude.ts`:
   - `queryDirect` and `queryBatch` substitute `"claude-sonnet-4-6"`
     when `options.model` is missing. CLAUDE.md (`Model & runtime
     safety`) bans this — `enforceAgentQuery` should have rejected the
     call upstream; the inline `?? "claude-sonnet-4-6"` is dead code at
     best and a silent override at worst.

Estimated savings (rough, depend on workload mix):

- Cheap-verify Sonnet → Haiku (per call): **~3× cheaper input,
  ~3× cheaper output** ($3/$15 → $1/$5 per MTok).
- Multi-agent triage specialist tier (deferred — see below): could give
  another large multiplier on triage cost.
- Stale-default fix: avoids paying 4.0-tier prices on workloads the
  operator did not opt into.

No new caching breakpoints needed — the existing `cache_control` on the
system block is the right place; the user prompts vary per finding so
caching them would write-and-never-read.

## Prompt site inventory

The runtime funnels every LLM request through one of these surfaces:

| Surface | Where | Caching | Tier today | Notes |
|---|---|---|---|---|
| Anthropic SDK direct (`messages.stream`) | `agent-runtime/claude.ts:596` (`queryDirect`) | `cache_control` 1h on system block when ≥ minCacheTokens | per-call | Streams + `finalMessage()`. Adaptive thinking with `display: "omitted"`. Good. |
| Anthropic SDK batch (`messages.batches.create`) | `agent-runtime/claude.ts:456` (`queryBatch`) | Same caching guard | per-call | Polls with exponential backoff (2s → 30s, 10min cap). 50% rate. Good. |
| Claude Agent SDK subprocess | `agent-runtime/claude.ts:882` (`query`) | Inherits Claude Code defaults | per-call | Tool-using path. Caching is the SDK's responsibility. |
| pi-ai SDK | `agent-runtime/pi-ai.ts:306` | `PI_CACHE_RETENTION=long` | per-call | Caching delegated to pi-ai. |
| Multi-agent triage specialist loop | `multi-agent-triage.ts:212` `runSpecialist` | system-prompt caching via runtime | Sonnet-tier (configured) | Each role runs its own structured query. Already cached via system prefix. |
| Triage manager | `multi-agent-triage.ts:483` | same | Sonnet-tier | One call per finding after specialists. |
| Cheap-verify (yes/no) | `bus/orchestrator/cheap-verify.ts:70` | yes (system prompt) | **Sonnet 4.6 (default)** | **Tier mistake** — should be Haiku. Already batches. |
| Verify-gate | `bus/orchestrator/verify-gate.ts:215` | yes (system prompt) | Haiku 4.5 | Already correct: Haiku + batch + thinkingDisabled. |
| LLM rescore | `scanners/llm-rescore.ts:64` | yes | Haiku 4.5 | Correct: batch API path; system prompt cached; 25 findings/batch. |
| NL planner | `copilot/nl-planner.ts:251` | runtime cache | Haiku 4.5, low effort, thinkingDisabled, max_tokens 1024 | Correct. |
| Threat-model patch | `threat-model-patch.ts:87` | runtime cache | Haiku 4.5, low effort, thinkingDisabled | Correct. |
| Threat-modeling (randori) | `agents/tasks/threat-modeling/config.ts:13` | runtime cache | Opus 4.6, effort `max` | Correct — this is the deep-synthesis tier. |
| Repo discovery (LLM carving) | `discovery/repo-discovery.ts:67` | runtime cache | **`claude-sonnet-4-20250514` (legacy)** | **Stale default** — bump to `claude-sonnet-4-6`. |
| Variant hunter / n-day diff hunter / agentic scanner | `modules/variant-hunter.ts:88` etc. | runtime cache | Sonnet 4.6 | Default is `ctx.config.model ?? "anthropic:claude-sonnet-4-6"` — same string as the `defaults.ts` default; harmless but not great per CLAUDE.md style. Defer (covered by enforcement). |

## Per-task default models

Default tier is `anthropic:claude-sonnet-4-6` (`config/defaults.ts`).
Per-task overrides:

| Task | Default | Verdict |
|---|---|---|
| `triage-batch` | Haiku 4.5 | Correct (classification). |
| `taint-analysis` `labelingModel` | Haiku 4.5 | Correct (per-edge labeling). |
| `threat-model` | Opus 4.6, effort `max` | Correct (deep synthesis). |
| `threat-hunt` | Opus 4.6 | Correct (long-horizon agentic). |
| `systems-hunt` | Opus 4.6 | Correct. |
| `invariant-analysis` extraction + check | Sonnet 4.6 | Correct. |
| Multi-agent triage manager | (follows `triage`) | OK — manager synthesises findings. |
| Multi-agent triage specialists | (follows `triage-specialist`) | **Could move to Haiku.** Each specialist evaluates one finding from one angle (taint, secrets, auth, etc.); synthesis happens in the manager. Deferred — needs eval. |
| `cheap-verify` (gate) | Sonnet 4.6 (hardcoded fallback) | **Wrong** — yes/no decision, fix to Haiku. |
| Repo-discovery LLM carving | `claude-sonnet-4-20250514` | **Stale** — fix to `claude-sonnet-4-6`. |

## Caching audit

`agent-runtime/claude.ts` correctly:

- Uses `cache_control: { type: "ephemeral", ttl: "1h" }` on the system
  prompt block.
- Skips the breakpoint when the system prompt is below
  `minCacheTokens` (4096 for Opus/Haiku, 2048 for Sonnet) — without this
  guard, sub-4K prefixes silently waste the 1.25× write premium.
- Renders `tools → system → messages` in that order, so the system
  breakpoint also caches any tool definitions implicitly (none in the
  direct path).
- Uses adaptive thinking with `display: "omitted"` to reduce time-to-
  first-text.

No additional `cache_control` breakpoints are warranted in the user
prompt — every per-finding/per-file user prompt varies, so a marker
there would be write-only.

## Sequential prompts that already batch correctly

- `cheap-verify`, `verify-gate`, `llm-rescore`, `multi-agent-triage`
  (manager + specialists are intentionally per-finding; manager is one
  call) — all use `queryBatch` with sequential fallback.

## Sequential prompts that should probably batch (deferred)

- `taint-analysis/label.ts` per-edge labeling: Haiku already, called in
  bursts. The labeling layer in `@kuzushi/augur` controls request
  shape; deferred — outside this repo's prompt-shaping surface.

## Forbidden silent fallback (must fix)

`claude.ts:397` and `claude.ts:541`:

```ts
let model = baseOptions.model ?? "claude-sonnet-4-6";
```

`enforceAgentQuery` is supposed to reject unset models before this
point. The inline `?? "claude-sonnet-4-6"` either:

- never fires (because enforcement caught it earlier — dead code), or
- silently overrides a missing model (which CLAUDE.md forbids).

Fix: replace with an explicit invariant check that throws when `model`
is missing, so the bug surfaces at runtime instead of silently using
Sonnet 4.6.

## Streaming

`queryDirect` already streams via `client.messages.stream()` +
`stream.finalMessage()` — the recommended shape per the `claude-api`
skill. The Claude Agent SDK subprocess path streams natively.

Nothing to change.

## Token / context size

`maxOutputTokens` defaults to 16000 for non-streaming-style direct
calls, which matches the skill's guidance for non-streaming requests.
The streaming path inside `queryDirect` could go higher, but 16000 is
already adequate for every observed structured-output schema and avoids
runaway cost from buggy schemas.

`CLAUDE_CODE_MAX_OUTPUT_TOKENS=100000` is set on the subprocess path so
large structured outputs (PASTA threat models) do not truncate — good.

## Token waste — bounded

Tool-result truncation is handled by the Claude Code subprocess
(read-tool truncation, grep limits). Nothing oversized was found
through this audit's static read.

## Items deferred (with reason)

- **Specialist tier in multi-agent triage** → Haiku. Reason: needs eval
  to confirm specialists produce well-scored evidence chains on Haiku
  before flipping the default; tier is operator-overridable today, so
  the right move is to leave the default at Sonnet and document the
  Haiku override.
- **Per-edge taint labeling batching**. Reason: shaped inside
  `@kuzushi/augur` — outside this repo's surface.
- **`tests/agent-runtime/batch-preserves-model.test.ts`** referenced in
  the task spec does not exist in this worktree; ran the surrounding
  agent-runtime + modules suites instead.

## Changes implemented (this PR)

1. `bus/orchestrator/cheap-verify.ts` — default model
   `anthropic:claude-sonnet-4-6` → `anthropic:claude-haiku-4-5-20251001`.
   This is the cheap pre-verify gate; it's a yes/no decision and
   already batches with `thinkingDisabled` upstream of it elsewhere.
2. `discovery/repo-discovery.ts` — default model
   `claude-sonnet-4-20250514` (legacy 4.0) → `claude-sonnet-4-6`. The
   carve loop runs once per scan over a small graph; tier change is
   directional (better intelligence, similar price).
3. `agent-runtime/claude.ts` — replace the silent
   `?? "claude-sonnet-4-6"` fallback in `queryBatch` and `queryDirect`
   with an explicit `Error` so a missing model surfaces immediately
   instead of silently routing to Sonnet 4.6, per CLAUDE.md model-safety
   rules.
