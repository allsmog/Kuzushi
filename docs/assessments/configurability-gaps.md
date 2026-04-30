# Configurability gaps audit

Date: 2026-04-30
Scope: hardcoded values in non-config files (`src/**` excluding
`src/config/`, `src/agent-runtime/enforcement.ts`, fixtures, mock UIs).

## 1. Inventory of hardcoded values

### Timeouts and budgets

| File:line | Constant / literal | Current value | Notes |
| --- | --- | --- | --- |
| `src/agent-runtime/turn-watchdog.ts:8` | `DEFAULT_TIMEOUT_MS` | `120_000` | TurnWatchdog never instantiated by production code (only its own tests). Dead. |
| `src/agent-runtime/tools.ts:14` | `DEFAULT_BASH_TIMEOUT` | `120_000` | Default for the agent's `Bash` tool. |
| `src/agent-runtime/tools.ts:15` | `MAX_BASH_TIMEOUT` | `300_000` | Hard ceiling on the `Bash` tool. |
| `src/agent-runtime/tools.ts:97-98` | `TSSERVER_OPEN_TIMEOUT_MS` / `TSSERVER_REQUEST_TIMEOUT_MS` | `30_000` / `15_000` | tsserver init/request bounds. |
| `src/agent-runtime/claude.ts:511` | `SLOT_TIMEOUT_MS` | `600_000` | Wait for adaptive concurrency slot. |
| `src/agent-runtime/tools.ts:14-16` | `BASH_MAX_BUFFER` | 64 MiB | Bash stdout/stderr cap. |
| `src/modules/mcp-bridge.ts:89` | `DEFAULT_MCP_TIMEOUT_MS` | `60_000` | Default request timeout for stdio + HTTP MCP servers. Not surfaced. |
| `src/scheduler/rate-limit-registry.ts:14` | `QUEUE_TIMEOUT_MS` | `5 * 60 * 1000` | Time before queued LLM calls give up waiting for a slot. |
| `src/scheduler/rate-limit-registry.ts:11` | `DEFAULT_MAX_CONCURRENCY` | `5` | Already env-configurable via `KUZUSHI_MAX_CONCURRENCY`. |
| `src/scheduler/rate-limit-registry.ts:17` | `RECOVERY_THRESHOLD` | `5` consecutive successes | Adaptive recovery threshold. |
| `src/scheduler/rate-limit-registry.ts:20` | `PROACTIVE_THROTTLE_FRACTION` | `0.1` | Throttle when remaining quota < 10%. |
| `src/lifecycle.ts:8` | `SHUTDOWN_TIMEOUT_MS` | `10_000` | Graceful shutdown deadline. |
| `src/incremental.ts:8` | `EXEC_TIMEOUT_MS` | `30_000` | git/exec timeouts inside the incremental scanner. |
| `src/patch.ts:66` | `EXEC_TIMEOUT_MS` | `60_000` | Patch validation subprocess timeout. |
| `src/agents/tasks/approval-gate.ts:28` | `DEFAULT_APPROVAL_TIMEOUT_MS` | `5 * 60 * 1000` | Already accepts `options.timeoutMs`. |
| `src/scanners/resolve-semgrep.ts:14` | `REQUEST_TIMEOUT_MS` | `30_000` | HTTP fetch for semgrep registry lookups. |
| `src/strategies/auto-rule.ts:201` | inline `30_000` | `30_000` | Auto-rule generation fetch. |
| `src/fuzz/sandbox.ts:206` | inline `30_000` | `30_000` | Default fuzz subprocess. |
| `src/store/schema.ts:172` | inline `30_000` | `30_000` | SQLite reset lock acquisition. |
| `src/poc-executor/docker.ts:16` / `process.ts:6` | `DEFAULT_TIMEOUT_MS` | `30_000` | Already overridden by `pocExecTimeoutMs`. |
| `src/modules/taint-iris-next/extractors.ts:102` | `AST_GREP_QUERY_TIMEOUT_MS` | `5_000` | ast-grep per-query timeout. |
| `src/bus/orchestrator.ts:181` | inline `100` | `100ms` | Inter-poll yield. Internal scheduling. |
| `src/bus/workers/triage-worker.ts:143` | inline `500` | `500ms` | Backoff between worker polls. |

### Retry / backoff

| File:line | Constant | Value | Notes |
| --- | --- | --- | --- |
| `src/retry.ts:27` | `RATE_LIMIT_BACKOFF_FACTOR` | `3` | Multiplier applied for `rate_limit` errors. |
| `src/bus/orchestrator.ts:973` | `MAX_TASK_RETRIES` | `5` | Pipeline-level task retry ceiling. Not exposed. |
| `src/agents/tasks/taint-analysis/extraction-agent.ts:121` | `MAX_RETRIES` | `2` | Extraction worker retries. |
| `src/agents/tasks/taint-analysis/cross-service/boundary-agent.ts:24` | `MAX_RETRIES` | `1` | Cross-service boundary retry. |
| `src/agent-runtime/tools.ts:99` | `TSSERVER_MAX_RETRIES` | `1` | Internal restart of stuck tsserver. |
| `src/agents/task-wrappers.ts:52` | `options?.maxRetries ?? 3` | `3` | Default for arbitrary task wrappers. |

### Hardcoded model literals (outside `src/config/defaults.ts` and `src/agent-runtime/enforcement.ts`)

| File:line | Literal | Status |
| --- | --- | --- |
| `src/discovery/repo-discovery.ts:67` | `options.model ?? "claude-sonnet-4-20250514"` | **Forbidden silent fallback** per CLAUDE.md (Model & runtime safety). |
| `src/modules/carlini-threat-hunt/carlini-threat-hunt.ts:83` | `DEFAULT_CARLINI_THREAT_HUNT_MODEL = "anthropic:claude-opus-4-7"` | Used only as a JSON-Schema advisory default; resolver falls back to `ctx.config.model`. Not actionable. |
| `src/agents/tasks/invariant-analysis/types.ts:62-63` | `extractionModel`/`checkModel = "anthropic:claude-sonnet-4-6"` | Resolver overrides with `config.model` when `taskConfig` is missing. Not actionable. |
| `src/agent-runtime/context-guards.ts:121-124` | model→token-budget map | Reference data, not a model selection. Not actionable. |
| `src/agent-runtime/claude.ts:104-106` | stale-model rename map | Informational warning surface. Not actionable. |
| `src/discovery/repo-discovery.ts:67` is the only true silent-fallback violation. | | |

### Magic thresholds

| File:line | Value | Notes |
| --- | --- | --- |
| `src/agent-runtime/tools.ts:30-31` | `FILE_CACHE_MAX_ENTRIES=128`, `FILE_CACHE_MAX_BYTES=32*1024*1024` | Internal LRU. |
| `src/agent-runtime/tools.ts:92-96` | `DEFAULT_READ_LIMIT=200`, `DEFAULT_GLOB_LIMIT=200`, `DEFAULT_GREP_LIMIT=200`, `DEFAULT_FIND_REFERENCES_LIMIT=50`, `MAX_FIND_REFERENCES_LIMIT=200` | Tool result caps; agents pass explicit limits in practice. |
| `src/discovery/repo-discovery.ts:28-29` | `DEFAULT_MAX_MODULES=30`, `DEFAULT_MAX_DEPTH=8` | Already overridable via `config.monorepo.maxModules` and call-site option. |

### Concurrency / parallelism

All major concurrency numbers (`triageConcurrency`, `verifyConcurrency`,
`pocHarnessConcurrency`, `patchConcurrency`,
`crossServiceConcurrency`) are already in `KuzushiConfig`.

The system-wide `DEFAULT_MAX_CONCURRENCY=5` in
`rate-limit-registry.ts` already accepts `KUZUSHI_MAX_CONCURRENCY`.

### Prompt strings inside business logic

A scan for inline `"You are…"`/`"<system>"` strings in `src/` finds the
canonical agent prompts in `src/prompts/`, `src/agents/tasks/**`, and
`src/modules/**`. These already have a structured `<verb>_PROMPT` /
`*_PROMPT_TEMPLATE` shape and the prompt-editor pipeline overrides
them via `.kuzushi/prompts/<moduleId>/<verb>.md`. No new violations
were found — i.e. no string buried in business logic that should
move out.

### Paths and filenames

| Where | Hardcoded path | Status |
| --- | --- | --- |
| `src/config/defaults.ts:135` | `artifactDir: ".kuzushi/systems-hunt"` | In `taskConfig`, operator-overridable. |
| `src/config/defaults.ts:156` | `workspaceDir: "./iris"` | In `taskConfig`. Operator-overridable. |
| `src/store/paths.ts` | `.kuzushi/findings.sqlite3`, `.kuzushi/runs/...` | Documented in CLAUDE.md, intentionally fixed. |

No further operator-relocatable paths found.

## 2. Top high-leverage knobs to surface

| # | Knob | Channel | Who flips it | Frequency | Confidence |
| --- | --- | --- | --- | --- | --- |
| 1 | Discovery LLM model — remove silent fallback to `claude-sonnet-4-20250514` | Code fix (no new operator knob) | n/a — guardrail fix | one-shot | **High** |
| 2 | `mcpRequestTimeoutMs` (config + `KUZUSHI_MCP_TIMEOUT_MS`) | `config.json` + env | Operator integrating slow remote MCP server | per-environment | **High** |
| 3 | `KUZUSHI_BASH_DEFAULT_TIMEOUT_MS` / `KUZUSHI_BASH_MAX_TIMEOUT_MS` | env var | Pentester running long subprocesses (codeql analyze, fuzzers) inside bash tool | per-target | **High** |
| 4 | `rateLimitQueueTimeoutMs` (config + `KUZUSHI_RATE_LIMIT_QUEUE_TIMEOUT_MS`) | `config.json` + env | CI operator with very strict per-tenant LLM quotas; long queues acceptable | rare, per-tenant | **High** |
| 5 | `incrementalExecTimeoutMs` (config) | `config.json` | Monorepo with slow `git status` (NFS-backed). | rare | Med |
| 6 | `maxTaskRetries` (config) | `config.json` | CI operator wanting a stricter ceiling on flaky transients | per-pipeline | Med |
| 7 | `tsserverOpenTimeoutMs` / `tsserverRequestTimeoutMs` (env) | env | Triage of huge monorepos where tsserver init exceeds 30s | rare | Med |
| 8 | Auto-rule generation HTTP timeout (env) | env | Same as #7 | rare | Low |
| 9 | `RECOVERY_THRESHOLD` and `PROACTIVE_THROTTLE_FRACTION` | n/a | tuning for a niche provider | very rare | Low (rejected) |
| 10 | `BASH_MAX_BUFFER` | env | Operator running scanners that emit > 64 MiB to stdout | very rare | Low (rejected) |

This audit ships #1–#4 (the high-confidence row).

## 3. Rejected proposals

- **TurnWatchdog timeout** (`src/agent-runtime/turn-watchdog.ts:8`).
  Rejected: the class is unused in production code paths (only its own
  tests instantiate it). Surfacing it would be cargo-culting a knob no
  operator can actually flip in a way that matters.
- **Carlini threat-hunt default model** (`carlini-threat-hunt.ts:83`).
  Rejected: the literal is a JSON-Schema advisory default. The
  `readModel` resolver falls through to `ctx.config.model`, so the
  operator's configured model is honored. No silent fallback.
- **Invariant-analysis default models** (`invariant-analysis/types.ts:62-63`).
  Rejected: same pattern — `resolveInvariantAnalysisConfig` rewrites
  to `config.model` when `taskConfig` is missing the key.
- **`PROACTIVE_THROTTLE_FRACTION`, `RECOVERY_THRESHOLD`** in
  `rate-limit-registry.ts`. Rejected: these are scheduler internals
  governing adaptive behavior. No concrete operator persona benefits
  from flipping them — they tune the *shape* of the recovery curve and
  changing them invalidates the testing assumptions in `tests/scheduler/`.
- **`FILE_CACHE_MAX_ENTRIES`, `FILE_CACHE_MAX_BYTES`** in `tools.ts`.
  Rejected: internal LRU bounds. No operator persona has a use case
  for tuning the agent's read-cache footprint.
- **`SHUTDOWN_TIMEOUT_MS`** in `lifecycle.ts`. Rejected: 10s is enough
  for graceful shutdown; longer means hung CI runs, shorter means
  truncated audit logs. No persona benefits from change.
- **`DEFAULT_READ_LIMIT`, `DEFAULT_GLOB_LIMIT`, `DEFAULT_GREP_LIMIT`**.
  Rejected: agents pass explicit limits in their tool calls when they
  need more; the defaults are just safety guards.
- **`SLOT_TIMEOUT_MS=600_000`** in `claude.ts`. Rejected: 10 minutes
  for a single concurrency slot is already generous; if it's hitting
  this, the operator's pipeline is misconfigured (queue depth too high
  vs. provider quota). Real fix is `KUZUSHI_MAX_CONCURRENCY`.
- **`patch.ts` and `incremental.ts` `EXEC_TIMEOUT_MS`**. Rejected for
  patch (60s is reasonable for `npm test` etc., and operators set
  `patchTestCommand`/`patchBuildCommand` for the slow path). Surfaced
  for incremental (#5 above is Med-confidence).
- **`auto-rule.ts` and `resolve-semgrep.ts` HTTP timeouts**. Rejected:
  these are quick metadata fetches; 30s is well over the p99.
- **Inline `100ms` and `500ms` orchestrator/worker poll delays**.
  Rejected: tuning these affects scheduler responsiveness in subtle
  ways and no operator persona benefits.

## 4. Implementation summary

The high-confidence row is implemented in this PR. See:

- `src/config/defaults.ts` — new `mcpRequestTimeoutMs` and
  `rateLimitQueueTimeoutMs` defaults.
- `src/types.ts` — typed fields on `KuzushiConfig`.
- `src/schemas.ts` — Zod schema entries.
- `src/config.ts` — normalizer + setter wiring.
- `src/discovery/repo-discovery.ts` — silent-fallback model literal
  removed; caller must pass `options.model` when supplying a runtime.
- `src/modules/mcp-bridge.ts` — env override `KUZUSHI_MCP_TIMEOUT_MS`,
  consumed when `options.timeoutMs` is unset.
- `src/copilot/core.ts` — passes `config.mcpRequestTimeoutMs` to the
  MCP bridge.
- `src/agent-runtime/tools.ts` — env overrides
  `KUZUSHI_BASH_DEFAULT_TIMEOUT_MS` and `KUZUSHI_BASH_MAX_TIMEOUT_MS`.
- `src/scheduler/rate-limit-registry.ts` — env override
  `KUZUSHI_RATE_LIMIT_QUEUE_TIMEOUT_MS` and constructor param so
  `KuzushiConfig.rateLimitQueueTimeoutMs` plumbs through.
- `tests/config/configurability-knobs.test.ts` — covers default,
  override, and invalid input for each new knob; covers the
  discovery silent-fallback removal.
