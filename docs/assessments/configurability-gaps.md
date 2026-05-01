# Configurability Gap Assessment

Audit of hardcoded values in the Kuzushi codebase that should be operator-
configurable. Scope: non-config `src/` files. Categorized by confidence so
implementations can land in priority order.

Last updated: 2026-04-30.

## Methodology

Searched `src/` for:

- `setTimeout`/`setInterval` literals
- `const [A-Z_]+ = <number>` named constants
- `?? "anthropic:..."` model fallbacks (CLAUDE.md guardrail violation)
- `MAX_*`, `*_MS`, `*_THRESHOLD`, batch-size literals

## High-confidence findings (implement now)

### G-01 Hardcoded model-string fallbacks bypass `enforceAgentQuery`

CLAUDE.md "Model & runtime safety" forbids `?? "anthropic:..."` defaults
inside modules / orchestrator helpers because they bypass `ctx.config.model`
and `enforceAgentQuery`. The following sites violate the rule:

| File | Line | Notes |
| --- | --- | --- |
| `src/bus/orchestrator/verify-gate.ts` | `model = options.model ?? "anthropic:claude-haiku-4-5-20251001"` | Dead — every caller already passes `resolveStageModel`. |
| `src/bus/orchestrator/cheap-verify.ts` | `model = options.model ?? "anthropic:claude-sonnet-4-6"` | Dead — same. |
| `src/scanners/llm-rescore.ts` | `model = options.model ?? "anthropic:claude-haiku-4-5-20251001"` | Dead — same. |
| `src/modules/n-day-diff-hunter.ts` | two sites: `?? ctx.config.model ?? "anthropic:..."` | The trailing literal is unreachable since `ctx.config.model` is required, but should be removed for clarity and to prevent future drift. |
| `src/modules/variant-hunter.ts` | `return ctx.config.model ?? "anthropic:..."` | Same. |
| `src/scanners/agentic.ts` | `DEFAULT_MODEL = "anthropic:claude-sonnet-4-6"` used when no `taskConfig.agentic.model` is set | The plugin's `init(pluginConfig)` does not receive global `config.model`, so absence of a per-task override silently picks an inline literal. **Real bug** — needs `init` to receive `config.model`. |

**Channel:** none (these are bugs to fix, not knobs to surface).

### G-02 `verify-gate` batch size hardcoded

`MAX_CANDIDATES_PER_BATCH = 15` in `src/bus/orchestrator/verify-gate.ts`.
Operators running large repos may want larger batches for fewer API calls
or smaller batches if they hit token limits.

**Channel:** `KuzushiConfig.verifyGateBatchSize` (top-level) +
`KUZUSHI_VERIFY_GATE_BATCH_SIZE` env var.

### G-03 `llm-rescore` batch size hardcoded

`MAX_FINDINGS_PER_BATCH = 25` in `src/scanners/llm-rescore.ts`. Same
rationale as G-02.

**Channel:** `KuzushiConfig.llmRescoreBatchSize` + env var.

### G-04 AST index file/size limits hardcoded

`MAX_FILE_SIZE_BYTES = 1_000_000` and `MAX_INDEXED_FILES = 2_500` in
`src/analysis-support/simple-index.ts`. Monorepos easily exceed 2,500
source files, silently truncating the symbol/text index.

**Channel:** `KuzushiConfig.astIndexMaxFiles`,
`KuzushiConfig.astIndexMaxFileBytes`.

### G-05 Shutdown timeout hardcoded

`SHUTDOWN_TIMEOUT_MS = 10_000` in `src/lifecycle.ts`. CI runs flushing large
SQLite databases or remote sessions may need longer.

**Channel:** `KUZUSHI_SHUTDOWN_TIMEOUT_MS` env var (process-level, not
config-file — this is an emergency knob).

## Medium-confidence findings (consider next)

### G-10 Context-gatherer walk caps

`MAX_WALK_ENTRIES = 4000`, `MAX_FILE_INDEX_ENTRIES = 500`,
`MAX_GREP_FILE_SIZE = 100_000` in `src/agents/tasks/context-gatherer.ts`.
Same monorepo concern. Surface in the existing `taskConfig["context-gatherer"]`
slot.

### G-11 Bash tool default timeout

`DEFAULT_BASH_TIMEOUT = 120_000` in `src/agent-runtime/tools.ts`. Heavy
build commands sometimes need more.

### G-12 MCP request timeout

`DEFAULT_MCP_TIMEOUT_MS = 60_000` in `src/modules/mcp-bridge.ts`. Cross-
network MCP servers sometimes need more.

### G-13 Bootstrap file caps

`DEFAULT_MAX_CHARS_PER_FILE = 20_000`, `DEFAULT_TOTAL_MAX_CHARS = 100_000`
in `src/prompts/bootstrap.ts`. Already partially surfaced via
`bootstrapFiles.maxCharsPerFile` and `.totalMaxChars` in `KuzushiConfig` —
no action needed.

### G-14 PoC pre-read byte cap

`MAX_PRE_READ_BYTES = 50_000` in `src/agents/tasks/pre-read.ts`,
`PRE_READ_BYTE_CAP = 20_000` in `src/triage.ts`. These mostly feel like
prompt-engineering constants, less operator-relevant.

## Low-confidence / leave-alone

- Module-internal magic numbers tied to algorithmic choices
  (`estimateMatchConfidence` weightings, scoring multipliers) — not
  configurability, just engineering judgement.
- `CTRL_C_ARM_WINDOW_MS = 2000` (UX timing) — fine.
- Module-default models (`DEFAULT_THREAT_HUNT_MODEL`,
  `DEFAULT_THREAT_MODEL_CONFIG.model`, `taint-analysis labelingModel`) —
  these are intentional per-module defaults that fall through to operator
  override via `taskConfig[<id>].model`. They are safer than `?? config.model`
  because they encode known reasoning needs (Opus for STRIDE etc.).
  Documented behavior — not a violation.

## Out of scope

- Path constants under `~/.kuzushi/` and `.kuzushi/` (operator-relocatable
  workspace dirs) — handled by `src/config/paths.ts` already.
- Provider/runtime backend defaults — locked by
  `src/agent-runtime/enforcement.ts` for safety.
