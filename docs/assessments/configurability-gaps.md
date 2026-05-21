# Configurability Gap Assessment

Audit of hardcoded values in the Kuzushi codebase that should be operator-
configurable. Scope: active Rust-first runtime paths plus retained non-visual
TypeScript helpers. Categorized by confidence so implementations can land in
priority order.

Last updated: during the Rust port.

## Methodology

Searched active runtime paths for:

- `setTimeout`/`setInterval` literals
- `const [A-Z_]+ = <number>` named constants
- hardcoded provider-model defaults and fallback chains
- `MAX_*`, `*_MS`, `*_THRESHOLD`, batch-size literals

## High-confidence findings (implement now)

### G-01 Hardcoded model-string fallbacks bypass model enforcement

Status: fixed and guarded. The TypeScript files that carried the original
`?? "anthropic:..."` fallback findings are no longer active runtime paths in
the shipped Rust app. The Rust model-router path rejects fallback chains, and
`pnpm quality:model-safety` checks for hardcoded provider-model defaults and
fallback declarations in the current enforcement boundary.

**Channel:** none. This remains a safety invariant, not an operator knob.

## Retired TypeScript-Runtime Findings

The original assessment listed configurability gaps in deleted TypeScript
runtime files:

- `src/bus/orchestrator/verify-gate.ts`
- `src/bus/orchestrator/cheap-verify.ts`
- `src/scanners/llm-rescore.ts`
- `src/scanners/agentic.ts`
- `src/analysis-support/simple-index.ts`
- `src/lifecycle.ts`
- `src/agents/tasks/context-gatherer.ts`
- `src/agent-runtime/tools.ts`
- `src/modules/mcp-bridge.ts`
- `src/prompts/bootstrap.ts`
- `src/agents/tasks/pre-read.ts`
- `src/triage.ts`

Those paths are not part of the shipped Rust app. Re-open specific knobs only
against current Rust code when an operator-facing use case appears.

## Low-confidence / leave-alone

- Module-internal magic numbers tied to algorithmic choices
  (`estimateMatchConfidence` weightings, scoring multipliers) — not
  configurability, just engineering judgement.
- `CTRL_C_ARM_WINDOW_MS = 2000` (UX timing) — fine.
- Historical TypeScript module-default model constants such as
  `DEFAULT_THREAT_HUNT_MODEL`, `DEFAULT_THREAT_MODEL_CONFIG.model`, and
  `taint-analysis labelingModel` are not accepted precedent for the Rust
  product path. Current runtime-backed Rust tools must resolve through
  `require_configured_model`, `resolve_explicit_model`, or the Rust router's
  explicit `models.toml` role mapping.

## Out of scope

- Path constants under `~/.kuzushi/` and `.kuzushi/` (operator-relocatable
  workspace dirs) — handled by `src/config/paths.ts` already.
- Provider/runtime backend defaults — locked by the Rust no-silent-fallback
  policy in `crates/kuzushi-core/src/runtime/policy/no_silent_fallback.rs`,
  the Rust agent router, and `scripts/check-model-safety.mjs`.
