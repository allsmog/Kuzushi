# TypeScript Removal — Execution Status

Tracker for the "Kuzushi: TypeScript Removal" plan. This file is the ground
truth for what has actually landed vs. what the plan proposes, and it records
where the plan's assumptions diverge from the current repo (`v0.24.0-alpha.4`).
Update it in every PR that advances a phase.

## Verified starting facts (measured, not estimated)

- Tracked `*.ts` / `*.tsx` files: **92** total.
- Non-allowlisted (the removal target): **63**. Allowlisted (permanent scan /
  design data): **29**.
- Allowlist (data, never runtime): `evals/**/fixtures/**`, `examples/**`,
  `.design-sync/**`, `packages/kuzushi-tui-kit/**`.
- Runtime `dependencies` still present: `@anthropic-ai/sdk`, `@langchain/*`
  (5), `langchain`, `undici`, `better-sqlite3`, `zod`, `typescript`, plus
  `@kuzushi/augur`, `chalk`, `commander`, `tinyglobby`, `yaml`.
- `optionalDependencies`: the four pinned plugins (`@kuzushi/tob-skills`,
  `@kuzushi/vuln-scout`, `promptarmor-plugin`, `shinsa-plugin`).

### The two real runtime couplings (verified in-tree)

1. **Agent loop / model backends / MCP / OAuth** spawn `node`:
   - `crates/kuzushi-openai/src/langgraph_runtime/bridge_process.rs:318` →
     `node scripts/langgraph-bridge.mjs`.
   - Contract types already exist:
     `langgraph_runtime/bridge_payloads.rs` (`BridgeRequest`,
     `BridgeResponse`, `NextStepBridgeRequest`, `NextStepBridgeResponse`).
   - A runtime seam **already exists**:
     `crates/kuzushi-core/src/runtime/domain/agent_runtime.rs:47`
     (`pub trait AgentRuntime`). Phase 1's `NativeRuntime` should implement
     this rather than inventing a new trait.
2. **Dynamic ESM module host** spawns `node`:
   - `crates/kuzushi-core/src/modules/dynamic_loader.rs:221`
     (`Command::new("node")`) → `scripts/kuzushi-dynamic-module-host.mjs`,
     resolved via the `KUZUSHI_DYNAMIC_MODULE_HOST` chain.

## Plan corrections (assumptions that do NOT hold as written)

These are load-bearing and were confirmed against the tree:

- **Phase 3 premise is inaccurate.** The plan says Rust maintains a *parallel*
  `config/config_model.rs` of the same `KuzushiConfig`. It does not. The zod
  `KuzushiConfigSchema` (`src/schemas.ts:655`, ~664-line JSON projection in
  `generated/schemas/kuzushi-config.json`) is a large **flat legacy** config
  (`agentRuntimeConfig`, `astIndexEnabled`, `autoPatchAfter`, …). The Rust
  `V2Config` (`crates/kuzushi-core/src/config/config_model.rs`) is a small
  **nested v3** config (`{model, runtime, operator, phases}`). They are
  different generations. "Inverting the source of truth" therefore is not a
  drop-in `#[derive(JsonSchema)]` on an existing mirror — it requires deciding
  whether the legacy `kuzushi-config.json` consumer contract is still owned at
  all, and if so, re-expressing it in Rust.
- **Raw LLM-IO structs do not exist in Rust.** `grep` for `RawTriageOutput` /
  raw triage output structs under `crates/kuzushi-core/src/modules/` returns
  nothing — parsing is bridge-side today. The plan already flags this ("if
  raw-output structs don't exist yet … defining them is part of Phase 1"), so
  the `schemars` derive for `generated/schemas/llm-io/*.json` is **downstream
  of Phase 1**, not parallel-first. Only the config schema portion of Phase 3
  is independent of Phase 1, and per the point above it is entangled with the
  legacy-vs-v3 config decision.

Net: Phase 3 is **not** the clean, do-it-first, 2–3 day parallel task the plan
assumes. Phase 1 is even more central than stated — it also unblocks the Rust
raw-output structs.

## Phase status

| Phase | Scope | Status | Notes |
|---|---|---|---|
| 0 | Guardrails / TS ratchet | **DONE** | `.ts-budget=63`, `ci/ts-budget.sh`, CI wired, `pnpm check:ts-budget`. Coexists with `check-retired-ts-runtime.mjs`. |
| 1 | Native agent runtime (replace LangGraph bridge) | **NOT STARTED** | Long pole. Requires live-API parity testing; must ship `agent_runtime = bridge \| native` and default `bridge` until parity proven. Cannot be parity-verified in a sandbox without provider credentials + network to the model APIs. |
| 2 | Retire dynamic module host | **BLOCKED on 1** | Needs the Phase-1 `rmcp` client. Plan recommends target C (MCP), bridge A (frozen subprocess protocol). Requires a plugin-author deprecation window. |
| 3 | Invert schema source of truth to Rust | **BLOCKED / re-scope** | See corrections above. Config half entangled with legacy-vs-v3 decision; LLM-IO half is downstream of Phase 1. |
| 4 | Delete module SDK + parity refs | **BLOCKED on 2** | Deletes `src/modules/**`, `src/testing/**`, etc. |
| 5 | npm distribution endgame | **BLOCKED on 1–4** | `dependencies:{}`, launcher-only `package.json`. |
| 6 | Tooling / web-kit / fixtures | **PARTLY INDEPENDENT** | `kuzushi-tui-kit` + `.design-sync` are already on the permanent allowlist. Husky→lefthook and benchmark/perf harness ports can proceed independently but are low-value until later phases land. |

## Definition of done (from the plan)

```bash
git ls-files '*.ts' '*.tsx' | grep -vE 'fixtures|examples|corpus' | wc -l   # == 0 (currently 63 minus corpus/design allowlist)
python3 -c "import json;p=json.load(open('package.json'));assert p.get('dependencies',{})=={}"
which node   # (none)
cargo build -p kuzushi-cli --release && ./target/release/kuzushi scan <demo-repo>   # full agent loop + MCP tools succeed
cargo xtask codegen --check   # green
# golden finding-set diff vs Phase 0 baseline: empty on demo-repo, owasp-benchmark, cve-corpus
```

## Why this can't be a single-session change

Phase 1 alone is the plan's own 1.5–2.5 week estimate and its correctness is
defined by **behavioral parity with the live LangGraph bridge against real
Anthropic/OpenAI/MCP endpoints**. There is no way to prove that parity — the
plan's own gate — without provider credentials and network access to those
services, and deleting the bridge before parity is proven would break the
shipping product. Phases 2/4/5 are hard-gated on Phase 1; Phase 3 is entangled
with it. Phase 0 (this change) is the piece that is fully self-contained,
safe, and verifiable now, and it is the ratchet the rest of the plan hinges on.
