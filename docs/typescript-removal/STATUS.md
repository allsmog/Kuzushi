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
| 1 | Native agent runtime (replace LangGraph bridge) | **SCAFFOLD LANDED** | Native tool loop, config flag, and factory seam are in and unit-tested offline (see below). Remaining: live-API parity harness, OAuth refresh port, `rmcp` MCP client, OpenAI `chat/completions`, and flipping the default. Live parity still needs provider credentials + network the sandbox lacks. |
| 2 | Retire dynamic module host | **BLOCKED on 1** | Needs the Phase-1 `rmcp` client. Plan recommends target C (MCP), bridge A (frozen subprocess protocol). Requires a plugin-author deprecation window. |
| 3 | Invert schema source of truth to Rust | **BLOCKED / re-scope** | See corrections above. Config half entangled with legacy-vs-v3 decision; LLM-IO half is downstream of Phase 1. |
| 4 | Delete module SDK + parity refs | **BLOCKED on 2** | Deletes `src/modules/**`, `src/testing/**`, etc. |
| 5 | npm distribution endgame | **BLOCKED on 1–4** | `dependencies:{}`, launcher-only `package.json`. |
| 6 | Tooling / web-kit / fixtures | **PARTLY INDEPENDENT** | `kuzushi-tui-kit` + `.design-sync` are already on the permanent allowlist. Husky→lefthook and benchmark/perf harness ports can proceed independently but are low-value until later phases land. |

## Phase 1 scaffold — what landed

The native runtime seam is real code, defaulting to `bridge`, and green offline:

- **Native tool loop** (`crates/kuzushi-openai/src/anthropic_oauth/tool_loop.rs`).
  Closes the one parity gap the pre-existing `AnthropicOAuthRuntime` had: it
  already did single queries + triage natively but not the tool-augmented loop.
  Now `AnthropicOAuthRuntime` implements `supports_tools()` and
  `next_step_blocking`, building the Anthropic Messages request from
  `system + prompt + history + tools` (via the same `build_messages_for_anthropic`
  renderer the bridge uses) and mapping the response to a single `AgentLoopStep`
  (`ToolCall` vs `Final`), with per-round cost. Unit-tested with recorded
  request/response JSON — no network.
- **Structured-output contract parity** (`anthropic_oauth/tests.rs` +
  `testdata/structured_output_contract.golden.txt`). The Rust
  `append_structured_output_contract` is asserted byte-for-byte against a golden
  captured from the bridge's `appendStructuredOutputContract` (model.mjs). The
  golden is regenerated by `testdata/regenerate_structured_output_contract.mjs`,
  a verbatim, dependency-free copy of the JS function that survives bridge dep
  removal. This is the plan's "snapshot-test it against the .mjs output before
  deleting" gate.
- **`agent_runtime` config flag** (`RuntimeConfig.agent_runtime`,
  `AgentRuntimeSelector = Bridge | Native`). Defaults to `Bridge`; skipped on
  serialize when default so existing config round-trips unchanged; rejected in
  untrusted project config (runtime policy stays operator-owned, same as
  `runtime.kind`).
- **Runtime factory** (`crates/kuzushi-openai/src/runtime_factory.rs`,
  `build_agent_runtime`). Switches on the flag; `native` resolves the Anthropic
  OAuth access token from the operator credential bag with **no silent
  fallback** (missing/expired/invalid → actionable error, never a quiet
  downgrade to the bridge). Wired into CLI **run** mode as the first live call
  site.

Remaining Phase 1 work (needs network / provider creds, so out of sandbox scope):

1. Record/replay parity harness: capture bridge request/response pairs, assert
   the native runtime matches on each, then diff the Phase 0 golden scans with
   `agent_runtime = native`.
2. OAuth **refresh** port (device/browser login, token refresh, model listing)
   — currently the native path errors on an expired token and defers to
   `kuzushi auth`; refresh still lives in the Node bridge.
3. `rmcp` MCP client (stdio + streamable-HTTP/SSE) to replace
   `@langchain/mcp-adapters`, mapping MCP tool schemas → provider tool defs.
4. OpenAI-compatible `chat/completions` client for non-Anthropic models (the
   native runtime is Anthropic-only today).
5. Wire scan + shell/TUI call sites through `build_agent_runtime` (they hold the
   concrete `LangGraphRuntime` for `with_cancellation`, a larger but mechanical
   rewire), then flip the default to `native` for one alpha before deleting the
   bridge.

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
