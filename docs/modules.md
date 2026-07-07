# Kuzushi Modules — Author's Guide

Canonical reference for building Kuzushi modules. The public SDK lives behind
two package exports:

- `kuzushi/modules` — types + authoring helpers (`defineModule`, `defineTool`,
  `ModuleLoadError`, narrow host handles).
- `kuzushi/testing` — in-memory mocks for unit-testing a tool in isolation.

Companion docs: [`mcp-server-requirements.md`](./mcp-server-requirements.md)
for MCP-bridged modules; [`api-compatibility.md`](./api-compatibility.md)
for legacy aliases and route compatibility;
[`devex/06-module-sdk-assessment.md`](./devex/06-module-sdk-assessment.md)
for the SDK audit that shaped the current surface.

## 1. What is a module?

A **module** is a unit of capability composition. Each module exposes one or
more **tools** (callable from shell, headless `run`, or pipeline tasks) and
optionally contributes pipeline **tasks**, **knowledge** packs, and event
declarations. Kuzushi's shell, scan pipeline, and `run` command all dispatch
through the same module contract — a tool written once works in all three
modes.

## 2. Current Rust Product Status

Kuzushi has one module/tool contract, but not every loading surface is equally
productized today.

- **Built-in Rust modules are the shipping product surface.** They appear in
  `kuzushi modules`, `kuzushi tools`, shell `/use`, scan tasks, and
  `kuzushi run <module:tool>`.
- **Retained TypeScript SDK modules are an authoring and compatibility
  surface.** The SDK remains useful for tests, package shape, dynamic-module
  descriptors, and migration references.
- **Dynamic `file://`, local path, and `package:` module loading is supported
  through the native CLI's global `--load` flag for shell and headless `run`.**
  The Node bridge is trusted-only: each specifier must be listed in
  `operator.trusted_modules`. Untrusted analyzers must use the v3 sandbox
  plugin path instead of the dynamic Node bridge.
- **MCP servers and deferred plugin adapters are exact, explicit integrations.**
  Rust MCP servers are exposed through `kuzushi mcp serve <backend>` and the
  agent bridge. The legacy `mcp:` module specifier remains a parsed
  compatibility form in the TypeScript SDK; it is not the native dynamic-loader
  path.

This guide documents the contract and the SDK shape. Shipping behavior should
be checked against `kuzushi modules`, `kuzushi tools`, and the Rust registry
tests before docs claim a capability is available to operators.

## 3. When to build one

Build a module when:

- You have a new scanner, intel feed, recon probe, or remediation action and
  it shouldn't live inside the core `sast` module.
- You want independent versioning, tests, and release cadence.
- You need a stable capability boundary that can later graduate into the Rust
  built-in registry or a supported dynamic-loader surface.

## 4. Anatomy

```text
my-module/
├── module.manifest.json   # declarative metadata (id, entry, requires)
├── package.json           # npm manifest (peer-deps on kuzushi)
├── tsconfig.json
├── src/
│   ├── index.ts           # exports `defineModule({...})` as default
│   └── index.test.ts      # uses `kuzushi/testing` helpers
└── README.md
```

The current Rust CLI does not ship a module scaffolder. Create this layout
manually or copy an in-tree module fixture until a Rust-native scaffolder is
added.

## 5. Manifest — `module.manifest.json`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | `string` | yes | `[a-z][a-z0-9-]*`. Must equal the exported module's `id`. |
| `displayName` | `string` | yes | Shown in `/modules` and catalog. |
| `version` | `string` | yes | Module's own semver. |
| `description` | `string` | no | One-line summary. `defineModule()` enforces one sentence and <=140 chars when present. |
| `category` | `"offense" \| "defense" \| "governance" \| "intel"` | yes | Grouping in the catalog. |
| `entry` | `string` | yes | Relative path to the compiled entry (e.g. `./dist/index.js`). |
| `kuzushiSdkVersion` | `string` | no (warn if missing) | Host SDK the module was authored against. Drift produces a warn. |
| `requires` | `{ env?: string[]; bins?: string[]; nodeVersion?: string }` | no | Exposed through SDK helper checks; native Rust built-ins should use descriptor options/config instead. |
| `configSchema` | `JSONSchema` | no | Validated against operator-supplied `moduleConfig` before `init()`. |
| `author` / `license` | `string` | no | npm-style metadata. |

```json
{
  "$schema": "https://raw.githubusercontent.com/allsmog/Kuzushi/main/schemas/module.manifest.schema.json",
  "id": "my-module",
  "displayName": "My Module",
  "version": "0.1.0",
  "description": "Example custom module",
  "category": "offense",
  "entry": "./dist/index.js",
  "kuzushiSdkVersion": "0.20.0",
  "requires": { "nodeVersion": ">=22", "env": ["MY_API_KEY"] }
}
```

The published schema at `schemas/module.manifest.schema.json` gives editors
autocomplete and inline validation.

## 6. The `CopilotModule` contract

Use `defineModule()` from `kuzushi/modules`. It's an identity function that
gives TypeScript tight inference and runs a construction-time guard that
every tool name starts with the module id.

```ts
import { defineModule, defineTool } from "kuzushi/modules";
import type { ExecutionContext, ToolResult } from "kuzushi/modules";

const pingTool = defineTool<"my-module">({
  name: "my-module:ping",
  description: "Connectivity check.",
  inputSchema: {
    type: "object",
    properties: { target: { type: "string" } },
    required: ["target"],
  },
  headless: true,
  async execute(input, ctx): Promise<ToolResult> {
    const target = (input as { target: string }).target;
    ctx.reportActivity?.(`pinging ${target}`);
    return { ok: true, output: `pong: ${target}`, data: { target } };
  },
});

export default defineModule({
  id: "my-module",
  displayName: "My Module",
  version: "0.1.0",
  description: "Example module",
  category: "offense",
  rank: "normal",
  tools: [pingTool],
});
```

Optional fields: `rank` (`"manual" | "low" | "normal" | "good" | "great" | "excellent"`),
`authors`, `references` (CVEs, ATT&CK techniques), `disclosureDate`, `notes`
(stability / reliability / side-effects), `examples` (metadata for docs/tests),
`requires`, `knowledge`, `events`, `hidden`,
`init(config, ctx)`, `dispose()`.

> **DAG participation.** DAG nodes are `DagTool`s declared inside `tools`.
> Use `defineDagTool<"<id>">({...})`; hidden infrastructure nodes use the
> same `DagTool` contract with `hidden: true`.

For live Rust built-in behavior, use the Rust descriptor/executor path as the
reference: `crates/kuzushi-core/src/modules/workspace_module.rs` for
descriptors and `crates/kuzushi-core/src/modules/application/sast_scan/` for
umbrella orchestration. The retained TypeScript files under `src/modules` are
SDK compatibility surfaces, not the runtime for built-in scan/shell/run
behavior.

## 7. Writing a tool

Every tool:

- Has a fully-qualified name `<module-id>:<action>`. **Enforced at load time** —
  the loader throws `ModuleLoadError{ code: "SHAPE_INVALID" }` if a tool's
  name doesn't start with the module id.
- Has an `inputSchema` (JSON Schema; top-level `type: "object"`).
- Has a `headless: boolean`. `headless: true` means **no TTY, no stdin prompts,
  no interactive subprocess attach** — the tool is safe to dispatch from
  `kuzushi run` and pipeline mode. If your tool asks the operator a question,
  mark it `headless: false`.
- Returns `ToolResult`: `{ ok, output, data?, costUsd? }`.

Duplicate tool names inside a single module are rejected. `costUsd` is optional
but recommended for LLM-driven tools — the shell accumulates it into the
per-run cost footer.

### `defineTool` compile-time prefix check

```ts
// Fails TypeScript before you run it:
defineTool<"my-module">({
  name: "other:scan",   // ← Type '"other:scan"' is not assignable to type `my-module:${string}`
  // ...
});
```

### 7.1. Writing a `DagTool`

A `DagTool` is a `ModuleTool` that participates in the scan pipeline DAG.
It has everything a normal tool has (`name`, `inputSchema`, `execute`) plus a
`dag` block that declares its `outputKind`, upstream `dependsOn` ids,
optional `condition`, `promptMode`, `toolPolicy`, and per-finding
`triageAgentConfig`.

```ts
import { defineDagTool, requireDag } from "kuzushi/modules";
import type { ExecutionContext } from "kuzushi/modules";
import type { Finding } from "kuzushi/scanners";
import type { ScanOpts } from "kuzushi";

const hunt = defineDagTool<"my-scanner", ScanOpts, Finding[]>({
  name: "my-scanner:hunt",
  displayName: "My Scanner",
  description: "LLM-driven hunt for weirdness X.",
  headless: true,
  inputSchema: { type: "object", properties: { target: { type: "string" } } },
  dag: {
    outputKind: "findings",
    dependsOn: ["context:context-gatherer", "context:app-model-build"],
    // Optional: only run when some upstream condition holds.
    condition: (upstream, _cfg) => !!upstream.get("context:app-model-build"),
  },
  async run(input, ctx: ExecutionContext): Promise<Finding[]> {
    const dag = requireDag(ctx);  // throws outside a pipeline run
    // use dag.runId, dag.scanPath, dag.upstreamOutputs etc.
    return [];
  },
});
```

Authors don't implement `execute` themselves — the retained TypeScript module
registry installs one automatically for SDK compatibility. Live Rust scan
behavior should be implemented through Rust descriptors/executors and the
shared registry boundary rather than by adding new TypeScript scan runtime
paths.

**Hidden DAG tools.** Internal helpers that shouldn't appear in `/use`
overviews or LLM tool lists should still be authored with `defineDagTool`;
set `hidden: true` and keep dependency names qualified.

## 8. `ExecutionContext` reference

| Field | Stability | Purpose |
|-------|-----------|---------|
| `cwd: string` | stable | Project/scan root. |
| `target?: string` | stable | Active repo/host target. |
| `workspaceId?: string` | stable | Current workspace id when one is active. |
| `runtime: AgentRuntime` | stable | LLM backend — call `runtime.query(...)` to reach Claude. |
| `bus: MessageBus` | stable | Event bus (use sparingly; prefer `events` scope). |
| `config: KuzushiConfig` | stable | Full host config; read module-specific keys. |
| `signal?: AbortSignal` | stable | Cancel long-running work. |
| `host?: HostInfo` | stable (new) | `{ sdkVersion, capabilities }` — see §10. |
| `logger?: ToolLogger` | stable (new) | `info/warn/error/debug` structured diagnostics. |
| `uiStore?: HostUiHandle` | narrow-handle | Read/update live shell UI state when the Rust TUI wires it. |
| `datastore?: ToolOptionStore` | narrow-handle | Read operator-set options (`setg FOO bar`). |
| `workspace?: WorkspaceHandle` | narrow-handle | Hosts/services/vulns/notes. |
| `events?: ModuleEventScope` | narrow-handle | Cross-module pub/sub (auto-torn-down on `dispose`). |
| `print?: PrintSink` | UX helper | `status/good/error/warn` — operator-facing. |
| `reportActivity?` | UX helper | Progress-rail entries. |
| `reportOutput?` | UX helper | Ephemeral live-tail output. |
| `seedTaskOutputs?: Map<string, unknown>` | advanced | Seed pipeline task outputs. |
| `toolModel?: string` | advanced | Per-tool model override from `setg TRIAGE_MODEL`. |

The narrow-handle interfaces are intentionally smaller than the host's
concrete classes so third-party modules don't pick up transitive dependencies
on host internals. Concrete host objects (e.g. `UIStore`, `WorkspaceManager`)
are structural supersets — no casts needed when the host passes them in.

### Resolving `model` in a module

Modules **must not** hardcode model strings as fallbacks. The runtime
boundary (`crates/kuzushi-core/src/runtime/policy/no_silent_fallback.rs`
plus the Rust agent router) rejects empty / incompatible models and fallback
chains before any LLM call. `scripts/check-model-safety.mjs` keeps that
boundary wired into CI. For retained TypeScript SDK modules, the expected
resolution chain is:

```ts
const model =
  (input?.model as string | undefined) /* inline tool arg */ ??
  ctx.toolModel /* setg <MODULE>_MODEL=… or /set model … */ ??
  ctx.config.model /* operator-configured global */;
```

For Rust built-ins, use `resolve_tool_model(tool_name, input, ctx)` or
`resolve_explicit_model(tool_name, parsed_input_model, ctx.config.model.as_deref())`.
Do not reintroduce deleted TypeScript task-runtime helpers as a new source of
model policy.

Anything that looks like `model = X ?? "anthropic:claude-..."` is the
silent-fallback pattern the audit removed and must not return.

### 8.1. Rust-side: `ctx.trace` (live module-progress feed)

Rust-native modules — anything in `crates/kuzushi-core/src/modules/**` — get
an additional optional handle on `ToolExecutionContext`:

```rust
pub struct ToolExecutionContext<'a> {
    pub config: &'a V2Config,
    pub workspace: Option<&'a WorkspaceTarget>,
    pub findings_store: Option<&'a FindingStore>,
    pub trace: Option<&'a TraceHandle>,  // <- new
}
```

When the shell starts a tool or scan it constructs a `TraceHandle` that
wraps a `BroadcastSink` (file + mpsc channel). The dispatch wrapper in
`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs` auto-stamps the
handle with the calling tool's `module_id` derived from the qualified tool
name (`semgrep:scan` → `semgrep`), so producer code only needs:

```rust
if let Some(trace) = ctx.trace {
    let _ = trace
        .step("tool", "scan", format!("semgrep start · target={}", target.display()))
        .emit();
}
// ... do work ...
if let Some(trace) = ctx.trace {
    let _ = trace
        .step("done", "scan", format!("semgrep complete · {} findings", findings.len()))
        .emit();
}
```

**API:**

| Method | Purpose |
|---|---|
| `trace.step(kind, verb, label)` | Build a `TraceStepBuilder`. Auto-stamps `module_id` and increments the per-run `n` counter. |
| `.with_latency_ms(ms)` / `.with_cost_usd(c)` / `.with_severity(s)` | Optional metadata. `severity == "danger"` flips the row to `Failing`. |
| `.emit() -> usize` | Records the step and returns its `n` so callers can pass it to `child(n)`. |
| `trace.child(parent_step)` | Returns a clone of the handle that auto-fills `parent_step` on subsequent `step(...)` calls. |
| `trace.for_module(module_id)` | Override the auto-stamped module (e.g. for sub-actor stamping). |

Drop-without-emit is supported: `TraceStepBuilder` records on `Drop` if
`.emit()` wasn't called, so the simplest pattern is just to ignore the
returned `usize`.

**Suggested phase verbs** (use the same vocabulary as TS `reportActivity`
so cross-module categorization stays consistent):

| Kind | When |
|---|---|
| `tool` | Top-level tool start/complete boundary. |
| `done` | Final step. Promotes the row to `Done` in the left pane. |
| `reasoning` | LLM/agent reasoning phase (e.g. `evidence-collect`, `cwe-select`). |
| `tool-start` / `tool-progress` / `tool-complete` | Sub-tool calls inside an agentic run. Use with `child(parent)`. |
| `refused` / `failing` | Severity = `danger`; flips the row to Failing in the dashboard. |

### 8.2. Per-LLM-call tracing via `TracedRuntime` + `parent_scope`

Beyond the explicit `ctx.trace.step(...)` boundaries above, **every LLM
call is auto-traced**. The dispatch wrapper at
`crates/kuzushi-core/src/modules/builtins/with_v2_builtins/execution.rs` wraps the incoming
`AgentRuntime` in a `TracedRuntime` (defined in
`crates/kuzushi-core/src/runtime/traced_runtime.rs`) whenever `ctx.trace.is_some()`. Each
call to `runtime.query_blocking`, `runtime.next_step_blocking`,
`runtime.triage_finding_blocking`, or `runtime.spawn_subagent_blocking`
emits a `kind="reasoning"` (or `tool-progress` / `done` for loop
iterations) step with `latency_ms` and `cost_usd` populated from the
provider response. Producers don't have to thread the trace handle into
their LLM call sites.

To group several LLM calls under a labelled phase header, push a
**parent_scope** RAII guard before the LLM region:

```rust
let phase = ctx
    .trace
    .map(|t| t.step("reasoning", "run", "evidence-collect").emit());
let _scope = match (ctx.trace, phase) {
    (Some(trace), Some(parent)) => Some(trace.parent_scope(parent)),
    _ => None,
};
let result = run_triage_stage2(store, runtime, &input, &config, kept)?;
drop(_scope);
```

Inside `_scope`, every step emitted by `TracedRuntime` (or by the
producer itself) carries `parent_step = Some(phase)`, so the renderer
indents the row under the phase header in the right pane. The scope is
per-thread; nested scopes form a stack and pop in LIFO order on drop.

Producers that already follow this pattern as canonical references:
`triage:run`, `verify:finding`, `agentic-sast:scan`, `taint-iris-next:hunt`,
`taint-iris-next:finding-review`, `carlini-threat-hunt:run`, `patch:finding`,
`threat-model:build`, `x-ray:run`, `run_plugin_finding_adapter` (used
by `vuln-scout:audit` / `tob:audit`), `shinsa:scan`, `prompt-armor:*`.

**Hidden modules** (`pipeline:*`, `systems-hunt:*`, `context-lite:index`,
compatibility aliases, and quarantined exact-only surfaces such as
`full-mode:*`, `deep-audit:*`, `exploit-chain:*`, `pwn:*`, `threat-leads:*`,
`chrome-rce:*`, and `vendor-assessment:*`) collapse into one aggregated
`subsystems` row in the Activity view. Their events also still flow through
but are filtered out of the right-pane feed unless the operator presses `V`
(verbose).

Headless `kuzushi run` creates a JSONL trace handle for run artifacts. Some
test/eval or compatibility contexts may still leave `ctx.trace` as `None`; the
`if let Some(...)` guard should always short-circuit cleanly.

See `crates/kuzushi-core/src/run_artifacts/trace_handle.rs` for the
implementation and
`crates/kuzushi-tui/tests/activity_dag_fixture.rs` for end-to-end
integration tests showing how to drive the view from a fake DAG.

## 9. `reportActivity` vs `reportOutput`

Use `reportActivity` for **structured phase labels** — they land in the
shell's progress rail and scrollback:

```ts
ctx.reportActivity?.("scanning deps/package.json");
for (let i = 0; i < deps.length; i++) {
  ctx.reportActivity?.(`analyzing ${deps[i].name}`, { step: i + 1, total: deps.length });
}
```

Use `reportOutput` for **ephemeral subprocess output** — it appears in the
live `⎿` tail beneath the tool-call header and disappears on completion:

```ts
ctx.reportOutput?.("npm install: added 142 packages in 3.4s");
```

Both are best-effort and optional — the `?.` matters in unit tests where no
bus is wired.

## 10. `costUsd`

LLM-driven tools should report per-invocation spend so the shell can show a
run-level total and honor `--budget` caps:

```ts
return {
  ok: true,
  output: summary,
  data: { findings },
  costUsd: usage.input_tokens * 3e-6 + usage.output_tokens * 15e-6,
};
```

## 11. Capability probe — `ctx.host.capabilities`

`ctx.host` is populated when compatibility TypeScript modules are executed
through the module host. Feature-probe before depending on an optional
capability so your tool survives both shell-mode and headless `run`:

```ts
if (ctx.host?.capabilities.has("workspace")) {
  ctx.workspace?.hosts.upsert({ /* ... */ });
} else {
  ctx.logger?.warn("my-module:scan running without workspace capability");
}
```

Well-known capabilities: `"workspace"`, `"ui-store"`, `"datastore"`,
`"print-sink"`, `"module-events"`, `"structured-output"`, `"tool-model"`.
The set is open — authors can publish modules that probe future capabilities
without a kuzushi release.

## 12. Load specifiers

The native Rust CLI accepts dynamic module specifiers via the global
`--load <specifier>` flag for `kuzushi shell` and `kuzushi run`. The loader
delegates to `scripts/kuzushi-dynamic-module-host.mjs`, imports the module
entry, and consumes the descriptor JSON returned by that host. Each specifier
must be listed under `[operator].trusted_modules` in the global config.
Untrusted third-party analyzers must be packaged for the v3 sandbox plugin
runtime, where capabilities are explicit and ambient process access is denied.

The retained TypeScript SDK parser also understands four compatibility
prefixes:

| Prefix | Example | Source |
|--------|---------|--------|
| `builtin:` | `builtin:sast` | Shipped inside the kuzushi package. |
| `file://` | `file:///abs/path/to/my-module` | Local directory with `module.manifest.json`. |
| `package:` | `package:@kuzushi/blackbox` | Installed npm package (manifest optional). |
| `mcp:` | `mcp:http://localhost:3000` | Parsed compatibility form only; native MCP is served through `kuzushi mcp serve <backend>`. |

A bare string (`"foo"`) defaults to `{ type: "builtin", id: "foo" }`.

## 13. Load errors — `ModuleLoadError`

The loader throws `ModuleLoadError` instead of plain `Error`. Branch on
`err.code`:

| Code | Cause | Fix |
|------|-------|-----|
| `MANIFEST_MISSING` | No `module.manifest.json` in the target directory. | Create the manifest at the module root. |
| `MANIFEST_INVALID` | Zod-parse failure (missing field, bad semver, bad category). | `err.details.issues` lists every problem. |
| `REQUIREMENTS_UNMET` | Reserved compatibility code; current SDK exposes requirement checks through `checkRequirements(...)` helper results instead of rejecting in the loader. | Check helper output before loading if your host wants hard enforcement. |
| `ENTRY_NOT_FOUND` | `entry` path doesn't exist. | Run your build; check `entry` is relative to the manifest. |
| `SHAPE_INVALID` | Exported module failed `validateModuleExport`. Includes tool-name-prefix and duplicate-name violations. | Error message lists the violating tool index. |
| `ID_MISMATCH` | Registry id conflict or lookup of an unknown module id. | Use a unique module id and verify the id is registered before resolving it. |
| `SDK_INCOMPATIBLE` | Reserved compatibility code; current SDK version checks warn through `checkSdkCompatibility(...)` rather than rejecting. | Update the manifest or host when warnings appear. |
| `CONFIG_INVALID` | `moduleConfig` fails the manifest's `configSchema`. | Check `err.details` for schema path + message. |

`ModuleLoadError extends Error`, so legacy `catch (err) { err.message }`
patterns keep working.

## 14. Testing

The `kuzushi/testing` export gives you in-memory helpers so tools can be
unit-tested without spinning up a real runtime or SQLite store.

```ts
import { describe, it, expect } from "vitest";
import {
  createMockToolContext,
  assertToolResult,
  expectModuleShape,
} from "kuzushi/testing";
import module from "./index.js";

describe("my-module", () => {
  it("exports a valid module shape", () => {
    expectModuleShape(module);
  });

  it("ping returns pong", async () => {
    const ctx = createMockToolContext({ cwd: "/tmp" });
    const result = await module.tools[0]!.execute({ target: "example" }, ctx);
    assertToolResult(result, { ok: true, outputContains: "pong: example" });
  });
});
```

`createMockToolContext` populates every `ExecutionContext` field with
permissive defaults and accepts per-field overrides. See
`src/testing/index.ts` for the full helper list.

## 15. Scaffolding status

The legacy TypeScript CLI had a `kuzushi create-module` scaffolder during SDK
hardening. That command is not part of the current Rust operator CLI, so it
must not appear in first-run instructions or CI examples.

Until a Rust-native scaffolder is implemented, create the layout from §4
manually:

- `module.manifest.json` with `$schema`, `id`, `displayName`, `version`,
  `description`, `category`, `entry`, and `kuzushiSdkVersion`.
- `package.json` with `peerDependencies.kuzushi` pinned to the host major.
- `src/index.ts` using `defineModule` + `defineTool`.
- `src/index.test.ts` using `createMockToolContext` + `expectModuleShape`.
- `README.md` with load and run examples.

## 16. MCP servers

Native MCP integration is explicit rather than a generic `--load mcp:<spec>`
module bridge. Kuzushi ships Rust MCP servers for analysis backends such as
tree-sitter, Joern, Clang, CodeQL, and gtags. Operators can run them over
stdio with:

```bash
kuzushi mcp serve <backend>
kuzushi mcp health <backend>
```

Agent-backed tools opt into these servers through the Rust agent bridge and
tool policy. The legacy `mcp:` module specifier remains a parsed compatibility
form in the TypeScript SDK, but the native CLI does not convert arbitrary MCP
servers into module tools.

## 17. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `Unknown tool: module:action` | Module not registered, wrong id, unsupported dynamic loading path, or tool prefix mismatch. | Check `kuzushi modules` / `kuzushi tools`; for Rust CLI usage, use a built-in or explicitly wired integration. |
| `ModuleLoadError: MANIFEST_MISSING` | No `module.manifest.json` at the path. | Add manifest at module root. |
| `ModuleLoadError: REQUIREMENTS_UNMET` | Reserved compatibility code; current SDK helper reports unmet requirements without throwing. | Check `checkRequirements(...)` output if you need hard enforcement. |
| `ModuleLoadError: ID_MISMATCH` | Duplicate module id during registration, or lookup of an unknown module id. | Use a unique id and verify the module is registered. |
| `ModuleLoadError: SHAPE_INVALID` with "does not start with" | Tool name prefix violates module id. | Rename tool to `<id>:<action>` or use `defineTool<"id">`. |
| `ModuleLoadError: SHAPE_INVALID` with "duplicate" | Two tools share a name. | Rename the duplicate. |
| `ModuleLoadError: SDK_INCOMPATIBLE` | Reserved compatibility code; current SDK version checks warn rather than throw. | Bump manifest or pin host when warnings appear. |
| MCP backend unavailable | Native MCP backend binary or runtime is missing. | Run `kuzushi mcp health <backend>` and install/configure the backend it reports. |

## 18. Minimal starter

Complete one-file module, copy-pasteable:

```ts
import { defineModule, defineTool } from "kuzushi/modules";
import type { ExecutionContext, ToolResult } from "kuzushi/modules";

const pingTool = defineTool<"my-module">({
  name: "my-module:ping",
  description: "Connectivity check.",
  inputSchema: {
    type: "object",
    properties: { target: { type: "string" } },
    required: ["target"],
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const target = (input as { target: string }).target;
    ctx.reportActivity?.(`pinging ${target}`);
    ctx.logger?.info("ping started", { target });
    if (ctx.host?.capabilities.has("workspace")) {
      ctx.workspace?.notes.create({ workspaceId: ctx.workspaceId!, body: `pinged ${target}` });
    }
    return { ok: true, output: `pong: ${target}`, data: { target } };
  },
});

export default defineModule({
  id: "my-module",
  displayName: "My Module",
  category: "offense",
  version: "0.1.0",
  description: "Example custom module",
  tools: [pingTool],
});
```

Ship it with a `module.manifest.json` as shown in §5 and build to
`./dist/index.js`. Load it in the native shell or headless run path with
`--load <specifier>` after adding the exact specifier to
`operator.trusted_modules`.
