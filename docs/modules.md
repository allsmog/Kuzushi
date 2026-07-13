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
more **tools** (callable from shell, headless `run`, or pipeline tasks when
the loading surface supports that mode) and
optionally contributes pipeline **tasks**, **knowledge** packs, and event
declarations. Kuzushi's shell, scan pipeline, and `run` command all dispatch
through the same module contract — a tool written once works in all three
modes.

## 2. Current Rust Product Status

Kuzushi has one module/tool contract, but not every loading surface is equally
productized today.

- **Built-in Rust modules are execution parts, not the default product
  navigation.** The shell projects them into six phase capabilities; direct
  engines remain discoverable through `tools`, `/use`, scan tasks, and
  `kuzushi run <module:tool>`.
- **Retained TypeScript SDK modules are an authoring and compatibility
  surface.** The SDK remains useful for tests, package shape, dynamic-module
  descriptors, and migration references.
- **Dynamic `file://`, local path, and `package:` module loading is supported
  through the native CLI's global `--load` flag for shell and headless `run`.**
  Local file/path modules execute as KWP workers only after the host hashes the
  exact resolved bundle and finds an active `kuzushi.lock` approval for its
  digest and descriptor hash. `package:` remains a trusted compatibility path.
- **MCP servers and deferred plugin adapters are exact, explicit integrations.**
  Rust MCP servers are exposed through `kuzushi mcp serve <backend>` and the
  agent bridge. The legacy `mcp:` module specifier remains a parsed
  compatibility form in the TypeScript SDK; it is not the native dynamic-loader
  path.

This guide documents the contract and the SDK shape. Shipping behavior should
be checked against the shell capability projection, `kuzushi tools`, and the
Rust registry tests before docs claim a capability is available to operators.
`kuzushi modules` remains a machine-readable registry view, not the normal
interactive journey.

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
    additionalProperties: false,
    properties: { target: { type: "string" } },
    required: ["target"],
  },
  headless: true,
  phase: "operate",
  effect: "read",
  approval: "none",
  workspaceRequirement: "required",
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

Model-backed tools that offer operator-editable instructions declare prompt
metadata on ToolDescriptor. Each entry names its role, canonical option key,
built-in instruction template, and project override location under
.kuzushi/prompts. This metadata drives shell preflight review; generated
repository context is not embedded in the editable template. A tool without
prompt metadata must not be presented as editable merely because it uses a
model.

Prompt provenance is part of the dispatch contract. Text auto-loaded from
`<target>/.kuzushi/prompts/<module>/<verb>.md`, or read through a prompt path
inside the target, is repository-owned data. The shared preparation boundary
wraps it as optional focus/context below the descriptor's immutable built-in
safety and output-contract instructions; it never becomes a replacement
system prompt. Target-local workspace option stores may not set descriptor
prompt keys. Explicit inline prompt text from one-shot tool input, shell
session options, or the operator-owned global option store remains an explicit
operator replacement. Scan, shell, and run all apply this split through the
same Rust registry preparation path.

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
  phase: "hunt",
  effect: "workspace-write",
  approval: "none",
  workspaceRequirement: "required",
  inputSchema: {
    type: "object",
    additionalProperties: false,
    properties: { target: { type: "string" } },
  },
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
    pub trace: Option<&'a TraceHandle>,
    pub cancellation: Option<&'a ScanCancellation>,
    pub authorization: ExecutionAuthorization,
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

`cancellation` is the one shared cancellation capability for native scanners,
nested `sast:scan` subtools, dynamic hosts, and runtime bridges. Code that
spawns work must propagate it instead of constructing a fresh token.
`authorization` records whether dispatch is automated, an explicit headless
operator invocation, or an interactively approved shell action; descriptor
approval and `headless` policy are enforced from that proof at the shared
dispatch boundary.

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
`taint-iris-next:finding-review`, `offense-review:threat-hunt`, `patch:finding`,
`threat-model:build`, `x-ray:run`, `run_plugin_finding_adapter` (used
by `vuln-scout:audit` / `tob:audit`), `shinsa:scan`, `prompt-armor:*`.

**Hidden modules** (`pipeline:*`, `systems-hunt:*`, `context-lite:index`,
compatibility aliases, and quarantined exact-only surfaces such as
`full-mode:*`, `deep-audit:*`, `exploit-chain:*`, `pwn:*`, `threat-leads:*`,
`chrome-rce:*`, and `vendor-assessment:*`) collapse into one aggregated
`subsystems` row in the Activity view. Their events also still flow through
but are filtered out of the right-pane feed unless the operator presses `V`
(verbose).

Folded support facades (`catalog`, `module-recommender`, `bounty`, and
`randori`) are exact-only during the capability migration. Canonical operator
routes are direct registry queries, the phase capability projection,
`recon:import`, and `threat-model:build` methodology options respectively.
Optional adapter packages do not become visible merely by existing in
`node_modules`; adapter configuration must be explicit.

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
bus is wired. KWP-backed dynamic modules that publish to the bus go through
`kuzushi/bus/publish`; the host checks `grant.bus.produce`, stamps module
origin, and records workspace-backed publishes in
`.kuzushi/v3/runs/<runId>/kwp-bus.jsonl`.

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
`--load <specifier>` flag for `kuzushi shell` and `kuzushi run`. For local
file/path modules, v0.1 accepts one self-contained entry file, hashes it, checks
`kuzushi.lock`, copies the approved bytes into a private read-only snapshot,
and starts a Node KWP worker over JSON-RPC stdio. Multi-file directory bundles
remain future work. Descriptor probing uses the same stripped environment and
exact-file-read Node permission shape as the serve worker. KWP loading requires
permission-mode network denial (`--allow-net`, introduced in Node 25); Kuzushi
does not pass that flag, adds a macOS network sandbox, and requires Node 26.3.1
or newer on other platforms. Execution performs a live `initialize` handshake,
checks the descriptor hash again, then invokes `tools/call`; module stdout is
redirected to tagged stderr so it cannot corrupt protocol output.

The old `[operator].trusted_modules` list remains only for non-local
compatibility specifiers. It is not the trust decision for local workers.
Headless dynamic invocations also require an explicit global
`--target <workspace>` so trust/config and run artifacts are rooted before the
module executes; dynamic inline path options are never used to bootstrap that
trust decision.

Every privileged worker call carries the host-issued invocation id and epoch.
The host rejects missing, mismatched, stale, or post-settlement authority
before dispatching filesystem, runtime, network, MCP, fuzz, findings,
artifacts, or bus handlers. A watchdog expiry or operator cancellation sends
`notifications/cancelled`, records the cancellation, drops stale results, and
kills the worker process group.

Approve a local module before loading it:

```sh
kuzushi kwp approve file:///abs/path/to/my-module.mjs --grant grant.toml
kuzushi --target /abs/workspace \
  --load file:///abs/path/to/my-module.mjs \
  run my-module:tool --input '{}'
```

Workspace-backed runs write broker decisions and invocation lifecycle events
to `.kuzushi/v3/runs/<runId>/kwp-audit.jsonl`, with bus publishes in
`kwp-bus.jsonl`. Inspect and verify the hash-linked audit chain with:

```sh
kuzushi kwp audit --target /abs/workspace --run-id run_... --json
```

An empty lockfile `signatureChain` is a local operator approval. Non-empty
entries use `ed25519:v1:<keyId>:<base64Signature>` and are checked against
global operator signing keys before worker spawn.

`kuzushi scan` deliberately does not load dynamic Node modules. Passing
`--load` with `scan` is a hard error with guidance to invoke the trusted tool
through `kuzushi run`; the flag is never silently discarded and a dynamic tool
is never invented as a `sast:scan` task. Other commands outside shell/run
(`modules`, `tools`, `findings`, `doctor`, `mcp`, and so on) reject `--load`
too, rather than accepting an operator input they will not consume.

### 12.1 Native dynamic-host contract

The native host projects a deliberately narrow, execution-safe subset of the
retained SDK:

- Module metadata: `id`, `displayName` (legacy `name` is accepted), `category`
  (legacy `kind` is accepted), `description`, `hidden`, and `tools`.
- Tool metadata: `name`, `description`, explicit `headless`, `effect`,
  `approval`, and `workspaceRequirement` values; optional `hidden`; a `phase`
  that is mandatory for effectful tools; and optional
  `runtimeRequirement: "never" | "always"`.
- Tool input: either explicit descriptor `options`, or the restricted object
  `inputSchema` described below.
- Execution: `execute(input, ctx)` or the legacy `run(input, ctx)` spelling.

Module ids and tool names are syntax-checked, duplicate names and aliases are
rejected, and registration is atomic. A dynamic module cannot replace an
already loaded module or tool. `headless` has no implicit default:
`headless: false` remains usable in the shell, while `kuzushi run` rejects it.
Dynamic policy also has no permissive default. `effect` is one of `read`,
`workspace-write`, `target-write`, `repository-execute`, or `external-action`;
target writes, repository-selected command execution, and external effects
require `approval: "explicit"`. `workspaceRequirement` is `optional` or
`required`. Effectful tools must declare a concrete journey `phase` rather
than falling into `operate`, so an unknown extension can never escape the
autonomy ceiling. A `repository-execute` surface must bind its resolved
commands into canonical prepared input before authorization, disclose them
before an interactive dispatch (or emit the exact preflight for an explicit
headless invocation), and fail closed when an isolating execution backend is
unavailable.

Every explicit option with `type: "path"` must also declare
`pathSemantics`: `workspace-read`, `state-write`, `target-write`,
`external-read`, `external-write`, or `executable`. `state-write` is confined
to `<target>/.kuzushi`; `target-write` is confined to the active target and
requires an explicit authorization proof; external, executable, and write
paths cannot come from target-owned workspace options. The host rejects a
path option without semantics instead of guessing. Existing dynamic modules
must add this field before upgrading.

The native process and the Node host perform a version handshake before
describing or executing a module. Both the protocol version and the Kuzushi
package semver must match, including for a
`KUZUSHI_DYNAMIC_MODULE_HOST` override. `ctx.host.sdkVersion` reports that
package semver; it is not a protocol label.

Host children are supervised as process trees, not only as direct PIDs.
Describe calls have a 30-second ceiling, execute calls have a 10-minute
ceiling, stdout is capped at 64 MiB, stderr at 64 KiB, and runtime protocol
lines at 64 MiB. Cancellation, timeout, malformed protocol, and oversized
output terminate the process group on Unix and the kill-on-close Job Object on
Windows before returning an error.

For `inputSchema`, the native bridge requires top-level
`additionalProperties: false`, because Rust descriptor validation rejects
unknown option keys. The bridge supports object properties with primitive
string/boolean/integer/number types, string enums, JSON objects without nested
schema constraints, and arrays of strings. Supported property metadata is
`description`, `default`, `enum`, and `items`. Unsupported schema keywords,
non-string enum members, undeclared required properties, invalid defaults, and
non-string array items fail during load instead of being weakened silently.
Use explicit descriptor `options` when the JSON Schema subset cannot express
the input honestly.

The legacy one-shot compatibility host cannot honor SDK lifecycle and DAG
state. It rejects
module `init`, `ready`, `dispose`, `requires`, `knowledge`, and `events`, plus
tool `init`, `dag`, and `runLifecycle`, rather than loading them and ignoring
their behavior. The native execution context supplies `cwd`, `target`, tool
identity, config, a feature-probe host with no advertised optional
capabilities, and an explicit error for unsupported `ctx.bus` access. Local
KWP workers instead expose only the capabilities pinned in their lockfile
grant and route every effect through the host broker.

Set `runtimeRequirement: "always"` when the tool calls `ctx.runtime`. The
native runtime adapter accepts the common SDK query shape
`{ prompt, options: { model, cwd, temperature, maxOutputTokens, allowedTools,
outputFormat, systemPromptPrefix, effort } }`. Its result is compatible with
both styles during migration:

```ts
// Retained SDK streaming shape.
for await (const message of ctx.runtime.query(request)) {
  if (message.type === "result" && message.subtype === "success") {
    console.log(message.result);
  }
}

// Legacy native dynamic-module shape.
const response = await ctx.runtime.query(request);
console.log(response.text);
```

SDK query options that the Rust callback cannot preserve (for example custom
tools, history, permission callbacks, or a separate budget) produce an
explicit error. Runtime-free tools receive an unavailable-runtime handle, so
using `ctx.runtime` without declaring `runtimeRequirement: "always"` also
fails explicitly.

The retained TypeScript SDK parser also understands four compatibility
prefixes:

| Prefix | Example | Source |
|--------|---------|--------|
| `builtin:` | `builtin:sast` | Shipped inside the kuzushi package. |
| `file://` | `file:///abs/path/to/my-module/dist/index.js` | Absolute compiled JavaScript module entry. |
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

`createMockToolContext` keeps its compatibility profile populated with
recording runtime, logger, UI, datastore, workspace, event, and print handles.
Pass a field as explicit `undefined` to test that handle's absence, or pass
`{ profile: "headless" }` to omit the runtime and optional operator-facing
handles together. Any handle explicitly supplied to a headless profile wins.
When `host` is not overridden, its capability set is inferred from the final
resolved handles. An explicit host capability set remains authoritative, but
the helper rejects a capability that advertises an omitted handle.

`assertToolResult(result, { costUsdMax })` treats cost as measured data rather
than assuming an omitted cost is zero. Both the bound and `result.costUsd` must
be finite, nonnegative numbers; missing, nonnumeric, negative, `NaN`, and
infinite values fail with a diagnostic. See `src/testing/index.ts` for the full
helper list.

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
module bridge. Every npm and platform-native runtime payload ships the Rust
servers exposed by the CLI: `gtags`, `clang`, `joern`, `tree-sitter`,
`codeql`, `revng`, `context`, `entry-points`, `threat-model`, `threat-intel`,
and `x-ray`. Operators can run them over stdio with:

```bash
kuzushi mcp serve <backend>
kuzushi mcp health <backend>
```

Agent-backed tools opt into these servers through the Rust agent bridge and
tool policy. The legacy `mcp:` module specifier remains a parsed compatibility
form in the TypeScript SDK, but the native CLI does not convert arbitrary MCP
servers into module tools.

KWP workers reach MCP servers only through host-mounted aliases configured in
global `operator.mcp_mounts`. A module grant names the alias and allowed tool
names; module code calls `ctx.mcp.call(...)` and never spawns or connects to
the server directly. The host validates the mount descriptor hash, isolates
per-invocation sessions, meters deadlines, and verifies returned artifacts.

Fuzzing follows the same pattern through `ctx.fuzz.run(...)` and global
`operator.fuzz_executors`. The worker needs both a matching fuzz grant and
`artifacts.write`; networked fuzzing is denied by default. The first-party
example at `examples/kwp/agentic-fuzz/module.mjs` writes its plan through
brokered workspace FS, optionally calls a mounted `symcc` alias, invokes the
selected host fuzz executor, and records verified artifact references.

`ctx.net.fetch(...)` is also host-brokered. Allowlisted requests can spill a
bounded response to an artifact via `responseArtifactPath`; request and
response bytes count cumulatively against `maxBytesPerInvocation`, with DNS/IP
SSRF checks, unsafe-header stripping, named-credential validation, and
redirects disabled in the live local-worker backend.

The npm wrapper prepends its private native platform directory to the child
`PATH`, and the Rust CLI also resolves an MCP executable next to itself. This
keeps `mcp health`, direct native archives, and bridge-spawned tools independent
of an operator's global `PATH`. Servers that wrap Joern, CodeQL, clangd, GNU
GLOBAL, or rev.ng still report those external engine prerequisites honestly.
The pure tree-sitter and artifact-reader servers have no external engine.

The npm package is the full Node-capable distribution. Platform-specific
native archives on GitHub contain the CLI and MCP siblings only; use the npm
tarball or a source checkout when a tool needs the LangGraph or trusted
dynamic-module Node host.

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
    additionalProperties: false,
    properties: { target: { type: "string" } },
    required: ["target"],
  },
  headless: true,
  phase: "operate",
  effect: "read",
  approval: "none",
  workspaceRequirement: "required",
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
`./dist/index.js`. Approve the exact resolved bundle, then load it in the
native shell or headless run path:

```bash
kuzushi kwp approve file:///absolute/path/to/my-module/dist/index.js
kuzushi --target . --load file:///absolute/path/to/my-module/dist/index.js \
  run my-module:ping --input '{"target":"example.com"}'
```
