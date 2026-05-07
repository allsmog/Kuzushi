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

## 2. When to build one

Build a module when:

- You have a new scanner, intel feed, recon probe, or remediation action and
  it shouldn't live inside the core `sast` module.
- You want independent versioning, tests, and release cadence.
- You need to ship capability to operators via `--load file://…` or
  `--load package:@scope/name` without forking Kuzushi.

## 3. Anatomy

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

## 4. Manifest — `module.manifest.json`

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | `string` | yes | `[a-z][a-z0-9-]*`. Must equal the exported module's `id`. |
| `displayName` | `string` | yes | Shown in `/modules` and catalog. |
| `version` | `string` | yes | Module's own semver. |
| `description` | `string` | yes | One-line summary. |
| `category` | `"offense" \| "defense" \| "governance" \| "intel"` | yes | Grouping in the catalog. |
| `entry` | `string` | yes | Relative path to the compiled entry (e.g. `./dist/index.js`). |
| `kuzushiSdkVersion` | `string` | no (warn if missing) | Host SDK the module was authored against. Drift produces a warn. |
| `requires` | `{ env?: string[]; bins?: string[]; nodeVersion?: string }` | no | Checked before `init()`. |
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

## 5. The `CopilotModule` contract

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
(stability / reliability / side-effects), `examples` (shell snippets shown by
`examples <id>`), `requires`, `knowledge`, `events`, `hidden`,
`init(config, ctx)`, `dispose()`.

> **DAG participation.** DAG nodes are `DagTool`s declared inside `tools`.
> Use `defineDagTool<"<id>">({...})`; hidden infrastructure nodes use the
> same `DagTool` contract with `hidden: true`.

See `src/modules/core-sast.ts` for the canonical reference.

## 6. Writing a tool

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

### 6.1. Writing a `DagTool`

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

Authors don't implement `execute` themselves — the module registry installs
one automatically. It re-enters the scan pipeline filtered
to this one task, so shell dispatch (`/use my-scanner; run`) and headless
`kuzushi run my-scanner:hunt --target ./repo` both share the exact code path
scan mode uses.

**Hidden DAG tools.** Internal helpers that shouldn't appear in `/use`
overviews or LLM tool lists should still be authored with `defineDagTool`;
set `hidden: true` and keep dependency names qualified.

## 7. `ExecutionContext` reference

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
| `uiStore?: HostUiHandle` | narrow-handle | Read/update the Ink shell's UI state. |
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
boundary (`src/agent-runtime/enforcement.ts`) rejects empty / incompatible
models, and `loadConfig` validates `agentRuntimeBackend` against
`config.model` before any LLM call. The right resolution chain is:

```ts
const model =
  ctx.toolModel /* setg <MODULE>_MODEL=… or /set model … */ ??
  (input?.model as string | undefined) /* inline tool arg */ ??
  ctx.config.model /* operator-configured global */;
```

For DAG tasks use `resolveTaskModel(context, "<task-id>")` from
`src/agents/tasks/runtime-overrides.ts`, which already follows this
precedence and falls back to `context.config.model`.

Anything that looks like `model = X ?? "anthropic:claude-..."` is the
silent-fallback pattern the audit removed and must not return.

## 8. `reportActivity` vs `reportOutput`

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

## 9. `costUsd`

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

## 10. Capability probe — `ctx.host.capabilities`

`ctx.host` is populated by `CopilotCore.executeTool`. Feature-probe before
depending on an optional capability so your tool survives both shell-mode
and headless `run`:

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

## 11. Load specifiers

Kuzushi resolves four specifier prefixes:

| Prefix | Example | Source |
|--------|---------|--------|
| `builtin:` | `builtin:sast` | Shipped inside the kuzushi package. |
| `file://` | `file:///abs/path/to/my-module` | Local directory with `module.manifest.json`. |
| `package:` | `package:@kuzushi/blackbox` | Installed npm package (manifest optional). |
| `mcp:` | `mcp:http://localhost:3000` | MCP server — see §15. |

A bare string (`"foo"`) defaults to `{ type: "builtin", id: "foo" }`.

```bash
# Interactive shell with a local module
kuzushi shell --load file:///abs/path/to/my-module

# Headless single-tool dispatch
kuzushi run my-module:ping --input '{"target":"example.com"}' \
  --load file:///abs/path/to/my-module
```

## 12. Load errors — `ModuleLoadError`

The loader throws `ModuleLoadError` instead of plain `Error`. Branch on
`err.code`:

| Code | Cause | Fix |
|------|-------|-----|
| `MANIFEST_MISSING` | No `module.manifest.json` in the target directory. | Create the manifest at the module root. |
| `MANIFEST_INVALID` | Zod-parse failure (missing field, bad semver, bad category). | `err.details.issues` lists every problem. |
| `REQUIREMENTS_UNMET` | Env var missing, Node too old, etc. | Set the env/upgrade Node per `manifest.requires`. |
| `ENTRY_NOT_FOUND` | `entry` path doesn't exist. | Run your build; check `entry` is relative to the manifest. |
| `SHAPE_INVALID` | Exported module failed `validateModuleExport`. Includes tool-name-prefix and duplicate-name violations. | Error message lists the violating tool index. |
| `ID_MISMATCH` | Manifest `id` ≠ exported module's `id`. | Align them. |
| `SDK_INCOMPATIBLE` | `kuzushiSdkVersion` major mismatch with host. | Update the manifest or the host. Currently warns; will reject in a future release. |
| `CONFIG_INVALID` | `moduleConfig` fails the manifest's `configSchema`. | Check `err.details` for schema path + message. |

`ModuleLoadError extends Error`, so legacy `catch (err) { err.message }`
patterns keep working.

## 13. Testing

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

## 14. Scaffolding status

The legacy TypeScript CLI had a `kuzushi create-module` scaffolder during SDK
hardening. That command is not part of the current Rust operator CLI, so it
must not appear in first-run instructions or CI examples.

Until a Rust-native scaffolder is implemented, create the layout from §3
manually:

- `module.manifest.json` with `$schema`, `id`, `displayName`, `version`,
  `description`, `category`, `entry`, and `kuzushiSdkVersion`.
- `package.json` with `peerDependencies.kuzushi` pinned to the host major.
- `src/index.ts` using `defineModule` + `defineTool`.
- `src/index.test.ts` using `createMockToolContext` + `expectModuleShape`.
- `README.md` with load and run examples.

## 15. MCP modules

Kuzushi can bridge any MCP-compatible server into a `CopilotModule` via
`--load mcp:<spec>`. Each MCP tool becomes a `ModuleTool`; the bridge
preserves the full `inputSchema` (required, additionalProperties, nested
shapes) and applies configurable timeouts (default 60s).

MCP-bridged tools default to `headless: false` unless the server advertises
`annotations.readOnlyHint: true && !destructiveHint`. Pass `trustHeadless:
true` via `createMcpModule` options to trust server-declared hints wholesale.
Auth tokens flow via `CreateMcpModuleOptions.authToken` or the
`KUZUSHI_MCP_TOKEN` env var (sent as `Authorization: Bearer <token>`).

The minimum an MCP server must implement to be Kuzushi-compatible is
documented in [`mcp-server-requirements.md`](./mcp-server-requirements.md).

## 16. Troubleshooting

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| `Unknown tool: module:action` | Module not loaded, wrong id, or tool prefix mismatch. | Check `/modules`; verify `--load` specifier. |
| `ModuleLoadError: MANIFEST_MISSING` | No `module.manifest.json` at the path. | Add manifest at module root. |
| `ModuleLoadError: REQUIREMENTS_UNMET` | Missing env var or Node version. | Set env; upgrade Node per manifest. |
| `ModuleLoadError: ID_MISMATCH` | Manifest `id` ≠ exported module's `id`. | Align them. |
| `ModuleLoadError: SHAPE_INVALID` with "does not start with" | Tool name prefix violates module id. | Rename tool to `<id>:<action>` or use `defineTool<"id">`. |
| `ModuleLoadError: SHAPE_INVALID` with "duplicate" | Two tools share a name. | Rename the duplicate. |
| `ModuleLoadError: SDK_INCOMPATIBLE` | Manifest `kuzushiSdkVersion` major differs from host. | Bump manifest or pin host. |
| MCP tool stuck for 60s | Server timeout. | Raise `timeoutMs` or investigate server. |

## 17. Minimal starter

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

Ship it with a `module.manifest.json` as shown in §4, build to `./dist/index.js`,
then:

```bash
kuzushi shell --load file:///abs/path/to/my-module
```
