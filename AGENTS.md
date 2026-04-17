# CLAUDE.md

This guide is for AI/code agents (Claude, Codex, etc.) working in Kuzushi, with a focus on the **Copilot module system**: how modules are structured, how they load, and how to add new ones safely.

## TL;DR

- A module is a `CopilotModule` (`src/modules/types.ts`).
- Modules expose **tools** (`module:action`) and may also contribute **pipeline tasks** (`AgentTask[]`).
- `CopilotCore` owns lifecycle and dispatch (`src/copilot/core.ts`).
- `ModuleRegistry` registers/initializes modules and resolves tools (`src/modules/registry.ts`).
- The built-in `sast` module is the reference implementation (`src/modules/core-sast.ts`).
- External modules can be loaded from:
  - builtin (`builtin:sast`)
  - local filesystem (`file:///abs/path` + `module.manifest.json`)
  - package (`package:@scope/name`)
  - MCP (`mcp:<server-spec>`)

---

## 1) Mental model: where modules fit

Kuzushi has one runtime core and three execution modes:

1. **scan mode** (`kuzushi scan`) — DAG pipeline execution.
2. **shell mode** (`kuzushi`) — conversational agent + tool dispatch.
3. **run mode** (`kuzushi run`) — headless single-tool execution.

All three modes converge on the same module abstraction (`CopilotModule`) and tool execution path (`CopilotCore.executeTool(...)`).

### Core flow

1. `CopilotCore.init()` creates/loads modules.
2. `ModuleRegistry.loadModule()` registers module + calls `init()` + wires tasks.
3. Tool calls resolve by fully-qualified name (`module:action`).
4. `ToolExecutionContext` provides runtime, bus, config, cwd, signal, and optional UI state.

---

## 2) Canonical interfaces you should know

### `CopilotModule`

Defined in `src/modules/types.ts`.

A module must provide:

- `id`, `displayName`, `category`, `version`, `description`
- `tools: ModuleTool[]`

Optional:

- `tasks: AgentTask[]` (for DAG pipeline)
- `knowledge` modules
- `events` metadata
- lifecycle hooks: `init(...)`, `dispose()`

### `ModuleTool`

Each tool must provide:

- `name`: **must be fully-qualified** (`"<moduleId>:<action>"`)
- `description`
- `inputSchema` (JSON schema-ish object)
- `headless` (if usable in non-interactive mode)
- `execute(input, ctx): Promise<ToolResult>`

### `ToolExecutionContext`

You get:

- `runtime` (LLM backend abstraction)
- `bus` (events)
- `config`
- `cwd`
- optional `target`, `workspaceId`, `signal`, `uiStore`, `seedTaskOutputs`

Use this context instead of creating ad-hoc global dependencies.

---

## 3) Module lifecycle and registry behavior

`ModuleRegistry` (`src/modules/registry.ts`) is strict about lifecycle:

- `register(mod)` throws on duplicate module ID.
- `loadModule(...)`:
  1. register
  2. `init(...)`
  3. add module tasks into shared `TaskRegistry` (if provided)
  4. rollback on failure
- `unloadModule(id)` calls `dispose()` if initialized.
- `disposeAll()` unloads in reverse order.

Tool routing:

- `resolveTool("module:action")` finds exact tool object.
- `allTools({ headlessOnly })` filters by headless compatibility.

---

## 4) How module specifiers are parsed

`parseModuleSpecifier()` in `src/modules/registry.ts` supports:

- `builtin:sast`
- `file:///absolute/path/to/module`
- `package:@kuzushi/some-module`
- `mcp:http://localhost:3000`
- bare string defaults to builtin ID (`"sast"` => builtin)

---

## 5) How loading works in `CopilotCore`

Private loaders in `src/copilot/core.ts`:

- `loadBuiltinModule(id)`
  - currently supports built-in `sast`.
- `loadLocalModule(path)`
  - reads `module.manifest.json`
  - validates requirements (`env`, `nodeVersion`)
  - imports entry module
  - enforces manifest ID == exported module ID
- `loadPackageModule(name)`
  - resolves installed package
  - if manifest exists: uses local-manifest flow
  - else: directly imports package export as `CopilotModule`
- `loadMcpModule(spec)`
  - bridges MCP tools as module tools via `createMcpModule(...)`

---

## 6) Required shape for local modules

For file-based module loading, include `module.manifest.json`.

Minimal example:

```json
{
  "id": "my-module",
  "displayName": "My Module",
  "version": "0.1.0",
  "description": "Custom Kuzushi module",
  "category": "offense",
  "entry": "./dist/index.js",
  "requires": {
    "nodeVersion": ">=22",
    "env": ["MY_API_KEY"]
  }
}
```

Validation and requirement checks live in `src/modules/loader.ts`.

---

## 7) Add a new module: practical checklist

### A) Implement the module

Create a module package (local repo folder or separate package) exporting a `CopilotModule`.

Suggested file layout:

```text
my-module/
  module.manifest.json
  src/index.ts
  src/tools/<tool>.ts
  package.json
```

### B) Define at least one tool

- Tool name must start with your module ID (`my-module:scan`, etc.).
- Keep `description` concrete; the shell planner relies on it.
- Define strict `inputSchema` so tool invocations are predictable.
- Return `ToolResult` with `ok` and useful `output`; include `data` for automation.

### C) (Optional) contribute DAG tasks

If module contributes pipeline tasks:

- expose `tasks: AgentTask[]`
- define clear `dependsOn` relationships
- ensure task IDs do not collide with existing IDs

`ModuleRegistry.loadModule(...)` auto-registers these tasks into the shared `TaskRegistry`.

### D) Load and test

Examples:

```bash
# shell with extra module
kuzushi shell --load file:///absolute/path/to/my-module

# run one tool headlessly
kuzushi run my-module:scan --input '{"target":"."}' --load file:///absolute/path/to/my-module
```

### E) Production hardening

- implement `init()` to validate credentials/connectivity up front
- implement `dispose()` for cleanup (connections, subprocesses)
- prefer deterministic outputs and structured `data`
- keep side effects explicit and auditable

---

## 8) Use `sast` module as your reference

`src/modules/core-sast.ts` shows best current patterns:

- rich tool catalog (`sast:scan`, `sast:semgrep`, `sast:codeql`, etc.)
- shared helpers for option merge and pipeline execution
- consistent summary output + optional cost accounting (`costUsd`)
- graceful handling of auth/config errors
- reuse of core scan pipeline instead of forked implementations

When in doubt, mirror `createCoreSastModule()` conventions for naming, schemas, and output ergonomics.

---

## 9) Guardrails for agents editing this repo

- Do not break `CopilotModule`/`ModuleTool` contracts without deliberate migration planning.
- Preserve the `module:action` naming convention.
- Prefer adding behavior in module/tool layer before touching orchestrator internals.
- If you add task-producing modules, include tests around dependency ordering.
- Keep `headless` truthful: shell-only behavior should not be marked headless.

---

## 10) Quick troubleshooting

### "Unknown tool: module:action"

- Module not loaded, wrong module ID, or tool name mismatch.
- Check `module.id`, `tool.name`, and load specifier.

### "No module.manifest.json found"

- Local module loader requires manifest at module root.

### "requirements not met"

- Missing env vars and/or Node version mismatch (see manifest `requires`).

### "Module ID mismatch"

- `module.manifest.json` `id` must match exported module object's `id`.

---

## 11) One-file module starter (TypeScript)

```ts
import type { CopilotModule } from "kuzushi/modules";

const module: CopilotModule = {
  id: "my-module",
  displayName: "My Module",
  category: "offense",
  version: "0.1.0",
  description: "Example custom module",
  tools: [
    {
      name: "my-module:ping",
      description: "Connectivity check",
      inputSchema: {
        type: "object",
        properties: { target: { type: "string" } },
      },
      headless: true,
      async execute(input) {
        const target = (input as { target?: string }).target ?? "default";
        return {
          ok: true,
          output: `pong: ${target}`,
          data: { target },
        };
      },
    },
  ],
};

export default module;
```

Use this as a skeleton, then add runtime/bus/config integration through `ToolExecutionContext` as needed.

---

## Security & Secrets

- Never commit API keys or `ANTHROPIC_API_KEY` values.
- Do not commit findings DB files (`<repo>/.kuzushi/findings.sqlite3`).
- The `.kuzushi/` directory, the SQLite DB, and per-run batch files are
  created with restrictive permissions (`0700` / `0600`). Do not relax
  them.
- Subprocesses spawned via `ClaudeSession`/pi-ai inherit a **filtered**
  environment via `buildSubprocessEnv()` in `src/agent-runtime/env.ts`.
  Add new safe env vars to that allowlist rather than spreading
  `process.env` directly.
- For CI/CD, prefer `agentRuntimeConfig.apiKeyFile` (path to a file at
  `0600`) over writing the literal key into `~/.kuzushi/config.json`.
  See `src/credentials.ts#resolveAgentRuntimeConfig`.
- Code-execution features (`--dynamic-analysis`, `pocExecute`) require
  an explicit opt-in (`--yes` / `KUZUSHI_YES_RUN_GENERATED_CODE=1`) in
  non-TTY contexts. See `ensureCodeExecutionOptIn` in
  `src/cli/commands/scan.ts`.
