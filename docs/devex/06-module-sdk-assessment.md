# DX-6 — Module SDK Assessment

Status: research-only (no `src/modules/**` edits).
Date: 2026-04-21.
Scope: the third-party author experience of the `kuzushi` / `kuzushi/modules` / `kuzushi/testing` SDK surface.

Current Rust CLI note: this assessment mentions the legacy TypeScript
`kuzushi create-module` scaffolder as historical audit context. The current
Rust operator CLI does not expose that command.

## 1. Executive summary

The Kuzushi module SDK has a coherent runtime contract (`CopilotModule`, `ModuleTool`, `ToolExecutionContext`) and a working loader pipeline for four module sources (builtin / file / package / MCP). However, the public surface is **not yet safe for third-party authors outside the `@kuzushi/*` github dependencies**:

- `ToolExecutionContext` in `src/modules/types.ts:161-192` leaks four internal-only abstractions via `import("...")` type references (`UIStore`, `Datastore`, `WorkspaceManager`, `ModuleEventScope`). A third party must resolve those paths for their types to compile, which couples their build to host internals.
- There is **no SDK version signal at all** — no `kuzushiSdkVersion` field in `ModuleManifest` (`src/modules/types.ts:305-318`), no capability probe, no min-host version check in `loader.ts`. A host-SDK break would silently load a mismatched module.
- `kuzushi/modules` currently re-exports only types and the registry, not a `defineModule()` helper; `kuzushi/testing` covers only the runtime fields a tool happens to read, not every `ToolExecutionContext` field.
- `ModuleTool.name` **is not validated against `module.id`** at load time — a third-party module can register `evilmod` with a tool named `sast:scan` and shadow a builtin under `allTools()`.

**Biggest single gap:** the `import("...internal path...")` leaks in `src/modules/types.ts`. They are visible through the `kuzushi/modules` re-export and will break any external author who tries to typecheck against a non-development install.

## 2. Stable contracts — ready for third-party use

These types/functions are well-shaped and should be frozen:

- `CopilotModule` (`src/modules/types.ts:360-427`) — the core unit; read-only fields, no internal leaks on the module side.
- `ModuleTool` (`src/modules/types.ts:243-288`) — clean shape once `ToolExecutionContext` is cleaned.
- `ToolResult` (`src/modules/types.ts:129-138`) — minimal and stable.
- `ModuleManifest` (`src/modules/types.ts:305-318`) — stable; needs **additive** fields (see §4).
- `ModuleRequirements` (`src/modules/types.ts:295-302`).
- `ModuleReference` (`src/modules/reference.ts:2-5`), `ModuleCategory`, `ModuleRank`, `ModuleNotes`.
- `parseModuleSpecifier` (`src/modules/registry.ts:264-280`) — deterministic, ok to export.
- Testing helpers `createMockToolContext`, `createMockBus`, `noopRuntime` (`src/testing/index.ts:30-91`) — shape is correct, coverage gaps noted in §4.

## 3. Accidentally public (dep leaks)

| Symbol | File:line | Leaks | Fix | Confidence |
| --- | --- | --- | --- | --- |
| `ToolExecutionContext.uiStore` | `src/modules/types.ts:161` | `import("../ui/state.js").UIStore` | Replace with an opaque `HostUiHandle` interface declared in `modules/types.ts` with only the methods a tool needs (or mark `uiStore: unknown` in the public type and narrow internally). | **high** |
| `ToolExecutionContext.datastore` | `src/modules/types.ts:179` | `import("../copilot/options.js").Datastore` | Move `Datastore` interface next to `types.ts` as `ToolOptionStore` with `.get<T>(key)` / `.set(key, val)` only. | **high** |
| `ToolExecutionContext.workspace` | `src/modules/types.ts:185` | `import("../workspace/manager.js").WorkspaceManager` | Extract a `WorkspaceHandle` interface in `modules/workspace-handle.ts` with the ~6 methods third parties use (hosts, services, findings read/write). | **high** |
| `ToolExecutionContext.events` / `ModuleContext.events` | `src/modules/types.ts:192, 338` | `import("../bus/module-events.js").ModuleEventScope` | Re-export `ModuleEventScope` from `kuzushi/modules` OR inline a narrower `ModuleEventScope` in `modules/types.ts` that only exposes `emit/on/off`. | **high** |
| `ToolExecutionContext.runtime: AgentRuntime` | `src/modules/types.ts:149` via `../agent-runtime/types.js:12` | Pulls in `AgentQueryOptions` (structured output, thinking, permission modes) | `AgentRuntime` is broad but this is the one legitimate leak — accept it and re-export from `kuzushi/modules`. | **low (discussion)** |
| `ToolExecutionContext.config: KuzushiConfig` | `src/modules/types.ts:153` via `../types.js` | Full host config shape | Either (a) narrow to `ToolConfigView` with only the surface tools read, or (b) accept and re-export. | **low (discussion)** |
| `ToolExecutionContext.bus: MessageBus` | `src/modules/types.ts:151` via `../bus/types.js:15` | Exposes `publish<E>`, `subscribe`, `unsubscribe`, `waitFor`, `close` — more than tools should touch | Add a narrower `ToolBus` interface (publish + subscribe only) that `MessageBus` extends. | **low (discussion)** |
| `ToolExecutionContext.print: PrintSink` | `src/modules/types.ts:173` via `../copilot/print.js` | `copilot/` path-leak | Either move `PrintSink` to `modules/print.ts` and have the shell depend on it, or accept. | **low (discussion)** |

## 4. Missing for third parties

### SDK version signal

- `ModuleManifest` has no `kuzushiSdkVersion` or `apiVersion` field (`src/modules/types.ts:305-318`). Loader ignores SDK drift (`src/modules/loader.ts:31-68`).
  - **Fix:** add optional `kuzushiSdkVersion?: string` to `ModuleManifest`, validate in `validateManifest` against `package.json`'s `version` with a semver-major compat check; warn (don't reject) on mismatch for the first release.
- No runtime probe for the loaded module to check host capabilities. Grepped: `kuzushiSdkVersion|sdkVersion|apiVersion` → 0 hits across `src/`.
  - **Fix:** inject `ctx.host = { sdkVersion, capabilities: Set<"workspace" | "structured-output" | "ui-store" | ...> }` into `ToolExecutionContext` (add after `src/modules/types.ts:237`). `CopilotCore.executeTool` (`src/copilot/core.ts:308-329`) already has the data to populate this.

### `defineModule()` / `defineTool()` builders

- `src/modules/index.ts` exports type aliases only. Authors must write `const mod: CopilotModule = { ... }` with an explicit annotation to get the right inference. A `defineModule<TConfig>(spec)` helper would (a) type-check the tool-name prefix vs. `id`, (b) infer the input schema, (c) emit runtime guards.
  - **Fix:** add `defineModule()` + `defineTool()` in a new file (`src/modules/define.ts`) and re-export from `src/modules/index.ts`.

### Structured error types

- `loader.ts` throws plain `Error` strings (`src/modules/loader.ts:17, 53, 107, 149`). Third parties can't programmatically handle e.g. "manifest missing id" vs "entry file missing".
  - **Fix:** introduce `ModuleLoadError` with `code: "MANIFEST_MISSING" | "MANIFEST_INVALID" | "REQUIREMENTS_UNMET" | "ENTRY_NOT_FOUND" | "SHAPE_INVALID" | "ID_MISMATCH" | "SDK_INCOMPATIBLE"` and `details`. Host already does ID mismatch at `src/copilot/core.ts:505-509`.

### Author-facing telemetry hooks

- `ctx.reportActivity` / `ctx.reportOutput` (`src/modules/types.ts:212-236`) cover progress, but there is no way for a tool to log structured diagnostics (warn/error/info) that the shell could surface in a "module log" panel. `ctx.print` (`src/modules/types.ts:173`) is close but uses the internal `PrintSink` shape.
  - **Fix:** add `ctx.logger?: { info, warn, error, debug }` with a tiny interface definition in `modules/types.ts`; default implementation emits to `bus`.

### Config-schema enforcement

- `ModuleManifest.configSchema` (`src/modules/types.ts:315`) is accepted but never validated against the `moduleConfig` passed to `init()` (`src/modules/registry.ts:72-74`).
  - **Fix:** in `ModuleRegistry.loadModule`, when manifest has `configSchema`, validate `opts.moduleConfig` against it before `mod.init(...)` is called.

## 5. Naming & enforcement gaps

- **Tool name prefix is documented, not enforced.** `validateModuleExport` (`src/modules/loader.ts:121-151`) checks `tool.name` is a string but not `name.startsWith(moduleId + ":")`. A module with `id: "foo"` can legally ship `{ name: "sast:scan", ... }`. The registry's `resolveTool` (`src/modules/registry.ts:178-192`) then finds it under the real owner, but `allTools()` returns both, creating shadow.
  - **Fix:** in `validateModuleExport`, reject `tool.name` that does not match `^[a-z][a-z0-9-]*:[a-z][a-z0-9_-]*$` and does not start with `<module.id>:`.
- **Duplicate tool names within a module.** `validateModuleExport` doesn't check for `tool.name` duplicates inside the same `tools[]`. `resolveTool` picks the first via `find`, silently hiding the rest.
  - **Fix:** reject duplicates in `validateModuleExport` after the existing loop (`src/modules/loader.ts:135-146`).
- **`headless: true` is not enforced.** No lint checks whether a headless tool reads `process.stdin` or spawns interactive binaries. Defined purely as an honor-system flag at `src/modules/types.ts:255`.
  - **Fix:** document explicitly that headless means "no prompts, no TTY allocation, no interactive subprocess attach." Add a lint check in `validateModuleExport` that complains (non-fatal) when a headless tool is missing an `inputSchema.required` entry (a heuristic proxy for "needs user input").
- **`manifest.id` vs `module.id` mismatch** is caught (`src/copilot/core.ts:505-509`) but not for npm packages without a manifest (`src/copilot/core.ts:549-552`). A package shipped without a manifest goes through `dynamicImportModule` which only does shape validation. A typo in `id` loads silently under the wrong name.
  - **Fix:** require manifests for `package:` mode once `kuzushiSdkVersion` lands; until then, log a warn.
- **`parseModuleSpecifier` default-to-builtin is surprising.** A bare string (`"foo"`) becomes `{ type: "builtin", id: "foo" }` and throws "Unknown built-in module" deep in `loadBuiltinModule` (`src/copilot/core.ts:480-482`). Third parties expecting package resolution get a misleading error.
  - **Fix:** make the default fall through to a "auto" resolver that tries builtin, then package, with a clear aggregated error.

## 6. Concrete implementation handoffs

### `[SCHEMA]` — Manifest / Zod agent

1. **Add `kuzushiSdkVersion?: string` to `ModuleManifest` + validate in loader.** Files: `src/modules/types.ts:305-318`, `src/modules/loader.ts:31-68`. Why: third parties need a way to declare host compat and the host needs to warn on drift. **High-confidence.**
2. **Introduce `ModuleLoadError` with `code` discriminator.** Files: new `src/modules/errors.ts`, `src/modules/loader.ts` (replace all `throw new Error(...)`), `src/copilot/core.ts:485-512`. Why: programmatic handling of load failures. **High-confidence.**
3. **Enforce `configSchema` against `moduleConfig` before `init()`.** Files: `src/modules/registry.ts:67-74` (add Zod-based validate step). Why: config-schema is declared but silently ignored. **High-confidence.**
4. **Extract `schema.ts` into a real Zod-backed module.** Files: `src/modules/schema.ts` (currently 2 lines) → add `zJsonSchema`, `zModuleManifest`, `zCopilotModule` shapes. Why: `validateManifest` and `validateModuleExport` are hand-rolled and miss edge cases. **Low-confidence** (needs design chat about Zod vs standard JSONSchema).

### `[MCP]` — MCP bridge agent

5. **Propagate MCP tool's own `inputSchema` fidelity (don't drop `required`).** Files: `src/modules/mcp-bridge.ts:60-80`. The current `mcp` wrapper assigns `mcpTool.inputSchema ?? { type: "object", properties: {} }` but never checks `required` / `additionalProperties`. Why: MCP tools lose their JSON-schema contract when bridged. **High-confidence.**
6. **Namespace collision when multiple MCP servers land on the same derived `moduleId`.** Files: `src/copilot/core.ts:555-569`. The regex produces identical IDs for `mcp:http://localhost:3000` and `mcp:http://localhost:3001`. Why: second load throws "already registered." Fix by appending `-<n>` on collision. **High-confidence.**
7. **MCP tools default to `headless: true` without verification.** Files: `src/modules/mcp-bridge.ts:64`. Why: MCP tools may prompt; marking them all headless breaks run-mode semantics. Fix by defaulting to `false` unless the MCP tool advertises `annotations.readOnlyHint` or similar. **Low-confidence** (needs MCP-spec review).

### `[TESTING]` — Testing SDK agent

8. **Extend `createMockToolContext` to cover all `ToolExecutionContext` fields.** Files: `src/testing/index.ts:80-91`. Missing: `print`, `datastore`, `workspace`, `events`, `toolModel`, `reportActivity`, `reportOutput`, `uiStore`, `seedTaskOutputs`. Why: tools that read these fields can't be unit-tested. **High-confidence.**
9. **Add `createMockEventScope()`.** Files: new helper in `src/testing/index.ts`. Why: `ctx.events.emit/on` usage is untested today. **High-confidence.**
10. **Add `assertToolResult(result, { ok, outputContains, dataShape })` helper.** Files: `src/testing/index.ts`. Why: the repeated `expect(result.ok).toBe(true); expect(result.output).toContain(...)` pattern (see `src/cli/create-module.ts:215-221`) should be a single call. **Low-confidence.**
11. **Expose the `validateModuleExport` shape check as a `expectModuleShape(mod)` test helper.** Files: `src/testing/index.ts`, consuming `src/modules/loader.ts:121`. Why: authors can assert their exported module will actually load. **High-confidence.**

### `[SCAFFOLD]` — Scaffolder agent

12. **Scaffolder should emit a stable `kuzushiSdkVersion` in the generated `module.manifest.json`.** Files: `src/cli/create-module.ts:80-97`. Why: once SDK-version lands, the scaffold has to set it. **High-confidence** (blocked on SCHEMA-1).
13. **Scaffolder should include a `peerDependencies` / `peerDependenciesMeta` block pinning `kuzushi >= <major>`.** Files: `src/cli/create-module.ts:99-126`. Currently uses `">=0.17.0"` which is pre-SDK-versioning. **High-confidence.**
14. **Generated `src/index.ts` should use `defineModule()` if it exists.** Files: `src/cli/create-module.ts:153-199`. Blocked on HOST-16. **Low-confidence.**

### `[DOCS]` — Docs agent

15. **Document the stable vs. unstable surface in `CLAUDE.md` §2 and in a new `docs/modules/sdk-reference.md`.** Files: `CLAUDE.md:76-108`, new `docs/modules/`. Enumerate frozen types (§2 of this report) and explicitly mark `uiStore/datastore/workspace/events` as unstable until the HOST-item cleanup lands. **High-confidence.**
16. **Add a "Migrating to SDK v1" section to `RELEASING.md`** covering the breaking renames from HOST-17/18. **High-confidence** (blocked on HOST items).

### `[HOST]` — host-core changes

17. **Extract narrow interfaces for `uiStore`, `datastore`, `workspace`, `events` into `src/modules/host-handles.ts` and update `ToolExecutionContext`.** Files: `src/modules/types.ts:161,179,185,192,338`. Why: the #1 dep-leak. This is a **breaking change** for `core-sast.ts` and the `@kuzushi/*` modules if they read internal `UIStore` / `WorkspaceManager` methods that aren't in the narrow interface. **High-confidence.**
18. **Enforce `tool.name.startsWith(module.id + ":")` in `validateModuleExport`.** Files: `src/modules/loader.ts:135-146`. Why: prevent shadow-registration. **Breaking** for any existing module that ships mis-prefixed tools — audit before landing. **High-confidence.**
19. **Reject duplicate tool names within a single module.** Files: `src/modules/loader.ts:135-146`. **High-confidence.**
20. **Re-export `defineModule`, `defineTool`, `ModuleLoadError`, `ModuleEventScope`, `ToolOptionStore`, `WorkspaceHandle` from `kuzushi/modules`.** Files: `src/modules/index.ts:1-17`. **High-confidence.**
21. **Inject `ctx.host = { sdkVersion, capabilities }` in `CopilotCore.executeTool`.** Files: `src/copilot/core.ts:308-329`, `src/modules/types.ts:141-237`. Why: runtime capability detection. **High-confidence.**
22. **Make `parseModuleSpecifier` default resolve to an "auto" type that tries builtin then package.** Files: `src/modules/registry.ts:278-280`, `src/copilot/core.ts:219-236`. **Low-confidence** (changes the UX of `--load foo`).

## 7. Migration notes — if recommended fixes land

The following items are **breaking** for existing in-tree modules (`core-sast.ts` and the 11 other built-in modules under `src/modules/`) and for the `@kuzushi/*` and `kuzushi-augur` packages listed in `dependencies`:

- **HOST-17 (narrow interfaces)** — any module that casts `ctx.uiStore`, `ctx.workspace`, `ctx.datastore`, or `ctx.events` to the internal concrete class will stop compiling. Touches `src/modules/sast/shared.ts:279-630` extensively. Recommended: land the narrow interface first with `extends` relationships so concrete types still satisfy them, then deprecate the wide types.
- **HOST-18 (name prefix enforcement)** — grep `ModuleTool` literals across all core modules before shipping; failing CI will catch most.
- **SCHEMA-1 (`kuzushiSdkVersion`)** — additive; not breaking at load time if missing is treated as "unknown, warn."
- **SCHEMA-2 (`ModuleLoadError`)** — callers of the loader functions that `catch` on `Error.message` keep working; anyone checking `instanceof Error` also works. Only programmatic `code` consumers need to update.
- **MCP-7 (headless default)** — breaking for operators who depend on MCP tools being runnable via `kuzushi run`. Needs a release note.

### Proposed `RELEASING.md` entry text

```md
### v0.20.0 — Module SDK hardening

Breaking:
- `ToolExecutionContext.uiStore | datastore | workspace | events` now use
  narrow `HostUiHandle | ToolOptionStore | WorkspaceHandle | ModuleEventScope`
  interfaces. Code that relied on internal concrete-class methods must either
  cast explicitly or migrate to the narrow API.
- Tool names are now required to begin with `<module.id>:` at load time.
  Loader throws `ModuleLoadError{ code: "SHAPE_INVALID" }` on violation.
- MCP-bridged tools default to `headless: false`. Pass
  `--load 'mcp:<spec>' --mcp-trust-headless` to restore the previous behavior.

Additive:
- `module.manifest.json` gains `kuzushiSdkVersion` (semver string). Omitting
  it produces a warn; a future release will require it.
- New public exports from `kuzushi/modules`: `defineModule`,
  `defineTool`, `ModuleLoadError`, `ModuleEventScope`, `ToolOptionStore`,
  `WorkspaceHandle`.
- `ToolExecutionContext.host = { sdkVersion, capabilities }` is populated
  by `CopilotCore.executeTool`; modules can probe capabilities before use.

Tooling:
- `kuzushi create-module` now emits `kuzushiSdkVersion` in the manifest
  and uses `defineModule()` in `src/index.ts`.
- `kuzushi/testing` exports `createMockEventScope`, `expectModuleShape`,
  `assertToolResult` and covers every `ToolExecutionContext` field.
```
