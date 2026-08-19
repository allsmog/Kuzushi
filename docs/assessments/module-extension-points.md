# Module Extension-Point Assessment

Status: historical TypeScript SDK/domain assessment. The SDK and handles below
are not current product surfaces; current authors use the brokered KWP contract
in `docs/modules.md`. Any mention of deleted shell/TUI files is likewise not
current operator UI guidance; new interactive shell behavior belongs in
`crates/kuzushi-tui`.

Audit of the Kuzushi module SDK's extension surface from the perspective of a
third-party module author. The goal: identify gaps that block plausible
modules — i.e. concrete capabilities a competent author would reach for and
discover that the SDK doesn't currently expose without reaching into host
internals.

This document was produced from scratch — there is no prior assessment for
this scope. Companion: `docs/devex/06-module-sdk-assessment.md` (the broader
DevEx audit).

## 1. Current handle map

`ExecutionContext` is the single contract surface for module tools. Today it
exposes the following capabilities, all backed by narrow handles in
`src/modules/host-handles.ts`:

| Capability key       | Field on `ctx`        | Handle                      | Read | Write |
| -------------------- | --------------------- | --------------------------- | ---- | ----- |
| `workspace`          | `workspace`           | `WorkspaceHandle`           | yes  | hosts/services/notes only |
| `ui-store`           | `uiStore`             | `HostUiHandle`              | yes  | yes   |
| `datastore`          | `datastore`           | `ToolOptionStore`           | yes  | yes   |
| `print-sink`         | `print`               | `PrintSink`                 | -    | yes   |
| `module-events`      | `events`              | `ModuleEventScope`          | sub  | emit  |
| `tool-model`         | `toolModel`           | string                      | yes  | -     |
| `structured-output`  | (runtime feature)     | -                           | -    | -     |
| (always)             | `logger`              | `ToolLogger`                | -    | yes   |
| (always)             | `reportActivity`      | UX helper                   | -    | yes   |
| (always)             | `reportOutput`        | UX helper                   | -    | yes   |
| (always)             | `resolveOption`       | unified option resolver     | yes  | -     |
| (always)             | `reportAgentActivity` | sub-agent activity reporter | -    | yes   |
| (DAG only)           | `dag`                 | `DagContext`                | yes  | -     |

Lifecycle hooks on `CopilotModule`:

- `init(config, ctx)` — once at load. Sees only itself, plus the bus.
- `dispose()` — once at unload.
- Per-tool `init(moduleConfig)` — once at load, after module-level `init`.

DAG hooks: `dag.condition(upstream, config)` is the only pre-flight predicate;
`dag.dependsOn` is the only declarative ordering primitive. `upstreamOutputs`
is read-only in `DagContext`.

## 2. Top extension-point gaps (with blocking-module examples)

Each entry answers "what concrete module does this unlock?" with a real
example. Anti-recommendations live in §3.

### 2.1. Findings emit/attach via the workspace handle — HIGH CONFIDENCE

**Gap.** `WorkspaceVulnStore` exposes only `listForWorkspace(workspaceId)`.
A third-party scanner module cannot persist a finding via `ctx.workspace.vulns`
— the only writers are inside the workspace import path
(`src/workspace/io/import.ts`) and the host's `VulnStore.create(...)` is not
on the narrow handle. To record a finding, a module today has to either
(a) cast through `rawDb()` and write SQL, or (b) emit a non-standard bus
event the host has never agreed to consume.

**Blocking module.** `@thirdparty/eslint-security` — an ESLint plugin
adapter that wants to store each rule violation as a finding so it surfaces
in `/findings`, `/since <ref>`, and the alias map (F-NNNN). Today this
module would have to fork host internals; with `WorkspaceVulnStore.create`
on the handle it works in a dozen lines.

**Fix.** Extend `WorkspaceVulnStore` with `create(input)` returning the
created row as `unknown`. Concrete `VulnStore.create` is structurally
compatible. The shipped patch in this PR adds it.

### 2.2. Per-run artifact persistence handle — HIGH CONFIDENCE

**Gap.** Operators can version-control `.kuzushi/v3/runs/<runId>/...` (CLAUDE.md
documents this), and several built-ins (audit-worker, scan-worker,
context-persist) write to that tree. There is no typed handle that gives a
third-party module a sandboxed writer for `<runId>/<moduleId>/...`. The
options today are: hardcode `path.join(".kuzushi", "runs", runId, ...)` (which
duplicates host path conventions and breaks if Kuzushi ever moves the tree),
or skip persistence entirely.

**Blocking module.** `@thirdparty/sbom-export` — a DAG tool that emits a
`CycloneDX` SBOM per scan. It wants to drop `sbom.json` into the run dir so
the operator can `git commit .kuzushi/v3/runs/<runId>/sbom-export/sbom.json`
alongside `summary.json`. Without a handle it cannot guarantee the path
matches the host's convention.

**Fix.** Add `RunArtifactStore` to `host-handles.ts` with `write(name,
content)` and `path(name)` methods, scoped per `(runId, moduleId)`. Wire on
`ExecutionContext.runArtifacts`, populated when both `dag.runId` and
`tool.moduleId` are present. Capability key: `"run-artifacts"`. Shipped in
this PR.

### 2.3. Post-batch `ready(ctx)` lifecycle hook — HIGH CONFIDENCE

**Gap.** A module's `init` runs serially during `CopilotCore.init` — when
your module's `init` is called, peer modules may not yet be loaded.
`ModuleEventScope.on("module:loaded", ...)` only fires from then on, so
there's a race for "I want to subscribe to every loaded module's tool
events, including ones already loaded when I came up." This is the same
problem operators hit with shell sub-views: the fix in shell-land was
post-mount initialization. The module SDK has no equivalent.

**Blocking module.** `@thirdparty/cross-correlator` — a governance module
that fans out to every other module's `tool:after_run` events to compute
cross-module correlation scores. Today it has to retry-poll the registry
inside `init`, which is brittle; with `ready(ctx)` it just iterates
`ctx.peers` once.

**Fix.** Add an optional `ready?(ctx: ModuleContext & { peers: ReadonlyArray<{
id: string; displayName: string }> })` to `CopilotModule`. Called by
`CopilotCore.init` after every initial-batch module's `init` resolves, in
load order. Shipped in this PR.

### 2.4. DAG pre-/post-task observation — MEDIUM CONFIDENCE

**Gap.** A `DagTool` only sees its declared upstream outputs via
`dag.upstreamOutputs`. There is no equivalent of `tool:after_run` for DAG
nodes — a module that wants to react to *any* finding-producing task
completing has to either subscribe to the bus's per-stage events (which
crosses an internal boundary) or declare itself downstream of every
finding-producing task (which forces a redeployment every time a new
finding-producing module is added).

**Blocking module.** `@thirdparty/findings-mirror` — push every newly-stored
finding to a remote SIEM in near-real-time. Today this module would have
to be a fan-in DAG node depending on every scanner; it should be a passive
observer.

**Recommendation.** Defer until a second concrete module needs it. The
existing `ModuleEventScope` covers the most common case if the host
publishes a stable `findings:created` framework event from
`WorkspaceVulnStore.create`. We document this as a follow-up rather than
shipping a new DAG-side hook today.

### 2.5. Module-contributed shell views/verbs/keybinds — REJECTED

**Gap.** Modules cannot register a `ShellView` id, slash verb, or keybind
through the SDK. Adding a view today requires the Rust shell recipe in
CLAUDE.md: define view state, command specs, state transitions, view models,
Ratatui rendering, plain output, and focused tests under `crates/kuzushi-tui`.

**Why reject (for now).** No high-confidence concrete blocking module yet —
the existing per-module home renderer + `module-run` view + tools table
covers ≥ 80% of the cases that motivate authors to want a custom view. Custom
verbs would expand the operator command surface uncontrollably; the right
escape hatch today is "expose another tool with `headless: false`", which
already gives operators a way to invoke it from the focused-module prompt.
Revisit when a third-party module surfaces a real need that can't be met
by a tool plus the existing module home renderer.

### 2.6. MCP-bridged module surface gap — DOCUMENTED, LOW CONFIDENCE FOR ACTION

**Gap.** MCP modules don't carry `references`, `notes`, `rank`, or `examples`
because the MCP protocol doesn't advertise those fields. They also can't
participate in DAGs (no `dag` block), can't write findings, and can't
subscribe to `module-events`. This is a feature, not a bug — Kuzushi can't
trust an arbitrary MCP server to satisfy those contracts — but operators
should know.

**Fix.** None today. Document the asymmetry in `docs/modules.md` §15.
Already partially present.

### 2.7. `ToolLogger` is fire-and-forget — LOW CONFIDENCE

**Gap.** `ctx.logger?.warn(...)` produces no observable artifact a module
can later assert on, and there's no module-log panel yet. Tests can use
`createRecordingLogger`, but production logs vanish into the bus.

**Recommendation.** Defer. The shell's audit log captures structured
events; a dedicated module-log panel is a UX project, not an SDK gap.

### 2.8. `kuzushi/testing` parity for new handles — HIGH CONFIDENCE (scoped
to whatever is shipped)

Every new handle added to `host-handles.ts` must come with a recording mock
in `src/testing/mocks/` and a re-export in `src/testing/index.ts`. The
existing pattern (`createMockWorkspace`, `createMockUiStore`, etc.) is the
template. Shipped in this PR for the new handles.

## 3. Anti-recommendations

These are tempting but should NOT be added:

- **Generic "host class" escape hatch on `ExecutionContext`.** Every host
  class leak (`UIStore`, `WorkspaceManager`, `Datastore`) increases the
  surface area third-party modules pin against. The narrow-handle pattern
  is intentional and load-bearing.
- **Module-contributed slash verbs.** Operator command space is finite;
  every verb the SDK lets a module take is a verb the host cannot reclaim
  without a breaking release. Tools-as-verbs (already supported) is enough.
- **Mutable `dag.upstreamOutputs`.** A module mutating its peer's outputs
  silently breaks the DAG's "outputs are stable artifacts" invariant.
- **Allowing modules to register host-internal capability keys.** The
  capability set is open, but adding a key like `"workspace"` from a
  third-party module would let it lie about host services it doesn't actually
  provide. Capability keys should remain host-emitted.
- **Per-tool `beforeShutdown` hooks separate from `dispose`.** `dispose` is
  the contract; splitting it adds ordering ambiguity without a concrete
  blocking module.

## 4. What this PR ships

Implements §2.1, §2.2, §2.3, §2.8 from the recommendations above. See:

- `src/modules/host-handles.ts` — `WorkspaceVulnStore.create`,
  `RunArtifactStore`, capability keys.
- `src/modules/types.ts` — `CopilotModule.ready`, `ExecutionContext.runArtifacts`,
  `ModuleContext.peers`.
- `src/copilot/core.ts` — wires `runArtifacts` per call, calls `ready` after
  init batch.
- `src/modules/core-sast.ts` — exemplary uses of all three.
- `src/testing/mocks/run-artifacts.ts` + extended `workspace.ts` — recording
  mocks.
- `tests/modules/run-artifacts.test.ts`, `tests/modules/workspace-vulns.test.ts`,
  `tests/modules/ready-hook.test.ts`.
- `schemas/module.manifest.schema.json` — `kuzushiSdkVersion` minor bump.
- `docs/modules.md` — new sections under §7 and §10.

§2.4 (DAG observation), §2.5 (custom views), §2.6 (MCP parity), and §2.7
(logger panel) are explicitly deferred — they need a concrete second blocking
module before they earn a place on the contract surface.
