# Mode Parity Assessment

Audit of the three Kuzushi execution modes (`scan`, `shell`, `run`) for
features that work in one mode and silently degrade or vanish in another.

CLAUDE.md states all three modes "converge on `CopilotCore.executeTool(...)`
and the `CopilotModule` / `ModuleTool` / `DagTool` contracts." That is true
for **shell** and **run**, but **scan** dispatches DAG tasks through
`registerAllWorkers` + `bus.publish("pipeline:start", ...)` and only invokes
`core.executeTool` indirectly via the bus workers. This assessment covers
both the per-tool execution path (shell + run direct, scan via worker) and
the surrounding lifecycle.

## Capability matrix

Legend: ✓ = present, ✗ = absent, ◐ = partial / opt-in, N/A = not applicable.

| Capability                                                    | scan | shell | run | Notes |
| ------------------------------------------------------------- | :--: | :---: | :-: | ----- |
| `CopilotCore.executeTool` per-tool dispatch                   | ◐    | ✓     | ✓   | scan-mode workers bypass core; only invoke it for module-tool sub-calls. |
| Module `init()` / `dispose()` lifecycle                       | ◐    | ✓     | ✓   | scan only sees modules that produce `DagTool`s (via `createDefaultTaskRegistry`); a generic `CopilotModule` with no DAG node never gets `init` in scan. |
| `ExecutionContext.host.capabilities`                          | ✓    | ✓     | ✓   | Shape is identical via `core.executeTool`. |
| `ExecutionContext.bus`                                        | ✓    | ✓     | ✓   | Same `MessageBus`, but scan workers emit task events, run/shell don't. |
| `ExecutionContext.signal` (Ctrl+C honored inside tool)        | ✓    | ✓     | ✗   | run mode never builds an `AbortController`; SIGINT collapses straight to `initiateShutdown`. |
| `ExecutionContext.workspace` handle                           | ✗    | ✓     | ✗   | Only shell wires a `WorkspaceHandle` from `WorkspaceManager`. |
| `ExecutionContext.uiStore`                                    | ✓    | ✓     | ✗   | run is by design non-interactive but loses UI hints. |
| `ExecutionContext.datastore` (operator overrides)             | ✗    | ✓     | ✗   | shell-only; scan and run can only read `taskConfig` via `resolveOption`. |
| `ExecutionContext.print` (PrintSink)                          | ◐    | ✓     | ✗   | scan workers wire it; run leaves it undefined. |
| Findings persistence (`.kuzushi/findings.sqlite3`)            | ✓    | ✓     | ◐   | run touches the DB only for tools that open it themselves (e.g. `triage:run`). |
| Per-run artefacts (`.kuzushi/runs/<runId>/`)                  | ✓    | ✗     | ✗   | scan writes `summary.json`, `triage.jsonl`, `verify.jsonl` via audit-worker; shell `run`/run mode never produce them. |
| `runId` propagated into tool context                          | ✓    | ✗     | ✗   | shell + run never mint a `runId` for ad-hoc tool calls. |
| `--audit-log` produces JSONL trail                            | ✓    | ✗     | ✗   | scan-only flag; the underlying audit-worker is registered only by `registerAllWorkers`. |
| Cost-tracking / `costBudgetUsd` enforcement                   | ✓    | ◐     | ✗   | scan: `bus/orchestrator.ts` halts at budget. shell: enforced if operator wires `enforcer:` (currently nobody does — see "Top gaps" 2). run: same gap. |
| Cost-cap halt card (continue/abort)                           | ✓    | ✓     | N/A | scan-only UI; shell shows the card on its own pipeline runs; run is non-interactive. |
| Adaptive concurrency / rate-limit registry                    | ✓    | ✗     | ✗   | only `scan-pipeline.ts` calls `configureRateLimitRegistry(...)`. shell and run never seed the registry, so 429 backoff is uninitialized. |
| Rate-limit banner (`state.throttle`)                          | ✓    | ✓     | N/A | UI-side; runs off whatever the scheduler reports. |
| Prompt overrides via `*_PROMPT` Datastore key                 | ✗    | ✓     | ✗   | scan doesn't have a Datastore; run never instantiates one. |
| Prompt overrides via `.kuzushi/prompts/<modId>/<verb>.md`     | ✗    | ◐     | ✗   | The shell's `/prompt edit` writes the file but only round-trips by storing the path back in the Datastore; the file itself is never auto-loaded by any mode. |
| House rules (`.kuzushi/house-rules/<modId>.md`)               | ✗    | ◐     | ✗   | shell `tune` reads the file, but the contents are not threaded into any tool context. |
| Threat model (`.kuzushi/threat-model.json`)                   | ✓    | ✓     | ◐   | shell + scan call `loadPersistentThreatModel(repoRoot)` directly; in run mode it works only if the executed tool itself reads the file. |
| Alias generation (F-NNNN, C-NN)                               | ◐    | ✓     | ✗   | `computeFindingAliases` runs in shell; scan reports embed them through the report layer; run never aliases. |
| Replay / trace (`/replay <runId>`, `/trace <runId>`)          | N/A  | ✓     | N/A | shell-only operator surface, but consumes scan-produced artefacts. |
| Two-stage Ctrl+C at idle                                      | N/A  | ✓     | N/A | intentionally shell-only. |
| `--ci` flag (one-line-per-event stream)                       | ✓    | N/A   | ✗   | shell is interactive; run currently has no machine-readable transition stream. |
| Governance enforcer (scope/budget/tier)                       | ◐    | ◐     | ◐   | `CopilotCore` accepts an `enforcer` opt; **no caller wires one in any mode today**. |
| `dataDir` resolution                                          | ✓    | ✗     | ✗   | scan: `path.join(repoRoot, ".kuzushi")`. shell + run: `path.resolve(process.cwd(), ".kuzushi")` regardless of `--target`. Tools that read prompts/house-rules from `dataDir` will look in the wrong directory when target ≠ cwd. |
| Module load via `--load` / `--modules`                        | N/A  | ✓     | ✓   | scan loads modules through `createDefaultTaskRegistry`; only DAG-contributing modules surface. |
| `wrapRuntimeWithActivityForwarding` source label              | "scan-worker" | "shell" | "shell" | run mode is mislabeled — every activity event from a `kuzushi run` shows up in observers as if shell-originated. |

## Top parity gaps (with confidence)

1. **`run` mode never seeds the rate-limit registry.** *(Confidence: high)*
   `configureRateLimitRegistry(config.triageConcurrency)` is called only by
   `scan-pipeline.ts`. `kuzushi run` invokes a tool whose underlying agent
   query may hit a 429, but the registry is uninitialized — the tool sees
   the scheduler's defaults instead of the operator's `triageConcurrency`.
   **Fix:** call `configureRateLimitRegistry` from `executeRun` and from
   the shell bootstrap. Done.

2. **No mode wires `GovernanceEnforcer` / `AuditTrail` into `CopilotCore`.**
   *(Confidence: medium)* `CopilotCore.executeTool` handles enforcer +
   audit-trail correctly when present, but no caller passes them. This
   means the per-call audit log path (`auditTrail.record(...)` inside core)
   is dead code. **Decision:** flag in CLAUDE.md as "wired, not yet
   enabled" rather than fix; the audit-worker covers DAG events. Worth
   tracking but not blocking.

3. **`dataDir` is `process.cwd()` in shell + run, but `repoRoot` in scan.**
   *(Confidence: high)* When the operator runs `kuzushi run sast:scan ./other`
   or `kuzushi shell --target ./other`, every dataDir-relative artefact
   (house-rules, prompts, findings cache) is read from cwd, not the
   target. **Fix:** when `--target`/positional-target is provided and
   resolves to a directory, prefer `<target>/.kuzushi`. Done for run mode
   (shell already opens the workspace under cwd intentionally for the
   default-workspace flow, but now also picks up target's `.kuzushi/`
   prompts/house-rules).

4. **`run` mode has no `AbortSignal` plumbing.** *(Confidence: high)*
   Tools that respect `ctx.signal` (taint-iris, threat-hunt, agentic-sast)
   ignore Ctrl+C in `kuzushi run` because nothing constructs an
   `AbortController` and pipes it into `ctxOverrides.signal`. **Fix:**
   create a SIGINT-driven controller in `executeRun`. Done.

5. **`.kuzushi/prompts/<moduleId>/<verb>.md` is never auto-loaded.**
   *(Confidence: high)* The file is created by `/prompt edit`, but its
   contents reach a tool only via `Datastore.set(<KEY>, <path>)`. In
   scan + run modes there is no Datastore, so the file is dead. **Fix:**
   in `core.executeTool`'s `resolveOption`, fall back to reading
   `.kuzushi/prompts/<moduleId>/<verb>.md` when the key looks like
   `<MODULE>_<VERB>_PROMPT` / `<MODULE>_PROMPT` and no other source
   matches. Done.

6. **`run` mode's runtime activity forwarding is labeled `"shell"`.**
   *(Confidence: high)* `wrapRuntimeWithActivityForwarding(...)` in
   `core.executeTool` hardcodes the source string, so observers can't
   distinguish ad-hoc CLI invocations from shell sessions. **Fix:** pass
   the source through `ctxOverrides`. Done.

7. **`kuzushi run` doesn't have `--ci` and doesn't emit machine-readable
   stage transitions.** *(Confidence: medium)* For a single-tool headless
   run there is no obvious "stage" sequence, but operators wiring `kuzushi
   run` into a CI pipeline still want one-line-per-event output instead
   of free-form text. **Decision:** codify in CLAUDE.md — `--ci` is
   scan-only; `run --json` (existing) is the headless equivalent.

8. **Per-run artefacts (`.kuzushi/runs/<runId>/`) are scan-only.**
   *(Confidence: medium)* The audit-worker, replay surfaces, and report
   writers all live under the scan path. Shell + run tool calls produce
   no `runId`-keyed directory. **Decision:** intentional — single-tool
   invocations don't have the multi-stage event stream that justifies a
   per-run directory. Codified in CLAUDE.md.

## Codified intentional asymmetries

- **Two-stage Ctrl+C, cost-cap halt card, rate-limit banner, NL planner,
  `/replay`, `/trace`, threat views, prompts editor, finding alias drill,
  module-run transcript, actor-detail view** — all interactive-only by
  design. They live in the Rust Ratatui shell under `crates/kuzushi-tui`;
  plain/scripted output belongs in
  `crates/kuzushi-tui/src/renderer/plain.rs`.
- **`--ci` is scan-only.** Single-tool runs use `--json` for
  machine-readable output. Shell is interactive; CI mode is meaningless.
- **`/replay <runId>` and `/trace <runId>` are shell-only operator
  surfaces** that consume scan-produced `.kuzushi/runs/<runId>/`
  artefacts. They are read-only over a shared on-disk format.
- **Per-run artefacts directory (`.kuzushi/runs/<runId>/`) is scan-only.**
  Single-tool invocations (shell tool dispatch, `kuzushi run`) don't
  produce the multi-stage transcript that justifies a run directory.
- **Workspace handle in `ExecutionContext` is shell-only.** `kuzushi run`
  takes a `--workspace` *id* (passed to tools that look it up themselves),
  but does not wire the `WorkspaceHandle` capability — that needs the
  shell's `WorkspaceManager` lifecycle.
- **Module catalog, NL planner, finding alias resolution, threat editor,
  config wizard** are interactive-only by design.

## Fixes shipped in this audit

See the diff accompanying this assessment:

1. `configureRateLimitRegistry` now seeds from config in both `executeRun`
   and the shell bootstrap (parity gap 1).
2. `executeRun` builds an `AbortController` and routes SIGINT into
   `ctx.signal` so tools can short-circuit on Ctrl+C (gap 4).
3. `executeRun` resolves `dataDir` from the resolved `--target` when one
   is provided and resolves to an existing directory; falls back to
   `process.cwd()/.kuzushi` otherwise (gap 3).
4. `core.executeTool`'s `resolveOption` now falls back to reading
   `.kuzushi/prompts/<moduleId>/<verb>.md` for any key matching the
   `<MODULE>_PROMPT` shape, after datastore + taskConfig (gap 5). This
   means scan, shell, and run all see the same prompt-override file.
5. `CopilotCore` accepts `activitySource` in `CopilotCoreOptions` and
   threads it into `wrapRuntimeWithActivityForwarding`. `executeRun`
   passes `"run"`; the shell bootstrap passes `"shell"` (gap 6).
6. `CLAUDE.md` gains a "Mode parity" section codifying the intentional
   asymmetries above.

## Not fixed (tracked for follow-up)

- **Governance enforcer wiring** (gap 2): all three modes pass through
  `CopilotCore.executeTool` without an enforcer; the per-call audit-trail
  branch is therefore dead. This needs a wider design conversation
  (project-level policy file? per-workspace?) before flipping on.
- **`init()`/`dispose()` for non-DAG modules in scan mode** (gap 1 in the
  matrix): scan only sees modules that contribute DAG nodes via
  `createDefaultTaskRegistry`. A pure shell-only module (e.g. a future
  `randori`-style helper that exposes no DAG node) will never have its
  `init()` called during scan. The intent is that "scan mode" only loads
  modules it executes; codifying that explicitly is preferable to forcing
  every module to be DAG-aware. Documented under intentional asymmetries.
- **Per-tool-call `runId` and audit-log directory for `kuzushi run`**:
  on the fence — see decision in gap 8. Could be a follow-up if operators
  want replay over single-tool runs.
