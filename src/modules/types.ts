/**
 * Core type definitions for the Kuzushi module system.
 *
 * A CopilotModule is the unit of capability composition — each module
 * exposes tools (for interactive/headless invocation) and optionally
 * pipeline tasks (for DAG execution), knowledge modules, and bus events.
 *
 * Modules are loaded by the ModuleRegistry and dispatched by CopilotCore.
 * They work identically across all three execution modes (pipeline, shell, run).
 */

import type Database from "better-sqlite3";
import type { AgentRuntime } from "../agent-runtime/types.js";
import type { TaskOutputKind } from "../agents/types.js";
import type { MessageBus } from "../bus/types.js";
import type { PrintSink } from "../copilot/print.js";
import type { KnowledgeModule } from "../knowledge/types.js";
import type { ToolPolicy } from "../prompts/tool-policy.js";
import type { Finding, TriageAgentConfig } from "../scanners/types.js";
import type { KuzushiConfig } from "../types.js";
import type {
  HostInfo,
  HostUiHandle,
  ModuleEventScope,
  ToolLogger,
  ToolOptionStore,
  WorkspaceHandle,
} from "./host-handles.js";
import type { ModuleReference } from "./reference.js";
import type { JSONSchema } from "./schema.js";

export type {
  HostCapability,
  HostInfo,
  HostUiHandle,
  ModuleEventHandler,
  ModuleEventPayload,
  ModuleEventScope,
  ToolLogger,
  ToolOptionStore,
  UiStatePatch,
  WorkspaceHandle,
  WorkspaceHostStore,
  WorkspaceNoteStore,
  WorkspaceServiceStore,
  WorkspaceVulnStore,
} from "./host-handles.js";
export type { ModuleReference } from "./reference.js";
export type { JSONSchema } from "./schema.js";

// ---------------------------------------------------------------------------
// Module categories
// ---------------------------------------------------------------------------

/** High-level classification for module capabilities. */
export type ModuleCategory = "offense" | "defense" | "governance" | "intel";

// ---------------------------------------------------------------------------
// Module ranking + provenance metadata (msfconsole-inspired)
// ---------------------------------------------------------------------------

/**
 * Reliability/quality tier. Mirrors Metasploit's Rank system so operators have
 * a one-word summary of what to expect. Higher = more reliable/accurate.
 *
 *  - manual    : requires human driving; not safe to automate
 *  - low       : works rarely or only under narrow conditions
 *  - normal    : generic default; no special claims
 *  - good      : reliable in typical conditions
 *  - great     : reliable across platforms/versions
 *  - excellent : production-grade; very high signal
 */
export type ModuleRank = "manual" | "low" | "normal" | "good" | "great" | "excellent";

/** Numeric ordering matching msf::RankingName. */
export const RANK_VALUE: Record<ModuleRank, number> = {
  manual: 0,
  low: 100,
  normal: 300,
  good: 400,
  great: 500,
  excellent: 600,
};

/** Qualitative notes about runtime behavior (msf::Notes). */
export interface ModuleNotes {
  /** stable | crash-safe | crash-service-down — how stable at runtime. */
  stability?: string[];
  /** reliable | unreliable-session | first-attempt — session/tool success profile. */
  reliability?: string[];
  /** artifacts-on-disk | ioc-in-logs | screen-effects — observable side effects. */
  sideEffects?: string[];
}

// ---------------------------------------------------------------------------
// Module dependencies
// ---------------------------------------------------------------------------

/**
 * A declared prerequisite for running a module. Checked in the shell's `run`
 * command before the module's tool is invoked; a missing requirement produces
 * a helpful error instead of garbage output from an unseeded downstream stage.
 *
 *  - snapshot: a field on the active ShellState.contextSnapshot must be
 *    present. Used when sub-module A consumes sub-module B's in-memory
 *    output (e.g. threat-hunt needs context.appModel + randori.threatModel).
 *  - findings: the workspace DB must contain at least `minCount` findings.
 *    Used by triage/verify/patch which operate on previously stored findings
 *    regardless of which scanner produced them.
 */
export type CopilotModuleRequirement =
  | {
      kind: "snapshot";
      /** Upstream module id (for the error hint: `use <moduleId>; run`). */
      moduleId: string;
      /** ShellState.contextSnapshot field that must be truthy. */
      field: "repoContext" | "fileIndex" | "appModel" | "threatModel" | "scenarios" | "modules";
    }
  | {
      kind: "findings";
      /** Minimum number of findings required (default 1). */
      minCount?: number;
    }
  | {
      /**
       * Hosts exist in the active workspace (e.g. blackbox modules that probe
       * previously-discovered services). Used by offense tooling that runs
       * after `recon`.
       */
      kind: "hosts";
      minCount?: number;
    }
  | {
      /**
       * A live session of the given kind must be registered with the
       * SessionManager (e.g. verify modules that exploit via an open shell).
       * Omit `sessionKind` to accept any live session.
       */
      kind: "session";
      sessionKind?: string;
    }
  | {
      /**
       * An environment variable must be set (e.g. SHODAN_KEY for recon feeds,
       * NVD_KEY for CVE enrichment). Checked against process.env.
       */
      kind: "env";
      name: string;
    };

// ---------------------------------------------------------------------------
// DAG-aware tool types (module-forward merge of AgentTask into ModuleTool)
// ---------------------------------------------------------------------------

/**
 * Re-export of `TaskOutputKind` from `src/agents/types.ts`. During the
 * module-forward merge both names co-exist; once `AgentTask` is demoted to an
 * internal adapter shape (Step 4 of the reconciliation plan) the canonical
 * name becomes `OutputKind` on the module side. Keeping these as the same
 * underlying type today means the bridge is a no-op cast rather than a
 * structural translation.
 */
export type OutputKind = TaskOutputKind;

/**
 * Kinds of per-agent activity a DagTool (or ModuleTool that fans out sub-
 * agents) can emit. Mirrors the shapes used by triage / verification /
 * poc-harness / dynamic-analysis / threat-hunt today; unifying them here is
 * step 1 toward the single `TaskAgentActivityEvent` bus envelope.
 */
export type AgentActivityKind = "tool-start" | "tool-progress" | "tool-complete" | "reasoning";

/** Optional payload attached to a `reportAgentActivity` call. */
export interface AgentActivityMeta {
  toolName?: string;
  toolInput?: Record<string, unknown>;
  summary?: string;
  elapsedSeconds?: number;
  index?: number;
  total?: number;
  /** Terminal signal — tells the UI to drop this fingerprint's row. */
  done?: boolean;
}

/**
 * Pipeline-only fields populated on `ExecutionContext.dag` when a tool is
 * being invoked as a DAG node (i.e. by the scan orchestrator). Shell-mode
 * and `kuzushi run` invocations leave `ctx.dag` undefined. Tools that need
 * DAG state should assert via a helper (`requireDag(ctx)`) rather than
 * speculatively reading `ctx.dag!.upstreamOutputs`.
 */
export interface DagContext {
  runId: string;
  /** Effective scan scope (same semantics as TaskContext.workRoot). */
  workRoot?: string;
  /** Git toplevel when the operator targeted a subdirectory of a repo. */
  repoRoot: string;
  scanPath?: string;
  gitRoot?: string;
  repoName: string;
  /** Optional findings DB for regression detection + historical lookups. */
  db?: Database.Database;
  /** Outputs from completed dependency nodes, keyed by qualified tool name. */
  upstreamOutputs: ReadonlyMap<string, unknown>;
}

// ---------------------------------------------------------------------------
// Module tool types
// ---------------------------------------------------------------------------

/** Result returned by a tool execution. */
export interface ToolResult {
  /** Whether the tool executed successfully. */
  ok: boolean;
  /** Human-readable output (rendered in shell, included in JSON for run mode). */
  output: string;
  /** Optional structured data (machine-readable, for downstream consumption). */
  data?: unknown;
  /** Optional cost in USD for this tool invocation. */
  costUsd?: number;
}

/** Context provided to every tool execution. */
export interface ExecutionContext {
  /** Active workspace ID, if any. */
  workspaceId?: string;
  /** Current target (repo path, host, etc.). */
  target?: string;
  /** The project/scan root directory. */
  cwd: string;
  /** Agent runtime for LLM queries. */
  runtime: AgentRuntime;
  /** Message bus for event coordination. */
  bus: MessageBus;
  /** Full config for reading module-specific settings. */
  config: KuzushiConfig;
  /** Abort signal for cancellation. */
  signal?: AbortSignal;
  /**
   * UIStore for Ink rendering. When provided, tools that run pipelines
   * should pass this through so the Ink UI renders progress natively
   * (PipelineIndicator, StatusFooter, etc.) instead of capturing stdout.
   *
   * Typed as the narrow `HostUiHandle`; the concrete host `UIStore` is a
   * structural superset, so passing it here is a safe upcast.
   */
  uiStore?: HostUiHandle;
  /**
   * Pre-computed task outputs to inject into a pipeline run, keyed by task ID.
   * Avoids re-running context tasks when the shell already has a ContextSnapshot.
   */
  seedTaskOutputs?: Map<string, unknown>;
  /**
   * msfconsole-style print helpers. Tools should prefer `ctx.print.status(...)`
   * / `ctx.print.good(...)` / `ctx.print.error(...)` / `ctx.print.warn(...)`
   * over direct console.log so output is consistently tagged and auditable.
   * May be undefined when a tool is invoked outside a shell/run driver.
   */
  print?: PrintSink;
  /**
   * Active datastore for resolving operator-set options (e.g. TRIAGE_PROMPT,
   * VERIFY_PROMPT). Tools that respect prompt overrides read here first and
   * fall back to their compiled default. Optional — undefined outside shell.
   *
   * Typed as the narrow `ToolOptionStore`; the concrete host `Datastore`
   * is a structural superset.
   */
  datastore?: ToolOptionStore;
  /**
   * WorkspaceManager for tools that read/write engagement state (hosts,
   * services, vulns, loot, creds, notes, sessions). Optional — undefined
   * when running outside a workspace (e.g. one-shot `kuzushi run`).
   *
   * Typed as the narrow `WorkspaceHandle`; the concrete host
   * `WorkspaceManager` is a structural superset.
   */
  workspace?: WorkspaceHandle;
  /**
   * Module-scoped pub/sub handle (framework events). Subscriptions made
   * through this scope are auto-torn-down when the module is unloaded.
   * Optional — omitted outside the shell/run driver (e.g. during tests
   * that exercise a tool directly).
   */
  events?: ModuleEventScope;
  /**
   * Optional per-tool model override. When the operator runs
   * `setg TRIAGE_MODEL haiku`, the shell resolves that to this field
   * before calling `tool.execute`. Tools that honor the override read
   * `ctx.toolModel ?? ctx.config.model`.
   */
  toolModel?: string;
  /**
   * Report a sub-step of the currently running tool to the shell's progress
   * rail. Publishes a `task:activity` bus event under the hood, which the
   * Ink shell turns into a rolling "↳ <description>" line beneath the
   * spinner. Best-effort — swallow publish errors, never throw. Optional
   * because some tool-invocation paths (e.g. unit tests) don't wire a bus.
   *
   * Example:
   *
   *   ctx.reportActivity?.("scanning deps/package.json");
   *   ctx.reportActivity?.("analyzing lodash@4.17.11", { step: 3, total: 42 });
   */
  reportActivity?: (
    description: string,
    meta?: { phase?: string; step?: number; total?: number },
  ) => void;
  /**
   * Forward a raw subprocess output line (stdout/stderr, Bash-command preview,
   * sub-agent tool-use header) into the running tool-call's `⎿` live tail.
   * Distinct from `reportActivity` in two ways:
   *   - **No scrollback entry.** The line is ephemeral — it appears in the
   *     live tail until the tool resolves, then disappears. Scrollback isn't
   *     polluted with potentially-noisy stdout.
   *   - **Larger tail buffer.** Output lines are stored up to 5 deep (vs 3
   *     for activities) so operators can see a few lines of context when a
   *     subprocess is streaming quickly.
   *
   * Use for: subprocess stdout preview, sub-agent tool-use streaming, nmap
   * per-host callbacks. Do NOT use for structured phase labels — those go
   * through `reportActivity`.
   *
   * Example:
   *
   *   ctx.reportOutput?.("npm install: added 142 packages in 3.4s");
   *   ctx.reportOutput?.("Read(src/utils/format.ts)");
   */
  reportOutput?: (line: string) => void;
  /**
   * Host-side capability probe + SDK version. Populated by
   * `CopilotCore.executeTool`; undefined in test-rig `createMockToolContext`
   * calls that don't wire a host. Tools should feature-probe with
   * `ctx.host?.capabilities.has("workspace")` before depending on a feature.
   */
  host?: HostInfo;
  /**
   * Optional structured logger. When the host wires one (the shell emits
   * to the MessageBus), module authors can call `ctx.logger?.warn(...)`
   * for machine-readable diagnostics. Distinct from `ctx.print` which is
   * human-facing operator output.
   */
  logger?: ToolLogger;
  /**
   * Pipeline-only state populated when the orchestrator invokes a `DagTool`
   * as part of a scan run. Undefined in shell + run + direct-test paths.
   * DagTool authors narrow via a helper (`requireDag(ctx)`) — never assert
   * `ctx.dag!` in business logic.
   */
  dag?: DagContext;
  /**
   * Unified operator-option resolver. Falls back through:
   *   1. `ctx.datastore.get(key)`  — per-session `set` / global `setg`
   *   2. `ctx.config.taskConfig[<moduleId>][<key>]` — persisted overrides
   *   3. `ctx.config.taskConfig[<moduleId>][<lowercased-key>]`
   * Returns `undefined` on miss. Replaces the duplicated "read
   * `THREAT_HUNT_PROMPT` from the module, `promptOverride` from the task"
   * pattern that exists across every task-wrapping module today.
   *
   * Optional because some test paths don't populate the host fallback
   * chain; production code always has one.
   */
  resolveOption?<T = string>(key: string): T | undefined;
  /**
   * Report per-sub-agent activity to the bus as a `${moduleId}:agent-activity`
   * event (formally typed by `TaskAgentActivityEvent`). The orchestrator and
   * report-worker subscribe to the template-literal pattern so every module
   * that fans out sub-agents (threat-hunt, verify, poc-harness, triage, …)
   * gets identical UI plumbing for free.
   *
   * `fingerprint` is a stable per-row id (e.g. an actor name for threat-hunt,
   * a finding id for verify). `kind: "tool-complete"` with `meta.done: true`
   * tells the UI to drop the row from its active-agents map.
   */
  reportAgentActivity?(
    fingerprint: string,
    kind: AgentActivityKind,
    meta?: AgentActivityMeta,
  ): void;
}

/**
 * A tool exposed by a module — callable from shell mode (via LLM tool dispatch),
 * run mode (direct headless invocation), or pipeline mode (if wrapped as a task).
 */
export interface ModuleTool {
  /** Fully qualified name: "module:action" (e.g. "blackbox:recon"). */
  readonly name: string;
  /** Human-readable description — the LLM reads this to decide when to invoke. */
  readonly description: string;
  /** JSON Schema for the tool's input parameters. */
  readonly inputSchema: JSONSchema;
  /**
   * Whether this tool can run without interactive confirmation.
   * Tools marked headless: true work in all three modes.
   * Tools marked headless: false require shell mode (approval gate in run/pipeline modes).
   */
  readonly headless: boolean;
  /**
   * Optional reliability tier — defaults to the module's rank if unset.
   * Used by `search rank:...` and `info` output.
   */
  readonly rank?: ModuleRank;
  /** Optional external references specific to this tool. */
  readonly references?: ReadonlyArray<ModuleReference>;
  /** Optional behavioral notes specific to this tool. */
  readonly notes?: ModuleNotes;
  // --- Optional display hooks (shell rendering) ---
  /**
   * Human-friendly label used in the shell's `⏺ <name>(...)` header instead
   * of the raw `module:action` name. Falls back to `name` when unset.
   * Example: `"Scan"` for `sast:scan`, `"Read"` for a `fs:read` tool.
   */
  readonly displayName?: string;
  /**
   * Custom renderer for the `(args)` portion of the `⏺` header. Return `null`
   * / `undefined` to fall back to the generic `summarizeInput()` extractor
   * (primary-field + 40-char clamp). Return `""` to suppress the hint entirely.
   * Example: Bash shows truncated command; Read shows the display path.
   */
  formatInput?(input: unknown): string | null | undefined;
  /**
   * Custom renderer for the per-tool result summary line (`⎿  <output>`) shown
   * under the `⏺` header on completion. Return `null` / `undefined` to fall
   * back to the generic `✓ done in Xs` line. Example: Read → `"Read 559 lines"`,
   * Glob → `"Matched 12 files"`, Bash → first stdout line truncated.
   */
  renderResult?(result: ToolResult): string | null | undefined;
  /**
   * When true, hides this tool from `search`, the LLM tool-dispatch list,
   * and the `/use <module>` overview. Used for DAG-internal nodes that exist
   * purely to produce upstream outputs for other tools (e.g. `context:gather`,
   * individual detection sub-tasks on the `agentic-sast` module). Hidden
   * tools still participate in the scan DAG and can be invoked programmatically.
   */
  readonly hidden?: boolean;
  /**
   * Optional one-time configuration hook — receives the per-module config
   * slice at registry load time. Used by scanner-plugin tools (semgrep,
   * codeql) to resolve rule paths from `moduleConfig` before any `execute`
   * call. Distinct from `CopilotModule.init` which runs at the module level;
   * this runs per-tool so tool-specific setup state stays colocated with
   * the tool definition.
   */
  init?(moduleConfig: Record<string, unknown>): Promise<void>;
  /** Execute the tool with validated input. */
  execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult>;
}

// ---------------------------------------------------------------------------
// DagTool — a ModuleTool that also participates in the scan DAG
// ---------------------------------------------------------------------------

/**
 * Pipeline-only spec for a `DagTool`. Mirrors the fields formerly declared on
 * `AgentTask` (dependsOn / outputKind / condition / promptMode / toolPolicy /
 * triageAgentConfig) so the bridge at `src/modules/dag-bridge.ts` can adapt
 * a DagTool into an AgentTask for the orchestrator's existing TaskRegistry
 * plumbing.
 *
 * All string references in `dependsOn` are **qualified tool names**
 * (`"threat-model-randori:build"`), not bare task ids. The bridge rewrites
 * these back to bare ids when populating the TaskRegistry during migration.
 */
export interface DagToolSpec {
  outputKind: OutputKind;
  dependsOn: ReadonlyArray<string>;
  condition?: (upstream: ReadonlyMap<string, unknown>, config: KuzushiConfig) => boolean;
  promptMode?: "full" | "minimal" | "none";
  toolPolicy?: ToolPolicy;
  triageAgentConfig?: (finding: Finding, repoName: string) => TriageAgentConfig;
  /**
   * Additional task ids to include in the task-filter when the DagTool is
   * invoked via shell / `kuzushi run`. The orchestrator's pinned-task mode
   * disables automatic dependency resolution, so multi-task chains
   * (e.g. `taint-iris` needs `taint-cwe-select` to run first) must opt
   * upstream nodes back in here.
   *
   * Ignored during normal scan-mode dispatch where full-DAG execution
   * resolves `dependsOn` automatically.
   */
  chainBefore?: ReadonlyArray<string>;
}

/**
 * A `DagTool` is a `ModuleTool` that also declares DAG-node semantics.
 * Author via `defineDagTool<"module-id">({...})` — the template-literal
 * `name` type enforces the module-id prefix at compile time.
 *
 * When the orchestrator invokes the tool as part of a scan run, it populates
 * `ctx.dag` with `upstreamOutputs` and scope paths. Shell / run-mode
 * invocations leave `ctx.dag` undefined; tools that need DAG state should
 * guard with a `requireDag(ctx)` helper so the missing-context error is
 * explicit rather than a `.upstreamOutputs` on undefined.
 *
 * DagTools use a separate `run()` method (returning the typed output) rather
 * than `execute()` (returning `ToolResult`). The bridge wraps `run` into the
 * `execute` contract for shell/run-mode invocations, converting the output
 * via the module's `outputKind` (e.g. `Finding[]` → `ToolResult.data`).
 */
export interface DagTool<Id extends string = string, TI = unknown, TO = unknown>
  extends ModuleTool {
  readonly name: `${Id}:${string}`;
  readonly dag: DagToolSpec;
  run(input: TI, ctx: ExecutionContext): Promise<TO>;
}

/**
 * Structural guard — returns true when a `ModuleTool` carries a `dag` spec.
 * Used by `ModuleRegistry.loadModule` to auto-register DagTools into the
 * shared TaskRegistry, and by the shell/search UI to distinguish "DAG
 * participant" from "interactive-only" tools.
 */
export function isDagTool(tool: ModuleTool): tool is DagTool {
  return (
    (tool as Partial<DagTool>).dag !== undefined &&
    typeof (tool as Partial<DagTool>).run === "function"
  );
}

/**
 * Runtime guard that narrows `ctx.dag` to `DagContext`. Throws a descriptive
 * error when called outside a DAG execution (e.g. from shell mode). DagTool
 * authors call this at the top of `run()` to pull `upstreamOutputs`, `runId`,
 * and scope paths without proliferating `ctx.dag!` assertions.
 */
export function requireDag(ctx: ExecutionContext): DagContext {
  if (!ctx.dag) {
    throw new Error(
      "DagTool.run called without ExecutionContext.dag populated — this tool must be invoked via the scan orchestrator, not directly from shell/run mode.",
    );
  }
  return ctx.dag;
}

// ---------------------------------------------------------------------------
// Module manifest (for external/npm modules)
// ---------------------------------------------------------------------------

/** Requirements that must be satisfied before a module can load. */
export interface ModuleRequirements {
  /** Environment variables that must be set. */
  env?: string[];
  /** CLI binaries that must exist on PATH. */
  bins?: string[];
  /** Minimum Node.js version (e.g. ">=22"). */
  nodeVersion?: string;
}

/** Declarative manifest for a module — lives in module.manifest.json. */
export interface ModuleManifest {
  id: string;
  displayName: string;
  version: string;
  description: string;
  category: ModuleCategory;
  /** Entry point relative to the manifest file. */
  entry: string;
  requires?: ModuleRequirements;
  /** Per-module configuration schema. */
  configSchema?: JSONSchema;
  author?: string;
  license?: string;
  /**
   * The `kuzushi` SDK version the module was authored against. Used by the
   * loader to warn on host-vs-module major-version drift. Accepts a plain
   * semver ("0.19.1") or a constraint expression (">=0.19", "^1.0.0").
   * Optional for backward compatibility with pre-SDK-versioning manifests;
   * a warning is emitted when omitted.
   */
  kuzushiSdkVersion?: string;
}

// ---------------------------------------------------------------------------
// Module context (provided during init)
// ---------------------------------------------------------------------------

/** Context provided to a module during initialization. */
export interface ModuleContext {
  /** Agent runtime for LLM queries. */
  runtime: AgentRuntime;
  /** Message bus for event pub/sub. */
  bus: MessageBus;
  /** Full Kuzushi config. */
  config: KuzushiConfig;
  /** The .kuzushi data directory (for module-specific persistence). */
  dataDir: string;
  /**
   * Module-scoped framework event handle. Subscriptions created here are
   * auto-disposed on `dispose()`. Optional for backward compatibility.
   */
  events?: ModuleEventScope;
}

// ---------------------------------------------------------------------------
// CopilotModule — the first-class capability unit
// ---------------------------------------------------------------------------

/**
 * A CopilotModule is a pluggable capability package.
 *
 * Each module exposes:
 * - **tools**: callable from shell (NL dispatch), run mode (headless), or as agent tools
 * - **tasks**: AgentTasks for DAG pipeline execution (optional)
 * - **knowledge**: domain-specific vuln knowledge for triage/detection (optional)
 * - **events**: bus events this module produces/consumes (optional)
 *
 * Modules are loaded from:
 * - Built-in (e.g. the core SAST module)
 * - npm packages (e.g. @kuzushi/blackbox)
 * - Local directories (file:// specifiers)
 * - MCP servers (tools auto-wrapped as ModuleTools)
 */
export interface CopilotModule {
  /** Unique module identifier (e.g. "sast", "blackbox", "honeypot"). */
  readonly id: string;
  /** Human-readable name shown in UI. */
  readonly displayName: string;
  /** Module category for grouping/filtering. */
  readonly category: ModuleCategory;
  /** Semver version string. */
  readonly version: string;
  /** Short description of what the module does. */
  readonly description: string;

  /**
   * Reliability tier — inherited by tools that don't override `rank`.
   * Defaults to "normal" when absent.
   */
  readonly rank?: ModuleRank;
  /** Authors (strings or "Name <email>"). */
  readonly authors?: ReadonlyArray<string>;
  /** External references — CVEs, ATT&CK techniques, CWEs, relevant URLs. */
  readonly references?: ReadonlyArray<ModuleReference>;
  /** Disclosure date (ISO YYYY-MM-DD) — relevant for n-day/CVE-tied modules. */
  readonly disclosureDate?: string;
  /** Stability/reliability/side-effect notes. */
  readonly notes?: ModuleNotes;

  /**
   * When true, hides the module from the catalog listing, `/modules` table,
   * and module-picker UI. Tools on hidden modules are still loaded and
   * participate in the scan DAG — this flag just affects user-facing
   * discoverability. Used by orchestrator-internal modules like `pipeline`
   * whose DagTools exist purely to produce upstream outputs for visible
   * modules.
   */
  readonly hidden?: boolean;

  /** Tools exposed by this module. */
  readonly tools: ReadonlyArray<ModuleTool>;

  /**
   * Canonical usage examples — rendered verbatim by `examples <moduleId>`.
   * Each entry is a short multi-line snippet; keep them copy-pasteable into
   * the shell. Example: "use semgrep\nset TARGET ./\nrun".
   */
  readonly examples?: ReadonlyArray<string>;

  /**
   * Upstream artifacts this module needs before `run` can meaningfully execute.
   * Checked by the shell's ModuleDispatcher against the active ShellState + DB.
   * Missing requirements produce a helpful "run X first" error. Optional —
   * modules with no deps (semgrep, codeql, context) omit this field.
   */
  readonly requires?: ReadonlyArray<CopilotModuleRequirement>;

  /** Knowledge modules contributed (registered in KnowledgeRegistry). */
  readonly knowledge?: ReadonlyArray<KnowledgeModule>;

  /** Events this module interacts with. Used for documentation and validation. */
  readonly events?: {
    produces: string[];
    consumes: string[];
  };

  /**
   * Initialize the module with config and runtime context.
   * Called once when the module is loaded. May be async (e.g. to check binary deps).
   */
  init?(config: Record<string, unknown>, ctx: ModuleContext): Promise<void>;

  /**
   * Graceful shutdown — close connections, stop background processes.
   * Called when the copilot session ends or the module is unloaded.
   */
  dispose?(): Promise<void>;
}

// ---------------------------------------------------------------------------
// Module specifier (how modules are referenced for loading)
// ---------------------------------------------------------------------------

/** How a module is referenced for loading. */
export type ModuleSpecifier =
  | { type: "builtin"; id: string }
  | { type: "local"; path: string }
  | { type: "package"; name: string }
  | { type: "mcp"; serverUrl: string };

// ---------------------------------------------------------------------------
// Module registry query types
// ---------------------------------------------------------------------------

/** Summary info for listing modules. */
export interface ModuleInfo {
  id: string;
  displayName: string;
  category: ModuleCategory;
  version: string;
  description: string;
  toolCount: number;
  taskCount: number;
  loaded: boolean;
  rank?: ModuleRank;
  references?: ReadonlyArray<ModuleReference>;
  disclosureDate?: string;
}
