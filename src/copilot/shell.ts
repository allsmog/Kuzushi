/**
 * Interactive copilot shell — the default `kuzushi` experience.
 *
 * The shell is module-forward: operators choose a module, set options,
 * and run tools through the dispatcher. Agent chat is explicit via /ask
 * so command execution stays predictable.
 */

import { once } from "node:events";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  killAllClaudeSubprocesses,
  warnIfNonAnthropicProxy,
  warnIfStaleModel,
} from "../agent-runtime/claude.js";
import { configureAgentRuntime } from "../agent-runtime/index.js";
import {
  describeModelOverrideFormat,
  validateModelOverride,
} from "../agent-runtime/model-validation.js";
import { clampHint, summarizeInput } from "../agent-runtime/tool-summary.js";
import type { AgentQueryOptions, AgentRuntime, AgentSession } from "../agent-runtime/types.js";
import { createBus } from "../bus/index.js";
import type { MessageBus } from "../bus/types.js";
import { JobManager } from "../jobs/manager.js";
import {
  type AttachmentStorageAdapter,
  buildHomeSlice,
  defaultAttachmentAdapter,
  type KindSpec,
} from "../modules/_shared/attachments/index.js";
import { CARLINI_THREAT_HUNT_KIND_SPEC } from "../modules/carlini-threat-hunt/attachments.js";
import { CONTEXT_KIND_SPEC } from "../modules/context/attachments.js";
import { formatContextSummary } from "../modules/core-sast.js";
import { resolveTaintIrisNextPersistentArtifacts } from "../modules/taint-iris-next/planner.js";
import { THREAT_MODEL_KIND_SPEC } from "../modules/threat-model/attachments.js";
import type { ModuleInfo, ModuleTool } from "../modules/types.js";
import { loadDraftScope, scopeToHomeSlice } from "../modules/vendor-assessment/storage.js";
import { SessionManager } from "../sessions/manager.js";
import type { PipelineRunRecord } from "../store.js";
import { applyThreatModelPatch, proposeThreatModelPatch } from "../threat-model-patch.js";
import { loadPersistentThreatModel } from "../threat-model-renderer.js";
import type { KuzushiConfig } from "../types.js";
import { formatUnknownModule, formatUnknownTool, formatUnknownVerb } from "../ui/error-format.js";
import { formatDuration } from "../ui/format.js";
import type {
  ContextGenerationSlice,
  ContextSnapshot,
  OptionsViewSlice,
  ShellArtifactStatus,
  ShellHistoryEntry,
  ShellModuleCard,
  ShellState,
  ShellView,
  SummaryData,
  ThreatTab,
  ToolActivityLine,
  TuneSnapshot,
  UIState,
  UIStore,
} from "../ui/state.js";
import { initContextBuildState } from "../ui/state.js";
import {
  appendCuratedStoryEvent,
  appendStoryTail,
  createAbortStoryEvent,
  createBackgroundJobStoryEvent,
  createShellStoryEvent,
  formatStoryEventPlain,
  isTerminalStoryStatus,
  type ShellStoryEvent,
  type ShellStoryEventDraft,
  type ShellTaskBackgroundJob,
  shouldPersistStoryEvent,
  upsertBackgroundJob,
} from "../ui/task-story.js";
import { toErrorMessage } from "../utils.js";
import { CopilotCore } from "./core.js";
import { looksLikePath, resolveTool } from "./dispatch/resolve-tool.js";
import { CoreDispatcher, DispatcherDriver, WorkspaceDispatcher } from "./dispatcher/index.js";
import { ModuleDispatcher } from "./dispatcher/module-dispatcher.js";
import { openInEditor } from "./editor.js";
import { computeChainAliases, computeFindingAliases, formatAliasTable } from "./finding-alias.js";
import { runPlanner, type ShellPlan } from "./nl-planner.js";
import { Datastore } from "./options.js";
import { createPrintSink, type PrintLevel, type PrintSink } from "./print.js";
import {
  editPrompt,
  formatEffectivePromptLine,
  formatPromptAuditTable,
  type PromptOptionKey,
  promptKeyToVerb,
  readEffectivePrompt,
  readPromptAudit,
} from "./prompt-edit.js";
import { listRecipes, resolveRecipePath } from "./recipes.js";
import { openRepl as openDevRepl } from "./repl.js";
import { formatRunReplay, formatRunsTable, formatRunTrace, readTraceEvents } from "./replay.js";
import { loadAndRunResource, saveResourceScript } from "./resource.js";
import {
  formatResumeChooser,
  formatRunReplaySummary,
  formatRunResumeSummary,
  latestCompletedRun,
  runMatchesTool,
  selectResumeCandidates,
  toolSupportsCheckpointResume,
} from "./resume.js";
import { parseToolArgs } from "./run.js";
import {
  buildSastTaskSelectionSummary,
  defaultManualSastTasks,
  formatSastTaskFeedback,
  formatSastTaskStateLine,
  readDisabledSastTasks,
  readManualSastTasks,
  readSastTaskMode,
  readStringArrayOption,
  resetSastTaskOptions,
  resolveSastTaskAtCursor,
  resolveSastTaskCapability,
  SAST_SCAN_TOOL_NAME,
  SAST_TASK_CAPABILITIES,
  type SastTaskMode,
  setSastTaskMode,
  toggleDisabledSastTask,
  updateDisabledSastTask,
} from "./sast-task-selection.js";
import {
  commandMatches,
  defineShellRoutes,
  routeShellInput,
  type ShellRoute,
  type ShellRouteDefinition,
} from "./shell/router.js";
import {
  buildShellPrompt,
  type CommandSurfaceKind,
  collectKnownVerbs,
  commandSurface,
  formatHelpForVerb,
  getCommandMetadata,
  isCommandVisibleInDefaultHelp,
  SHELL_COMMAND_CATALOG,
  SHELL_COMMAND_GROUP_TITLES,
  type ShellCommandEntry,
  type ShellCommandGroup,
} from "./shell-commands.js";
import { SpoolController } from "./spool.js";

export type { ShellCommandEntry, ShellCommandGroup } from "./shell-commands.js";
export {
  buildShellPrompt,
  firstShellSuggestion,
  listShellSuggestions,
  SHELL_COMMAND_CATALOG,
} from "./shell-commands.js";

const SHELL_ALLOWED_TOOLS = ["Read", "Glob", "Grep", "Bash", "LS"];
const SHELL_HISTORY_FILENAME = "shell-history.json";
const MAX_SHELL_HISTORY = 1000;
const DEFAULT_NO_SESSION_MESSAGE =
  "Copilot disabled — no interactive agent session is available. Run /backend pi-ai, /backend claude, or /backend codex, then /auth to set credentials.";
const CREDENTIALS_CANCELLED_MESSAGE =
  "Copilot disabled. Run /auth to enable it later, export a provider API key, or save credentials to ./.kuzushi/credentials.json.";
const CANCELLED_TOOL_MESSAGE = "Cancelled active operation.";
const CANCELLED_AGENT_MESSAGE = "Cancelled active request.";
const SIGNAL_DUPLICATE_GRACE_MS = 150;

const CONTEXT_REQUIRED_TOOLS = new Set([
  "carlini-threat-hunt:run",
  "taint-iris:hunt",
  "taint-iris-next:hunt",
]);

/**
 * Claude Agent SDK built-in tool names — used to tag `task:activity` pulses
 * that are really sub-agent tool-use / tool-summary headers ("Read · path",
 * "Glob \"**\/*.go\" (300 files)"). Those render in base text color like the
 * parent `⏺` tool-call row, matching opencode/Claude Code's `∟`/`⎿`
 * convention where muted gray is reserved for free-form body-text pulses
 * ("scanning repo structure"), not for nested invocation headers.
 *
 * Intentionally case-sensitive: Kuzushi's own `ctx.reportActivity` messages
 * start with lowercase verbs ("scanning", "enriching", "phase N (…)") so
 * this match won't false-positive on them.
 */
const SUBAGENT_TOOL_NAMES = [
  "Read",
  "Write",
  "Edit",
  "MultiEdit",
  "Glob",
  "Grep",
  "Bash",
  "LS",
  "Task",
  "TodoWrite",
  "WebFetch",
  "WebSearch",
  "NotebookRead",
  "NotebookEdit",
] as const;
const SUBAGENT_TOOL_RE = new RegExp(`^(?:${SUBAGENT_TOOL_NAMES.join("|")})\\b`);

/** True when a task:activity description is a sub-agent tool invocation/summary header. */
function looksLikeSubagentToolLine(text: string): boolean {
  return SUBAGENT_TOOL_RE.test(text);
}

/**
 * True when a task:activity description is the *start-side* of a sub-agent
 * tool call — either a bare tool name emitted on `tool-call-start` (before
 * args have streamed) or the assistant-message-block hint (`"Read · path"`).
 * These are superseded by the later `tool-summary` line (`"Read path (42
 * lines)"`), so we suppress the start-side entries from scrollback history
 * to avoid showing two-to-three rows for each Read/Grep/Bash. The
 * running tool's `liveActivities` tail and the per-agent heartbeat still
 * tick on every sub-agent step — suppression only targets the *permanent*
 * scrollback record, not the live ephemeral feed.
 */
function looksLikeSubagentStartLine(text: string): boolean {
  if (!SUBAGENT_TOOL_RE.test(text)) return false;
  // Assistant tool_use hint: "Read · src/api.ts"
  if (text.includes(" · ")) return true;
  // tool-call-start: bare name ("Read", "Grep", ...)
  return !/\s/.test(text);
}

/** Build a seed map from a ContextSnapshot to inject into pipelines.
 *
 * Seed VALUE SHAPE must match what each task actually returns, because
 * downstream consumers (`extractActorsWithThreats` in carlini-threat-hunt,
 * `asStrideTaskOutput` in scanner tasks, …) deref specific fields on
 * the upstream output. Mismatches manifest as "0 findings, 0 actors"
 * with no error — the task just short-circuits on
 * `!isRecord(raw["document"])`.
 *
 * Per-key shapes (derived from each task's `run()` return):
 *   context-gatherer:      { repoContext, fileIndex }
 *   context-enricher:      EnrichedContext (bare)
 *   app-model-build:       ApplicationModel (bare)
 *   threat-model-randori:  { document: ThreatModelDocument, findings: Finding[] }
 *   threat-scenario-build: { scenarios: ThreatScenario[] }
 *
 * `findings: []` for threat-model-randori is safe — carlini-threat-hunt only
 * reads `.document`, and no other task reads the findings array from
 * the threat-model output (those findings flow separately via
 * `taskOutputs["threat-model-randori"].findings` into the report
 * phase, which isn't reconstructed from the snapshot).
 */
function buildSeedMapFromSnapshot(
  snapshot: ContextSnapshot,
  extras: { threatModel?: unknown; scenarios?: unknown[] } = {},
): Map<string, unknown> {
  const seed = new Map<string, unknown>();
  if (snapshot.repoContext || snapshot.fileIndex) {
    seed.set("context-gatherer", {
      repoContext: snapshot.repoContext,
      fileIndex: snapshot.fileIndex,
    });
  }
  if (snapshot.enrichedContext) seed.set("context-enricher", snapshot.enrichedContext);
  if (snapshot.appModel) seed.set("app-model-build", snapshot.appModel);
  if (extras.threatModel)
    seed.set("threat-model-randori", { document: extras.threatModel, findings: [] });
  if (extras.scenarios) seed.set("threat-scenario-build", { scenarios: extras.scenarios });
  return seed;
}

export interface ShellOptions {
  config: KuzushiConfig;
  runtime: AgentRuntime;
  /** Active workspace id used for persistence and tool execution. */
  workspace?: string;
  /** Human-readable active workspace name for shell UI and prompts. */
  workspaceName?: string;
  modules?: string[];
  /**
   * Built-in module ids to skip during the default load (forwarded to
   * `CopilotCoreOptions.excludeBuiltinModules`). Lets `kuzushi shell
   * --exclude codeql` bypass loading the codeql module when its CLI
   * isn't installed. Field-test issue #21.
   */
  excludeBuiltinModules?: string[];
  target?: string;
}

interface ShellContext {
  focusedModule: string | null;
  /** UIStore for passing to tool execution (so pipeline renders through Ink). */
  uiStore?: UIStore;
  /** Workspace manager for persistence (optional — degrades gracefully). */
  workspaceManager?: import("../workspace/manager.js").WorkspaceManager;
  /** Absolute path to `.kuzushi/` for this session — used by tune/house-rules. */
  dataDir?: string;
}

interface LocalCommandResult {
  output?: string;
  exit?: boolean;
  /**
   * Keep the shell's current turn busy after this local command. Live controls
   * such as `/pause` and `/resume` change queue state but do not end the run.
   */
  keepProcessing?: boolean;
  /** Update focusedModule. */
  setFocus?: string | null;
  /** Clear rendered conversation history. */
  clearHistory?: boolean;
  /** Close the current agent session before continuing. */
  resetSession?: boolean;
  /** Apply an in-memory shell-state update. */
  shellStateUpdater?: (shell: ShellState) => ShellState;
  /** Fully-qualified tool name executed successfully by this command. */
  executedToolName?: string;
  /** Async tool execution needed — returns a promise of output. */
  asyncExecute?: (signal?: AbortSignal) => Promise<string | AsyncExecutionResult>;
  /**
   * When set, the shell should stream this string through `currentSession.query()`
   * — this is the `/ask` pathway. Replaces the old silent fallback that
   * forwarded any unknown input to the agent and invited hallucinated answers.
   */
  askQuestion?: string;
  /**
   * Set by `/target <path>` so the input loop can re-mirror `opts.target` into
   * the globals Datastore. M3: keeps the per-module DelegatingDatastore
   * fall-through aligned with the active shell target across `run`/`run .`
   * dispatches.
   */
  targetUpdated?: boolean;
}

interface AsyncExecutionResult {
  output: string;
  ok?: boolean;
  costUsd?: number;
}

function applyImplicitShellTarget(opts: ShellOptions): void {
  if (!opts.target) {
    opts.target = process.cwd();
  }
}

/**
 * Mirror `opts.target` into the globals Datastore so per-module
 * DelegatingDatastores can fall through to it. Called once at shell startup
 * and again whenever `/target <path>` updates the active target — keeps
 * `run` (no args) from spuriously erroring with "Missing required: target"
 * when the home view shows a perfectly valid target.
 */
function syncShellTargetToGlobals(opts: ShellOptions, globals: Datastore): void {
  if (opts.target) {
    globals.set("target", opts.target, "global");
  } else {
    globals.unset("target", "global");
  }
}

/**
 * M1: copy taskConfig entries keyed by a legacy module id forward to the
 * canonical id. Idempotent. The canonical entry wins on key conflict so an
 * operator who already has both `taskConfig["threat-hunt"]` and
 * `taskConfig["carlini-threat-hunt"]` keeps their newer settings.
 */
function migrateLegacyTaskConfigKeys(
  config: KuzushiConfig,
  aliases: ReadonlyArray<{ from: string; to: string }>,
): void {
  if (aliases.length === 0) return;
  for (const { from, to } of aliases) {
    const legacy = config.taskConfig[from];
    if (!legacy) continue;
    config.taskConfig[to] = {
      ...legacy,
      ...(config.taskConfig[to] ?? {}),
    };
  }
}

function inferWorkspaceNameFromTarget(target: string | undefined): string | undefined {
  const raw = target?.trim();
  if (!raw) return undefined;

  const urlMatch = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
  if (urlMatch) {
    try {
      const url = new URL(raw);
      return sanitizeWorkspaceName(url.hostname || url.pathname);
    } catch {
      return sanitizeWorkspaceName(raw);
    }
  }

  // U1: Walk up to the nearest .git ancestor and use `<repo>/<relative>`
  // as the display name. Without this, scanning a sub-tree of a monorepo
  // (e.g. `~/monorepo/lab/agents/`) showed `agents` — the basename — making
  // it impossible to tell which repo was actually in scope.
  const resolved = path.resolve(raw);
  const repoRoot = findGitRoot(resolved);
  if (repoRoot && repoRoot !== resolved) {
    const repo = path.basename(repoRoot);
    const rel = path.relative(repoRoot, resolved);
    return sanitizeWorkspaceName(rel ? `${repo}/${rel}` : repo);
  }
  return sanitizeWorkspaceName(path.basename(resolved));
}

/** Walk up from `dir` to find the nearest ancestor containing a `.git/` (or
 *  `.git` worktree pointer file). Returns null when none found. */
function findGitRoot(dir: string): string | null {
  let cur = dir;
  for (let depth = 0; depth < 64; depth += 1) {
    if (existsSync(path.join(cur, ".git"))) return cur;
    const parent = path.dirname(cur);
    if (parent === cur) return null;
    cur = parent;
  }
  return null;
}

function sanitizeWorkspaceName(raw: string | undefined): string | undefined {
  const cleaned = (raw ?? "")
    .trim()
    .replace(/[^A-Za-z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return cleaned.length > 0 ? cleaned.slice(0, 80) : undefined;
}

function readDefaultWorkspaceName(): string | undefined {
  const defaultFile = path.join(homedir(), ".kuzushi", "default-workspace");
  if (!existsSync(defaultFile)) return undefined;
  try {
    const name = readFileSync(defaultFile, "utf8").trim();
    return name || undefined;
  } catch {
    return undefined;
  }
}

function workspaceDisplayName(
  opts: ShellOptions,
  workspaceManager?: import("../workspace/manager.js").WorkspaceManager,
): string | null {
  if (opts.workspaceName) return opts.workspaceName;
  if (!opts.workspace) return null;
  const ws = workspaceManager?.get(opts.workspace);
  return ws?.name ?? opts.workspace;
}

type ShellSessionOutcome = {
  session: AgentSession | undefined;
  error?: string;
};

type ToolPropertySchema = {
  type?: string | string[];
  description?: string;
  default?: unknown;
  enum?: unknown[];
  items?: ToolPropertySchema;
};

function shellHistoryPath(dataDir: string): string {
  return path.join(dataDir, SHELL_HISTORY_FILENAME);
}

function capShellHistory(history: string[]): string[] {
  return history.filter(Boolean).slice(-MAX_SHELL_HISTORY);
}

/**
 * Map the sub-verb of `/threats <sub>` to a threat-model shellView. Accepts
 * both named (`dfd`, `stride`, `stories`, `scope`, `summary`) and numeric
 * (`1..5`) shortcuts so operators can cycle through the Phase C views with
 * the same keys shown in the footer.
 */
export function resolveThreatView(
  sub: string | undefined,
): { shellView: ShellView; threatTab: ThreatTab; label: string } | undefined {
  switch (sub) {
    case "dfd":
    case "1":
      return { shellView: "threats", threatTab: "dfd", label: "data flow diagram" };
    case "stride":
    case "2":
      return { shellView: "threats", threatTab: "stride", label: "STRIDE matrix" };
    case "stories":
    case "3":
      return { shellView: "threats", threatTab: "stories", label: "attacker stories" };
    case "scope":
    case "4":
      return { shellView: "threats", threatTab: "scope", label: "scope & criticality" };
    case "summary":
    case "5":
      return { shellView: "threats", threatTab: "summary", label: "threat summary" };
    default:
      return undefined;
  }
}

const CONTEXT_REGEN_SLICES: ReadonlyArray<ContextGenerationSlice> = [
  "all",
  "repo",
  "enrichment",
  "app-model",
];
const THREAT_MODEL_REGEN_SLICES = [
  "all",
  "dfd",
  "stride",
  "stories",
  "scope",
  "scenarios",
] as const;
type ThreatModelRegenSlice = (typeof THREAT_MODEL_REGEN_SLICES)[number];

function parseContextRegenSlice(value: string | undefined): ContextGenerationSlice | undefined {
  return CONTEXT_REGEN_SLICES.includes(value as ContextGenerationSlice)
    ? (value as ContextGenerationSlice)
    : undefined;
}

function parseThreatModelRegenSlice(value: string | undefined): ThreatModelRegenSlice | undefined {
  return THREAT_MODEL_REGEN_SLICES.includes(value as ThreatModelRegenSlice)
    ? (value as ThreatModelRegenSlice)
    : undefined;
}

/**
 * Best-guess "default tool" for a focused module — mirrors the preference
 * order used by ModuleDispatcher's `run`. Used when a fresh `/plan` runs
 * before the operator has touched `/options` and `lastUsedTool` is unset.
 */
export function pickDefaultToolName(core: CopilotCore, moduleId: string): string | undefined {
  if (!core.hasModule(moduleId)) return undefined;
  const mod = core.registry.get(moduleId);
  const preferred = [
    `${moduleId}:run`,
    `${moduleId}:scan`,
    `${moduleId}:audit`,
    `${moduleId}:hunt`,
    `${moduleId}:exploit`,
    `${moduleId}:build`,
    `${moduleId}:list`,
  ];
  for (const name of preferred) {
    const t = mod.tools.find((x) => x.name === name);
    if (t) return t.name;
  }
  const headless = mod.tools.find((t) => t.headless);
  return (headless ?? mod.tools[0])?.name;
}

function pickCheckpointResumeTool(core: CopilotCore, moduleId: string): ModuleTool | undefined {
  if (!core.hasModule(moduleId)) return undefined;
  const mod = core.registry.get(moduleId);
  const visible = mod.tools.find((tool) => !tool.hidden && toolSupportsCheckpointResume(tool));
  if (visible) return visible;
  return mod.tools.find((tool) => toolSupportsCheckpointResume(tool));
}

/** `.kuzushi/house-rules/<moduleId>.md` — per-module nudge text from the operator. */
function houseRulesPath(dataDir: string, moduleId: string): string {
  return path.join(dataDir, "house-rules", `${moduleId}.md`);
}

/**
 * Read the optional house-rules text for a module. Returns undefined when no
 * file exists; never throws — an unreadable file just surfaces as empty.
 */
export function readHouseRules(dataDir: string, moduleId: string): string | undefined {
  const file = houseRulesPath(dataDir, moduleId);
  if (!existsSync(file)) return undefined;
  try {
    return readFileSync(file, "utf-8").trim() || undefined;
  } catch {
    return undefined;
  }
}

/**
 * Build the narrow TuneSnapshot the v2 Tune screen renders from. Pulls from
 * KuzushiConfig so the Tune screen stays a pure read of the config the
 * operator already has; edits still flow through the full ConfigEditor.
 */
export function buildTuneSnapshot(
  config: KuzushiConfig,
  dataDir: string,
  focusedModule: string | null,
): TuneSnapshot {
  const houseRules = focusedModule ? readHouseRules(dataDir, focusedModule) : undefined;
  const houseRulesPathStr = focusedModule ? houseRulesPath(dataDir, focusedModule) : undefined;
  return {
    // Preset is a CLI-level notion that doesn't round-trip to the stored
    // config; when present in the live `config` snapshot it's available, but
    // we leave it undefined if the user hasn't pinned one.
    preset: (config as unknown as { preset?: string }).preset,
    tasks: config.tasks ?? [],
    verify: config.verify ?? false,
    autoPatch: config.autoPatchEnabled ?? false,
    triageConcurrency: config.triageConcurrency ?? 5,
    model: config.model ?? "",
    houseRules,
    houseRulesPath: houseRulesPathStr,
  };
}

async function existingRunDbPaths(dataDir: string, target?: string): Promise<string[]> {
  const paths: string[] = [];
  if (target && !/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) {
    const { defaultDbPath } = await import("../store.js");
    paths.push(defaultDbPath(path.resolve(target)));
  }
  paths.push(path.join(dataDir, "findings.sqlite3"));
  return [...new Set(paths)].filter((dbPath) => existsSync(dbPath));
}

async function readRunHistoryForCatalog(
  dataDir: string,
  target?: string,
): Promise<PipelineRunRecord[]> {
  const dbPaths = await existingRunDbPaths(dataDir, target);
  if (dbPaths.length === 0) return [];
  const { initDb, listRuns } = await import("../store.js");
  const runs: PipelineRunRecord[] = [];
  for (const dbPath of dbPaths) {
    const db = initDb(dbPath);
    try {
      runs.push(...listRuns(db, { limit: 250 }));
    } finally {
      db.close();
    }
  }
  return runs;
}

function normalizeHydrationTarget(raw: string | null | undefined): string | undefined {
  const trimmed = raw?.trim();
  if (!trimmed) return undefined;
  if (/^file:\/\//i.test(trimmed)) {
    try {
      return fileURLToPath(trimmed);
    } catch {
      return undefined;
    }
  }
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) && !/^file:\/\//i.test(trimmed)) {
    return undefined;
  }
  return path.resolve(trimmed);
}

function resolveHydrationTarget(opts: ShellOptions, shell: ShellState): string | undefined {
  return normalizeHydrationTarget(
    opts.target ?? shell.target ?? shell.contextSnapshot?.target ?? process.cwd(),
  );
}

function noteHydrationError(status: ShellArtifactStatus, label: string, error: unknown): void {
  const message = toErrorMessage(error);
  status.lastError = status.lastError
    ? `${status.lastError}; ${label}: ${message}`
    : `${label}: ${message}`;
}

function sortRunsNewestFirst(runs: ReadonlyArray<PipelineRunRecord>): PipelineRunRecord[] {
  return [...runs].sort((a, b) => runSortTime(b) - runSortTime(a));
}

function runSortTime(run: PipelineRunRecord): number {
  const raw = run.completedAt ?? run.updatedAt ?? run.startedAt;
  const parsed = Date.parse(raw);
  return Number.isFinite(parsed) ? parsed : 0;
}

async function hydrateSummaryFromDisk(
  dataDir: string,
  target: string | undefined,
  runs: ReadonlyArray<PipelineRunRecord>,
  status: ShellArtifactStatus,
): Promise<SummaryData | null> {
  const dbPaths = await existingRunDbPaths(dataDir, target);
  const dbPath = dbPaths[0];
  if (!dbPath) return null;
  status.findingsDbPath = dbPath;
  const { getActionableFindings, initDb, listRuns } = await import("../store.js");
  const { buildSummaryData } = await import("../ui/summary-data.js");
  const db = initDb(dbPath);
  try {
    const sortedRuns = sortRunsNewestFirst(runs);
    const latestRun = sortedRuns[0] ?? listRuns(db, { limit: 1 })[0];
    const firstFinding = latestRun
      ? undefined
      : getActionableFindings(db, undefined, { includeFalsePositives: true })[0];
    const repo = latestRun?.repo ?? firstFinding?.repo ?? (target ? path.basename(target) : "");
    if (!repo) return null;
    let summary: SummaryData;
    try {
      summary = buildSummaryData(db, repo, {
        ...(latestRun?.runId ? { runId: latestRun.runId } : {}),
        ...(target ? { repoRoot: target } : {}),
      });
    } catch (error) {
      noteHydrationError(status, "threat-model summary", error);
      summary = buildSummaryData(db, repo);
    }
    status.findingsCount = summary.actionableFindings.length;
    return summary;
  } finally {
    db.close();
  }
}

function hydrateKbSlice(
  shell: ShellState,
  repoRoot: string,
  status: ShellArtifactStatus,
): ShellState {
  const moduleId = shell.kb?.moduleId ?? shell.focusedModule;
  if (!moduleId) return shell;
  const entry = KB_REGISTRY.get(moduleId);
  if (!entry) return shell;
  const adapter = entry.adapter ?? defaultAttachmentAdapter<string>(moduleId);
  const scopePath = adapter.pathFor(repoRoot);
  const docs = adapter.read(repoRoot);
  const slice = buildHomeSlice(moduleId, scopePath, docs, entry.spec);
  const cursor =
    shell.kb && shell.kb.moduleId === moduleId
      ? Math.min(shell.kb.cursor, Math.max(0, slice.documents.length - 1))
      : 0;
  status.kbPath = scopePath;
  return {
    ...shell,
    kbState: { ...(shell.kbState ?? {}), [moduleId]: slice },
    ...(shell.shellView === "kb"
      ? { kb: { moduleId, cursor, collapsed: shell.kb?.collapsed ?? false } }
      : {}),
  };
}

export async function hydrateShellArtifacts(
  shell: ShellState,
  core: CopilotCore,
  opts: ShellOptions,
  dataDir: string,
): Promise<{ shell: ShellState; summary?: SummaryData | null }> {
  const repoRoot = resolveHydrationTarget(opts, shell);
  const status: ShellArtifactStatus = {
    refreshedAt: Date.now(),
    target: repoRoot ?? null,
  };
  let nextShell: ShellState = shell;
  let summary: SummaryData | null | undefined;

  let runs: PipelineRunRecord[] = [];
  try {
    runs = sortRunsNewestFirst(await readRunHistoryForCatalog(dataDir, repoRoot));
    status.runCount = runs.length;
    nextShell = {
      ...nextShell,
      moduleCatalog: buildModuleCatalog(core.listModules(), core, runs),
    };
  } catch (error) {
    noteHydrationError(status, "run history", error);
  }

  if (repoRoot) {
    try {
      const { contextSnapshotPath, loadContextSnapshot } = await import(
        "../modules/sast/context-persist.js"
      );
      status.contextSnapshotPath = contextSnapshotPath(repoRoot);
      nextShell = {
        ...nextShell,
        contextSnapshot: loadContextSnapshot(repoRoot) ?? null,
      };
    } catch (error) {
      noteHydrationError(status, "context snapshot", error);
    }

    if (!nextShell.threatModelDirty && !nextShell.pendingThreatPatch) {
      try {
        const { loadShellThreatModel } = await import("./threat-model-loader.js");
        const loaded = loadShellThreatModel(repoRoot);
        status.threatModelPath =
          loaded?.sourcePath ?? path.join(repoRoot, ".kuzushi", "threat-model.json");
        nextShell = loaded
          ? {
              ...nextShell,
              threatModel: loaded.document,
              threatModelSource: { path: loaded.sourcePath, mtimeMs: loaded.mtimeMs },
            }
          : {
              ...nextShell,
              threatModel: null,
              threatModelSource: undefined,
            };
      } catch (error) {
        noteHydrationError(status, "threat model", error);
      }
    }

    try {
      nextShell = hydrateKbSlice(nextShell, repoRoot, status);
    } catch (error) {
      noteHydrationError(status, "knowledge base", error);
    }

    if (nextShell.focusedModule === "vendor-assessment" || nextShell.vendorAssessment) {
      try {
        const vendorAssessment = scopeToHomeSlice(repoRoot, loadDraftScope(repoRoot));
        status.vendorAssessmentScopePath = vendorAssessment.scopePath;
        nextShell = { ...nextShell, vendorAssessment };
      } catch (error) {
        noteHydrationError(status, "vendor assessment scope", error);
      }
    }
  }

  try {
    summary = await hydrateSummaryFromDisk(dataDir, repoRoot, runs, status);
  } catch (error) {
    noteHydrationError(status, "findings summary", error);
  }

  return {
    shell: {
      ...nextShell,
      target: opts.target ?? nextShell.target ?? null,
      artifactStatus: status,
    },
    summary,
  };
}

async function hydrateShellStore(
  store: UIStore,
  core: CopilotCore,
  opts: ShellOptions,
  dataDir: string,
): Promise<void> {
  const shell = store.getState().shell;
  if (!shell) return;
  const hydrated = await hydrateShellArtifacts(shell, core, opts, dataDir);
  const patch: Partial<UIState> = { shell: hydrated.shell };
  if (hydrated.summary !== undefined) {
    patch.summary = hydrated.summary;
  }
  store.update(patch);
}

/**
 * Transform `core.listModules()` into the flat struct the v2 ModuleCatalog /
 * ModuleHome screens render from. Keeping this here (rather than inside the
 * UI layer) so the UI never has to import anything from `src/modules/`.
 */
export function buildModuleCatalog(
  modules: ReadonlyArray<ModuleInfo>,
  core: CopilotCore,
  runs: ReadonlyArray<PipelineRunRecord> = [],
): ShellModuleCard[] {
  return modules.map((mod) => {
    const registryHas =
      (core.registry as { has?: (id: string) => boolean }).has?.(mod.id) ?? core.hasModule(mod.id);
    const instance = registryHas ? core.registry.get(mod.id) : undefined;
    const toolSummaries = instance
      ? instance.tools.map((tool) => ({
          name: tool.name,
          // Tool names are always fully-qualified "module:verb"; split to get the
          // bare verb. Fall back to the full name if a module somehow used a
          // different convention (e.g. an external package).
          verb: tool.name.includes(":") ? tool.name.split(":").slice(1).join(":") : tool.name,
          description: tool.description,
          headless: tool.headless,
          hidden: tool.hidden === true,
          ...(tool.runLifecycle?.resume ? { resumeMode: tool.runLifecycle.resume } : {}),
          ...(tool.runLifecycle?.liveControl ? { liveControl: tool.runLifecycle.liveControl } : {}),
        }))
      : undefined;
    const checkpointTools =
      instance?.tools.filter((tool) => toolSupportsCheckpointResume(tool)) ?? [];
    const resumeCandidate = checkpointTools
      .flatMap((tool) => selectResumeCandidates(runs, mod.id, tool))
      .sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt))[0];
    const completedCandidate =
      checkpointTools.length > 0
        ? latestCompletedRun(
            runs.filter((run) =>
              checkpointTools.some(
                (tool) => run.status === "complete" && runMatchesTool(run, mod.id, tool),
              ),
            ),
          )
        : undefined;
    const runState = resumeCandidate
      ? {
          kind: "resume" as const,
          runId: resumeCandidate.runId,
          summary: formatRunResumeSummary(resumeCandidate),
          actions: ["resume", "restart", `replay ${resumeCandidate.runId}`],
        }
      : completedCandidate
        ? {
            kind: "complete" as const,
            runId: completedCandidate.runId,
            summary: formatRunReplaySummary(completedCandidate),
            actions: [`replay ${completedCandidate.runId}`, "rerun"],
          }
        : undefined;
    const moduleRun = sortRunsNewestFirst(runs).find((run) => runBelongsToModule(run, mod.id));
    const genericLastRunAt = moduleRun
      ? Date.parse(moduleRun.completedAt ?? moduleRun.updatedAt ?? moduleRun.startedAt)
      : undefined;
    const genericLastRunSummary =
      moduleRun && genericLastRunAt !== undefined && Number.isFinite(genericLastRunAt)
        ? formatPipelineRunRecencySummary(moduleRun, genericLastRunAt)
        : undefined;
    const lastRunAt = runState
      ? Date.parse(
          runState.kind === "complete"
            ? (completedCandidate?.completedAt ?? completedCandidate?.startedAt ?? "")
            : (resumeCandidate?.updatedAt ?? resumeCandidate?.startedAt ?? ""),
        )
      : genericLastRunAt;
    const lastRunSummary = runState?.summary ?? genericLastRunSummary;
    const lastRunSeverityCounts = parseSeverityCounts(moduleRun?.metricsJson);
    return {
      id: mod.id,
      displayName: mod.displayName,
      category: mod.category,
      description: mod.description,
      rank: mod.rank,
      toolCount: mod.toolCount,
      // External packages surface later via a loader flag; default false here.
      external: false,
      ...(lastRunSummary
        ? {
            ...(lastRunAt !== undefined && Number.isFinite(lastRunAt) ? { lastRunAt } : {}),
            lastRunSummary,
            ...(lastRunSeverityCounts ? { lastRunSeverityCounts } : {}),
            ...(runState ? { runState } : {}),
          }
        : {}),
      toolSummaries,
    };
  });
}

function runBelongsToModule(run: PipelineRunRecord, moduleId: string): boolean {
  return contributingModuleIds(run).has(moduleId);
}

/**
 * Pull a `severityCounts` map out of a pipeline run's `metrics_json` blob.
 * Returns `undefined` when the column is null, the JSON is malformed, or
 * the field is missing/empty — callers fall back to a plain summary line.
 * Non-finite or negative counts are silently dropped so the sparkline
 * helper never has to defend against bad data.
 */
function parseSeverityCounts(metricsJson?: string | null): Record<string, number> | undefined {
  if (!metricsJson) return undefined;
  try {
    const parsed = JSON.parse(metricsJson) as { severityCounts?: unknown };
    const raw = parsed?.severityCounts;
    if (!raw || typeof raw !== "object") return undefined;
    const out: Record<string, number> = {};
    for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
      if (typeof value === "number" && Number.isFinite(value) && value >= 0) {
        out[key] = value;
      }
    }
    return Object.keys(out).length > 0 ? out : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Walk the run record and return every module that contributed to the run —
 * not just the run owner. A `sast:scan` pipeline includes `semgrep:scan`,
 * `codeql:scan`, etc. in its `config.tasks` array; without this lookup, the
 * semgrep card stays "never run" forever even after running inside a sast
 * pipeline. Reading `tasks` from `configJson` keeps us in sync with how the
 * pipeline runner already records what it ran.
 */
function contributingModuleIds(run: PipelineRunRecord): Set<string> {
  const ids = new Set<string>();
  if (run.moduleId) ids.add(run.moduleId);
  if (run.toolName?.includes(":")) {
    const owner = run.toolName.split(":")[0];
    if (owner) ids.add(owner);
  }
  try {
    const cfg = JSON.parse(run.configJson) as { tasks?: unknown };
    if (Array.isArray(cfg.tasks)) {
      for (const task of cfg.tasks) {
        if (typeof task !== "string") continue;
        const mod = task.split(":")[0];
        if (mod) ids.add(mod);
      }
    }
  } catch {
    /* malformed configJson — fall through with what we have */
  }
  return ids;
}

function formatPipelineRunRecencySummary(run: PipelineRunRecord, lastRunAt: number): string {
  const status =
    run.status === "complete"
      ? "ok"
      : run.status === "error"
        ? "error"
        : run.status === "interrupted"
          ? "interrupted"
          : run.status;
  const action = run.toolName ? toolActionName(run.toolName) : (run.resumeLabel ?? "run");
  const cost =
    typeof run.totalCostUsd === "number" && run.totalCostUsd > 0
      ? ` · $${run.totalCostUsd.toFixed(2)}`
      : "";
  return `${status} · ${action} · ${formatRunRecency(lastRunAt)}${cost}`;
}

function normalizeAsyncExecutionResult(value: string | AsyncExecutionResult): AsyncExecutionResult {
  return typeof value === "string" ? { output: value } : value;
}

function moduleIdFromToolName(toolName: string): string | null {
  const [moduleId] = toolName.split(":");
  return moduleId && moduleId.length > 0 ? moduleId : null;
}

function seedFocusedModuleRun(
  store: UIStore | undefined,
  shellState: ShellState,
  tool: ModuleTool,
  startedAtMs: number,
  inputSummary?: string,
  model?: string,
  effort?: string,
  thinkingDisabled?: boolean,
): void {
  if (!store) return;
  const moduleId = moduleIdFromToolName(tool.name);
  if (!moduleId || shellState.focusedModule !== moduleId) return;

  updateShell(store, (shell) => {
    const existing =
      shell.moduleRun?.status === "running" && shell.moduleRun.toolName === tool.name
        ? shell.moduleRun
        : undefined;
    return {
      ...shell,
      shellView: "module-run",
      focusedActor: null,
      moduleRun: {
        moduleId,
        source: "shell",
        toolName: tool.name,
        ...(tool.displayName ? { displayName: tool.displayName } : {}),
        ...((inputSummary ?? existing?.inputSummary)
          ? { inputSummary: inputSummary ?? existing?.inputSummary }
          : {}),
        ...(tool.runLifecycle?.liveControl ? { liveControl: tool.runLifecycle.liveControl } : {}),
        ...((model ?? existing?.model) ? { model: model ?? existing?.model } : {}),
        ...((effort ?? existing?.effort) ? { effort: effort ?? existing?.effort } : {}),
        ...((thinkingDisabled ?? existing?.thinkingDisabled) !== undefined
          ? { thinkingDisabled: thinkingDisabled ?? existing?.thinkingDisabled }
          : {}),
        startedAtMs: existing?.startedAtMs ?? startedAtMs,
        status: "running",
        steps: existing?.steps ?? [],
        evidenceTail: existing?.evidenceTail ?? [],
        findingCount: existing?.findingCount ?? 0,
        costUsd: existing?.costUsd ?? 0,
      },
    };
  });
}

function seedCheckpointModuleRun(
  store: UIStore | undefined,
  shellState: ShellState,
  tool: ModuleTool,
  startedAtMs: number,
  inputSummary?: string,
  model?: string,
  effort?: string,
  thinkingDisabled?: boolean,
): void {
  if (!store || tool.runLifecycle?.persistence !== "pipeline-checkpoint") return;
  seedFocusedModuleRun(
    store,
    shellState,
    tool,
    startedAtMs,
    inputSummary,
    model,
    effort,
    thinkingDisabled,
  );
}

function patchCheckpointModuleRunTerminal(
  store: UIStore,
  toolName: string,
  status: "done" | "error" | "aborted",
  costUsd?: number,
): void {
  updateShell(store, (shell) => {
    if (!shell.moduleRun || shell.moduleRun.toolName !== toolName) return shell;
    const run = shell.moduleRun;
    if (run.status !== "running") return shell;
    return {
      ...shell,
      moduleRun: {
        ...run,
        status,
        completedAtMs: run.completedAtMs ?? Date.now(),
        ...(costUsd != null ? { costUsd } : {}),
      },
    };
  });
}

function formatRunRecency(lastRunAt: number): string {
  const deltaMs = Math.max(0, Date.now() - lastRunAt);
  const minutes = Math.floor(deltaMs / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return new Date(lastRunAt).toISOString().slice(0, 10);
}

function buildModuleRunSummary(
  toolName: string,
  status: "ok" | "fail" | "abort",
  lastRunAt: number,
  costUsd?: number,
): string {
  const statusText = status === "ok" ? "ok" : status === "abort" ? "aborted" : "error";
  const action = toolActionName(toolName);
  const recency = formatRunRecency(lastRunAt);
  const cost = typeof costUsd === "number" ? ` · $${costUsd.toFixed(2)}` : "";
  return `${statusText} · ${action} · ${recency}${cost}`;
}

function applyModuleRunTelemetry(
  moduleCatalog: ShellModuleCard[] | undefined,
  toolName: string,
  status: "ok" | "fail" | "abort",
  costUsd?: number,
): ShellModuleCard[] | undefined {
  if (!moduleCatalog || moduleCatalog.length === 0) return moduleCatalog;

  const moduleId = moduleIdFromToolName(toolName);
  if (!moduleId) return moduleCatalog;

  const lastRunAt = Date.now();
  let touched = false;
  const next = moduleCatalog.map((card) => {
    if (card.id !== moduleId) return card;
    touched = true;
    return {
      ...card,
      lastRunAt,
      lastRunSummary: buildModuleRunSummary(toolName, status, lastRunAt, costUsd),
    };
  });
  return touched ? next : moduleCatalog;
}

export function loadShellCommandHistory(dataDir: string): string[] {
  const historyPath = shellHistoryPath(dataDir);
  if (!existsSync(historyPath)) {
    return [];
  }

  try {
    const raw = JSON.parse(readFileSync(historyPath, "utf-8")) as unknown;
    return Array.isArray(raw)
      ? capShellHistory(raw.filter((value): value is string => typeof value === "string"))
      : [];
  } catch {
    return [];
  }
}

export function saveShellCommandHistory(dataDir: string, history: string[]): void {
  const historyPath = shellHistoryPath(dataDir);
  writeFileSync(historyPath, `${JSON.stringify(capShellHistory(history), null, 2)}\n`, "utf-8");
}

export function extractAssistantText(content: Array<Record<string, unknown>>): string {
  return content
    .map((block) =>
      block["type"] === "text" && typeof block["text"] === "string" ? block["text"] : "",
    )
    .join("");
}

/**
 * Pull `tool_use` blocks out of an assistant message so they can be surfaced
 * in the shell's rolling activity tail. Returns one line per tool use —
 * "<toolName>(<short-input-hint>)" — with the input hint capped so the tail
 * doesn't blow past the column width.
 */
export function extractToolUseActivities(content: Array<Record<string, unknown>>): string[] {
  const out: string[] = [];
  for (const block of content) {
    if (block["type"] !== "tool_use") continue;
    const name = typeof block["name"] === "string" ? block["name"] : "tool";
    const hint = summarizeInput(block["input"]);
    out.push(hint ? `${name} · ${hint}` : name);
  }
  return out;
}

/**
 * Parse tool_use blocks out of an assistant message into `⏺` header entries
 * — `{ id, name, inputHint }` triples. Separate from `extractToolUseActivities`
 * (which returns the legacy `⎿ ` body-form string) because the cc-repo-style
 * flow emits the header once per tool call, not as a progress line.
 *
 * The `id` is the Anthropic `tool_use` block id (when present), used later
 * to correlate with `tool-summary` / `tool-progress` events so agent-driven
 * `⏺` entries can flip from running → resolved without manual bookkeeping.
 */
export function extractToolUseHeaders(
  content: Array<Record<string, unknown>>,
): Array<{ id?: string; name: string; inputHint?: string }> {
  const out: Array<{ id?: string; name: string; inputHint?: string }> = [];
  for (const block of content) {
    if (block["type"] !== "tool_use") continue;
    const id = typeof block["id"] === "string" ? (block["id"] as string) : undefined;
    const name = typeof block["name"] === "string" ? block["name"] : "tool";
    const hint = summarizeInput(block["input"]);
    out.push({
      ...(id ? { id } : {}),
      name,
      ...(hint ? { inputHint: hint } : {}),
    });
  }
  return out;
}

export { summarizeInput };

/**
 * Resolve the `(args)` portion of a tool-call header: prefer the per-tool
 * `formatInput` hook when it produces a non-empty string, otherwise fall
 * back to the generic primary-field extractor + 40-char clamp.
 *
 * Returning `""` from `formatInput` deliberately suppresses the hint (some
 * tools have no meaningful input to surface). Returning `null`/`undefined`
 * triggers the fallback.
 */
export function renderToolInputHint(
  tool: { formatInput?(input: unknown): string | null | undefined },
  input: unknown,
): string | undefined {
  if (tool.formatInput) {
    const custom = tool.formatInput(input);
    if (custom === "") return undefined;
    if (custom != null) return clampHint(custom);
  }
  return summarizeInput(input);
}

export function finalizeAssistantText(
  pendingAssistantText: string | undefined,
  resultText: string,
): string {
  return pendingAssistantText && pendingAssistantText.length > 0
    ? pendingAssistantText
    : resultText;
}

/**
 * Safety-net fallback: if the configured runtime does not expose
 * `createSession()`, swap `opts.runtime` to a fresh `ClaudeAgentRuntime` so the
 * shell still has an interactive session. Both the built-in runtimes (claude,
 * pi-ai) implement sessions today; this only engages for custom/future
 * runtimes that skip the optional method.
 *
 * Idempotent — safe to call multiple times.
 */
async function ensureClaudeShellRuntime(opts: ShellOptions, store?: UIStore): Promise<void> {
  if (typeof opts.runtime.createSession === "function") return;
  const backend = opts.config.agentRuntimeBackend ?? "pi-ai";
  // Pre-policy this used to silently construct a ClaudeAgentRuntime and
  // mutate opts.config.agentRuntimeBackend = "claude". That violates the
  // "no silent runtime swap" rule — operators who chose a different
  // backend would suddenly find their shell running on Anthropic Claude
  // (different provider, different billing) without explicit consent.
  const message =
    `Backend "${backend}" does not support interactive sessions. ` +
    `Kuzushi will not silently switch your shell to "claude". ` +
    `Run \`/backend claude\` (and \`/provider <anthropic:model>\` if needed) to use the interactive shell, ` +
    `or use \`kuzushi run\`/\`kuzushi scan\` which work with any backend.`;
  const { KuzushiSilentFallbackError } = await import("../agent-runtime/enforcement.js");
  if (store) {
    appendToHistory(store, { type: "error", text: message, timestamp: Date.now() });
  } else {
    process.stderr.write(`${message}\n`);
  }
  throw new KuzushiSilentFallbackError(message);
}

/**
 * Apply a CredentialOutcome to env vars + ShellOptions.config and (when the
 * user opted in) persist the API key to <cwd>/.kuzushi/credentials.json via
 * persistLocalCredentials. Returns a tuple describing what to surface to the user.
 *
 * Shared across the Ink startup prompt, the readline startup prompt, the
 * lazy re-prompt path inside ensureSession(), and the /auth slash command.
 */
type CredentialApplyResult = {
  enabled: boolean;
  /** Status string to render to the conversation (e.g. "Copilot enabled."). */
  message?: string;
  /** Path the credential was persisted to, when applicable. */
  persistedTo?: string;
};

/**
 * Rebuild `opts.runtime` so it picks up the latest config + env. Runtime
 * instances capture credentials at construction, so credentials supplied later
 * via /auth need a fresh backend instance. Keep the configured backend intact:
 * pi-ai stays pi-ai, claude stays claude, codex stays codex.
 */
async function rebuildShellRuntime(opts: ShellOptions): Promise<void> {
  opts.runtime = configureAgentRuntime(opts.config);
}

async function hasActiveShellCredentials(opts: ShellOptions): Promise<boolean> {
  // Inherited mode: the operator opted to trust whatever the parent process
  // / Claude Code session already has. Skip the prompt unconditionally —
  // the SDK subprocess will resolve creds at query time and surface a real
  // error if none are reachable, which is more useful than a generic
  // "no creds" preflight.
  if (opts.config.auth === "inherited") return true;

  const { resolveActiveCredentials } = await import("../config.js");
  const active = resolveActiveCredentials(opts.config);
  const backend = opts.config.agentRuntimeBackend ?? "pi-ai";

  if (backend === "claude") {
    const { hasAnthropicCredentials } = await import("../ui/setup.js");
    return hasAnthropicCredentials(active.apiKey, active.authToken);
  }

  if (active.apiKey || active.authToken || active.baseUrl) return true;

  const { hasAnyProviderCredentials } = await import("../ui/setup.js");
  return hasAnyProviderCredentials();
}

/** Merge `patch` into the active backend's slot in agentRuntimeConfig. */
function mergeIntoActiveSlot(
  opts: ShellOptions,
  patch: { apiKey?: string; authToken?: string; baseUrl?: string },
): void {
  const backend = opts.config.agentRuntimeBackend ?? "pi-ai";
  const slot = backend === "codex" ? "codex" : backend === "pi-ai" ? "piAi" : "claude";
  const existing = opts.config.agentRuntimeConfig?.[slot] ?? {};
  const nextSlot = { ...existing, ...patch };
  opts.config.agentRuntimeConfig = {
    ...opts.config.agentRuntimeConfig,
    [slot]: nextSlot,
  };
}

async function applyCredentialOutcome(
  outcome: import("../ui/setup.js").CredentialOutcome,
  opts: ShellOptions,
): Promise<CredentialApplyResult> {
  if (outcome.action === "cancel") {
    return { enabled: false, message: CREDENTIALS_CANCELLED_MESSAGE };
  }

  const choice = outcome.choice;
  if (choice.kind === "inherited") {
    // "Inherited Claude" — flip to the claude backend and persist `auth:
    // "inherited"` to the global config so future launches skip the prompt
    // even when no API key is in env. Generic "Use environment" (no
    // providerId or providerId === "inherited") only rebuilds the runtime;
    // it relies on whatever env vars already exist and re-prompts later
    // if they're missing.
    if (choice.providerId === "inherited-claude") {
      opts.config.agentRuntimeBackend = "claude";
      opts.config.auth = "inherited";
      let persistedTo: string | undefined;
      try {
        const { applyConfigPatch, configPath } = await import("../config.js");
        applyConfigPatch([
          { path: "agentRuntimeBackend", value: "claude" },
          { path: "auth", value: "inherited" },
        ]);
        persistedTo = configPath();
      } catch (error) {
        const detail = toErrorMessage(error);
        await rebuildShellRuntime(opts);
        return {
          enabled: true,
          message: `Inherited Claude enabled (in-memory). Failed to persist: ${detail}`,
        };
      }
      await rebuildShellRuntime(opts);
      return {
        enabled: true,
        message: `Inherited Claude enabled. Saved to ${persistedTo}.`,
        persistedTo,
      };
    }
    await rebuildShellRuntime(opts);
    return { enabled: true };
  }

  const { providerEnvVar, providerBaseUrlEnvVar, backendConfigSlot, persistLocalCredentials } =
    await import("../config.js");

  const providerLabel = choice.providerId;
  const apiKey = choice.kind === "api-key" ? choice.value : choice.apiKey;
  const baseUrl = choice.baseUrl;
  const persist = choice.persist === true;

  // Merge the new creds into the active backend slot so rebuildShellRuntime
  // can pick them up this session.
  const slotPatch: Record<string, string> = {};
  if (apiKey) slotPatch.apiKey = apiKey;
  if (baseUrl) slotPatch.baseUrl = baseUrl;
  mergeIntoActiveSlot(opts, slotPatch);

  // Export to env vars pi-ai will resolve when the runtime initializes.
  const envKey = providerEnvVar(providerLabel);
  if (envKey && apiKey) process.env[envKey] = apiKey;
  const envUrl = providerBaseUrlEnvVar(providerLabel);
  if (envUrl && baseUrl) process.env[envUrl] = baseUrl;

  await rebuildShellRuntime(opts);

  if (persist) {
    try {
      const targetCwd = opts.target ? path.resolve(opts.target) : process.cwd();
      const slot = backendConfigSlot(opts.config.agentRuntimeBackend);
      const writtenTo = persistLocalCredentials({ [slot]: slotPatch }, targetCwd);
      return {
        enabled: true,
        message: `Copilot enabled. ${providerLabel} credentials saved to ${writtenTo} (${slot} slot).`,
        persistedTo: writtenTo,
      };
    } catch (error) {
      const detail = toErrorMessage(error);
      return {
        enabled: true,
        message: `Copilot enabled (in-memory). Failed to persist credentials: ${detail}`,
      };
    }
  }

  return { enabled: true, message: `Copilot enabled for this session (${providerLabel}).` };
}

export function createShellSession(
  runtime: AgentRuntime,
  options: AgentQueryOptions,
): ShellSessionOutcome {
  if (!runtime.createSession) {
    return { session: undefined, error: DEFAULT_NO_SESSION_MESSAGE };
  }

  try {
    return {
      session: runtime.createSession(options),
    };
  } catch (error) {
    const detail = toErrorMessage(error);
    return {
      session: undefined,
      error: `Failed to create agent session: ${detail}`,
    };
  }
}

function buildSessionOptions(opts: ShellOptions, systemPrompt: string): AgentQueryOptions {
  return {
    cwd: opts.target ? path.resolve(opts.target) : process.cwd(),
    model: opts.config.model,
    allowedTools: SHELL_ALLOWED_TOOLS,
    permissionMode: "default",
    systemPromptPrefix: systemPrompt,
    effort: "high",
  };
}

function formatLabelValueRows(rows: Array<[string, string | null | undefined]>): string[] {
  const visibleRows = rows.filter(([, value]) => value != null && value !== "");
  if (visibleRows.length === 0) {
    return [];
  }

  const width = Math.max(...visibleRows.map(([label]) => label.length));
  return visibleRows.map(([label, value]) => `  ${label.padEnd(width)} ${value}`);
}

function formatCommandRows(rows: Array<[string, string]>): string[] {
  const width = Math.max(...rows.map(([label]) => label.length));
  return rows.map(([label, value]) => `  ${label.padEnd(width)} ${value}`);
}

function formatSections(sections: string[][]): string {
  const lines: string[] = [""];
  for (const section of sections.filter((value) => value.length > 0)) {
    if (lines[lines.length - 1] !== "") {
      lines.push("");
    }
    lines.push(...section);
  }
  lines.push("");
  return lines.join("\n");
}

function formatModuleDescription(description: string): string {
  const firstSentence = description.split(".")[0];
  return firstSentence.endsWith(".") ? firstSentence : `${firstSentence}.`;
}

function formatChoices(values: ReadonlyArray<string>, limit = 16): string {
  if (values.length === 0) return "(none)";
  const shown = values.slice(0, limit);
  const suffix = values.length > limit ? `, +${values.length - limit} more` : "";
  return `${shown.join(", ")}${suffix}`;
}

function formatModuleChoices(core: CopilotCore): string {
  return formatChoices(
    core
      .listModules()
      .map((module) => module.id)
      .sort(),
  );
}

function formatToolChoices(core: CopilotCore, focusedModule: string | null): string {
  const tools = core.registry
    .allTools()
    .map(({ tool }) => tool.name)
    .filter((name) => !focusedModule || name.startsWith(`${focusedModule}:`))
    .sort();
  return formatChoices(tools);
}

function formatSastTaskChoices(): string {
  return formatChoices(
    SAST_TASK_CAPABILITIES.map((capability) => capability.id),
    20,
  );
}

function parseCommand(input: string): { cmd: string; args: string[] } {
  const [cmd = "", ...args] = input.trim().split(/\s+/);
  return { cmd, args };
}

export type ShellInputTaxonomy =
  | "slash-meta"
  | "bare-compat-meta"
  | "module-action"
  | "agent-query"
  | "exit"
  | "empty";

const BARE_COMPAT_META_COMMANDS = new Set([
  "help",
  "modules",
  "m",
  "tools",
  "use",
  "back",
  "b",
  "findings",
  "f",
  "tune",
  "t",
  "kb",
  "attachments",
  "tasks",
  "story",
  "prompts",
  "resume",
  "options",
  "open",
]);

export function classifyShellInput(
  input: string,
  focusedModule: string | null = null,
): ShellInputTaxonomy {
  const trimmed = input.trim();
  if (!trimmed) return "empty";
  if (trimmed.startsWith("?")) return "agent-query";
  if (trimmed.startsWith("/")) return "slash-meta";
  const [verb = ""] = trimmed.toLowerCase().split(/\s+/, 1);
  if (verb === "exit" || verb === "quit" || verb === "q") return "exit";
  if (verb === "ask") return "agent-query";
  if (BARE_COMPAT_META_COMMANDS.has(verb)) return "bare-compat-meta";
  return focusedModule ? "module-action" : "module-action";
}

function toolActionName(toolName: string): string {
  return toolName.split(":")[1] ?? toolName;
}

function getToolProperties(tool: ModuleTool): Record<string, ToolPropertySchema> {
  const schema = tool.inputSchema;
  const properties = schema["properties"];
  if (!properties || typeof properties !== "object" || Array.isArray(properties)) {
    return {};
  }

  return Object.entries(properties).reduce<Record<string, ToolPropertySchema>>(
    (acc, [key, value]) => {
      if (value && typeof value === "object" && !Array.isArray(value)) {
        acc[key] = value as ToolPropertySchema;
      }
      return acc;
    },
    {},
  );
}

function getEffectiveToolProperties(
  tool: ModuleTool,
  config: KuzushiConfig,
): Record<string, ToolPropertySchema> {
  const properties = getToolProperties(tool);
  const modelKey = findOptionKey(properties, "model");
  const modelDescription = describeModelOverrideFormat(config.agentRuntimeBackend);
  if (modelKey) {
    return {
      ...properties,
      [modelKey]: {
        ...properties[modelKey],
        description: properties[modelKey]?.description || modelDescription,
      },
    };
  }
  return {
    ...properties,
    model: {
      type: "string",
      description: modelDescription,
      ...(config.model ? { default: config.model } : {}),
    },
  };
}

function findOptionKey(
  properties: Record<string, ToolPropertySchema>,
  optionKey: string,
): string | undefined {
  const normalized = optionKey.toUpperCase();
  return Object.keys(properties).find((key) => key.toUpperCase() === normalized);
}

function schemaAcceptsToolProperty(tool: ModuleTool, optionKey: string): boolean {
  const properties = getToolProperties(tool);
  if (findOptionKey(properties, optionKey)) return true;
  const additional = (tool.inputSchema as { additionalProperties?: unknown }).additionalProperties;
  return additional !== undefined && additional !== false;
}

function validateModelOptionValue(
  optionKey: string,
  value: unknown,
  config: KuzushiConfig,
): string | undefined {
  if (optionKey.toUpperCase() !== "MODEL") return undefined;
  if (typeof value !== "string") {
    return "Invalid value for model: expected a string.";
  }
  return validateModelOverride(config.agentRuntimeBackend, value) ?? undefined;
}

function readStoredModelOption(options: Record<string, unknown>): string | undefined {
  const modelKey = Object.keys(options).find((key) => key.toUpperCase() === "MODEL");
  const value = modelKey ? options[modelKey] : undefined;
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function readStoredEffortOption(options: Record<string, unknown>): string | undefined {
  const value = options["effort"];
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function readStoredThinkingDisabledOption(options: Record<string, unknown>): boolean | undefined {
  const thinking = options["thinking"];
  if (typeof thinking === "boolean") return !thinking;
  const thinkingDisabled = options["thinkingDisabled"];
  return typeof thinkingDisabled === "boolean" ? thinkingDisabled : undefined;
}

function stripSyntheticModelOptionFromInput(
  tool: ModuleTool,
  input: Record<string, unknown>,
): Record<string, unknown> {
  if (schemaAcceptsToolProperty(tool, "model")) return input;
  const next = { ...input };
  for (const key of Object.keys(next)) {
    if (key.toUpperCase() === "MODEL") {
      delete next[key];
    }
  }
  return next;
}

function createShellModelDatastore(
  config: KuzushiConfig,
  options: Record<string, unknown>,
): { datastore?: Datastore; error?: string } {
  const model = readStoredModelOption(options);
  if (!model) return {};
  const error = validateModelOverride(config.agentRuntimeBackend, model);
  if (error) return { error };
  const datastore = new Datastore();
  datastore.set("model", model);
  return { datastore };
}

function applyStoredShellOptionsToInput(
  tool: ModuleTool,
  input: Record<string, unknown>,
  storedOptions: Record<string, unknown> | undefined,
): Record<string, unknown> {
  if (!storedOptions || Object.keys(storedOptions).length === 0) return input;
  const next = { ...input };
  for (const [optionKey, value] of Object.entries(storedOptions)) {
    if (optionKey.toUpperCase() === "MODEL" && !schemaAcceptsToolProperty(tool, optionKey)) {
      continue;
    }
    next[optionKey] = value;
  }
  return next;
}

function resolveToolName(
  toolName: string,
  core: CopilotCore,
  focusedModule: string | null,
): string | undefined {
  // Thin adapter over the shared resolver — keeps the legacy signature that
  // callers in this file rely on (undefined on unresolved). For richer info
  // (ambiguous / path), use `resolveTool()` from `./dispatch/resolve-tool.js`
  // directly.
  const result = resolveTool({
    input: toolName,
    focusedModule,
    registry: core.registry,
  });
  return result.kind === "tool" ? result.toolName : undefined;
}

function formatUnknownToolMessage(toolName: string, core?: CopilotCore): string {
  const available = core ? core.registry.allTools().map((entry) => entry.tool.name) : [];
  return formatUnknownTool(toolName, available);
}

function formatValue(value: unknown): string {
  if (value == null || value === "") {
    return "—";
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return "—";
    }
    return value.map((item) => String(item)).join(",");
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}

function schemaIncludesType(schema: ToolPropertySchema | undefined, expected: string): boolean {
  if (!schema?.type) {
    return false;
  }
  const types = Array.isArray(schema.type) ? schema.type : [schema.type];
  return types.includes(expected);
}

function parseNumericValue(rawValue: string, integerOnly: boolean): number | undefined {
  if (!rawValue.trim()) {
    return undefined;
  }
  if (integerOnly) {
    if (!/^-?\d+$/.test(rawValue.trim())) {
      return undefined;
    }
    return Number.parseInt(rawValue, 10);
  }

  if (!/^-?\d+(\.\d+)?$/.test(rawValue.trim())) {
    return undefined;
  }
  return Number.parseFloat(rawValue);
}

function coerceOptionValue(rawValue: string, schema: ToolPropertySchema): unknown {
  if (schemaIncludesType(schema, "array")) {
    const itemSchema = schema.items ?? {};
    return rawValue
      .split(",")
      .map((value) => value.trim())
      .filter((value) => value.length > 0)
      .map((value) => coerceOptionValue(value, itemSchema));
  }

  if (schemaIncludesType(schema, "boolean")) {
    if (rawValue === "true") return true;
    if (rawValue === "false") return false;
  }

  if (schemaIncludesType(schema, "integer")) {
    const parsed = parseNumericValue(rawValue, true);
    if (parsed !== undefined) {
      return parsed;
    }
  }

  if (schemaIncludesType(schema, "number")) {
    const parsed = parseNumericValue(rawValue, false);
    if (parsed !== undefined) {
      return parsed;
    }
  }

  return rawValue;
}

function validateOptionValue(
  optionKey: string,
  value: unknown,
  schema: ToolPropertySchema,
): string | undefined {
  const enumValues = Array.isArray(schema.enum) ? schema.enum : undefined;
  if (!enumValues) {
    return undefined;
  }

  const values = Array.isArray(value) ? value : [value];
  const invalid = values.find((item) => !enumValues.some((candidate) => candidate === item));
  if (invalid === undefined) {
    return undefined;
  }

  return `Invalid value for ${optionKey}: ${formatValue(invalid)}. Allowed: ${enumValues.map((item) => String(item)).join(", ")}`;
}

function validateOptionType(
  optionKey: string,
  value: unknown,
  schema: ToolPropertySchema,
): string | undefined {
  if (schemaIncludesType(schema, "array") && !Array.isArray(value)) {
    return `Invalid value for ${optionKey}: expected a comma-separated list.`;
  }
  if (schemaIncludesType(schema, "boolean") && typeof value !== "boolean") {
    return `Invalid value for ${optionKey}: expected true or false.`;
  }
  if (schemaIncludesType(schema, "integer") && !Number.isInteger(value)) {
    return `Invalid value for ${optionKey}: expected an integer.`;
  }
  if (schemaIncludesType(schema, "number") && typeof value !== "number") {
    return `Invalid value for ${optionKey}: expected a number.`;
  }
  return undefined;
}

function formatOptionDescription(schema: ToolPropertySchema): string {
  const description = schema.description?.trim() ?? "";
  const enumValues = Array.isArray(schema.enum) ? schema.enum : undefined;
  if (!enumValues || enumValues.length === 0) {
    return description || "—";
  }

  const suffix = enumValues.map((item) => String(item)).join(" | ");
  return description ? `${description} (${suffix})` : suffix;
}

function resolveFrameworkVersion(): string {
  try {
    const url = new URL("../../package.json", import.meta.url);
    const pkg = JSON.parse(readFileSync(url, "utf8")) as { version?: string };
    return pkg.version ?? "dev";
  } catch {
    return "dev";
  }
}

function resolveAuditLogPath(
  config: KuzushiConfig | undefined,
  dataDir: string,
): string | undefined {
  const auditLog = (config as { auditLog?: string | boolean } | undefined)?.auditLog;
  if (!auditLog) return undefined;
  if (typeof auditLog === "string") return auditLog;
  return path.join(dataDir, "audit.log");
}

function filteredWorkspaceListing(
  mgr: import("../workspace/manager.js").WorkspaceManager,
  pattern: string,
  activeId: string | undefined,
): { output: string } {
  let regex: RegExp;
  try {
    regex = new RegExp(pattern, "i");
  } catch {
    return { output: `[-] Invalid regex: ${pattern}` };
  }
  const rows = mgr
    .list()
    .filter((ws) => regex.test(ws.name))
    .map((ws) => {
      const active = ws.id === activeId ? " *" : "  ";
      const targets = ws.targets.join(", ") || "no targets";
      return `${active}${ws.name}  —  ${targets}`;
    });
  return {
    output: rows.length === 0 ? `  (no matches for /${pattern}/i)` : rows.join("\n"),
  };
}

function formatHistory(commandHistory: string[]): string {
  const entries = commandHistory.slice(-50);
  if (entries.length === 0) {
    return "  No command history yet.";
  }

  const start = commandHistory.length - entries.length + 1;
  const width = String(start + entries.length - 1).length;
  return formatSections([
    [
      "  Command History",
      ...entries.map((entry, index) => `  ${String(start + index).padStart(width)}  ${entry}`),
    ],
  ]);
}

function recordLocalUsageEvent(
  dataDir: string | undefined,
  event: {
    type: "command";
    timestamp: string;
    command: string;
    surface: CommandSurfaceKind;
    view?: string;
    outcome: "started" | "succeeded" | "failed" | "cancelled";
  },
): void {
  if (!dataDir || process.env["KUZUSHI_DISABLE_LOCAL_ANALYTICS"] === "1") return;
  try {
    mkdirSync(dataDir, { recursive: true });
    appendFileSync(path.join(dataDir, "usage.jsonl"), `${JSON.stringify(event)}\n`, "utf8");
  } catch {
    // Usage telemetry is local and best-effort; it must never block a command.
  }
}

function recordCommandUsage(ctx: ShellContext, shellState: ShellState, command: string): void {
  const metadata = getCommandMetadata(command);
  const normalized = command.replace(/^\//, "").trim().split(/\s+/)[0]?.toLowerCase() ?? command;
  recordLocalUsageEvent(ctx.dataDir, {
    type: "command",
    timestamp: new Date().toISOString(),
    command: normalized,
    surface: metadata.surface,
    view: shellState.shellView,
    outcome: "started",
  });
}

function updateShell(store: UIStore, updater: (shell: ShellState) => ShellState): void {
  const shell = store.getState().shell;
  if (!shell) return;
  store.update({ shell: updater(shell) });
}

function appendToHistory(store: UIStore, entry: ShellHistoryEntry): void {
  updateShell(store, (shell) => ({
    ...shell,
    history: [...shell.history, entry],
  }));
}

export function shouldAppendSeparateBodyOutput(
  bodyOutput: string | undefined,
  completionSummary: string | undefined,
): boolean {
  const body = bodyOutput?.trim();
  if (!body) return false;
  const summary = completionSummary?.trim();
  if (!summary) return true;
  if (body === summary) return false;
  const firstLine = body.split(/\r?\n/, 1)[0]?.trim();
  const rest = body.slice(firstLine?.length ?? 0).trim();
  return !(firstLine === summary && rest.length === 0);
}

function latestToolCallResultOutput(shell: ShellState | null | undefined): string | undefined {
  const history = shell?.history ?? [];
  for (let i = history.length - 1; i >= 0; i -= 1) {
    const entry = history[i];
    if (entry?.type === "tool-call" && entry.resultOutput) {
      return entry.resultOutput;
    }
  }
  return undefined;
}

interface StoryAppendOptions {
  persistHistory?: boolean;
  liveOnly?: boolean;
}

function applyStoryEventToShell(
  shell: ShellState,
  event: ShellStoryEvent,
  options: StoryAppendOptions = {},
): ShellState {
  const currentTurnId = shell.taskStory?.activeTurnId;
  if (event.turnId && currentTurnId && event.turnId !== currentTurnId && event.source !== "jobs") {
    return shell;
  }
  const activeRunIds =
    event.runId && !shell.taskStory?.activeRunIds.includes(event.runId)
      ? [...(shell.taskStory?.activeRunIds ?? []), event.runId]
      : (shell.taskStory?.activeRunIds ?? []);
  const terminalStory =
    event.status === "fail" || event.status === "aborted" || event.kind === "result"
      ? isTerminalStoryStatus(event.status)
      : false;
  const nextStory = {
    activeTurnId: event.turnId ?? shell.taskStory?.activeTurnId,
    activeRunIds,
    startedAt: shell.taskStory?.startedAt ?? event.timestamp,
    endedAt: terminalStory ? event.timestamp : shell.taskStory?.endedAt,
    abortStatus:
      event.status === "aborting"
        ? ("aborting" as const)
        : event.status === "aborted"
          ? ("aborted" as const)
          : (shell.taskStory?.abortStatus ?? ("idle" as const)),
    abortReason:
      event.status === "aborted"
        ? (event.detail ?? shell.taskStory?.abortReason)
        : shell.taskStory?.abortReason,
    backgroundJobs: shell.taskStory?.backgroundJobs,
    events: appendCuratedStoryEvent(shell.taskStory?.events ?? [], event),
  };
  let nextShell: ShellState = {
    ...shell,
    taskStory: nextStory,
  };

  if (shell.currentTool) {
    nextShell = {
      ...nextShell,
      currentTool: {
        ...shell.currentTool,
        storyTail: appendStoryTail(shell.currentTool.storyTail, event),
        abortStatus: nextStory.abortStatus,
        ...(event.runId ? { runId: event.runId } : {}),
        ...(event.kind === "phase" ? { phase: event.message, subLabel: event.message } : {}),
        lastEventAt: event.timestamp,
      },
    };
  }

  const shouldPersist = options.persistHistory ?? shouldPersistStoryEvent(event);
  if (!options.liveOnly && shouldPersist) {
    nextShell = {
      ...nextShell,
      history: [
        ...nextShell.history,
        {
          type: "story",
          text: formatStoryEventPlain(event),
          timestamp: event.timestamp,
          storyEvent: event,
          ...(event.status === "aborted" ? { abortStatus: "aborted" as const } : {}),
        },
      ],
    };
  }
  return nextShell;
}

function appendStoryEvent(
  store: UIStore,
  draft: ShellStoryEventDraft,
  options: StoryAppendOptions = {},
): ShellStoryEvent {
  const event = createShellStoryEvent(draft);
  updateShell(store, (shell) => applyStoryEventToShell(shell, event, options));
  return event;
}

function updateBackgroundJobStory(store: UIStore, job: ShellTaskBackgroundJob): void {
  updateShell(store, (shell) => ({
    ...shell,
    taskStory: {
      activeTurnId: shell.taskStory?.activeTurnId,
      activeRunIds: shell.taskStory?.activeRunIds ?? [],
      startedAt: shell.taskStory?.startedAt ?? job.startedAt,
      endedAt: shell.taskStory?.endedAt,
      abortStatus: shell.taskStory?.abortStatus ?? "idle",
      abortReason: shell.taskStory?.abortReason,
      backgroundJobs: upsertBackgroundJob(shell.taskStory?.backgroundJobs, job),
      events: shell.taskStory?.events ?? [],
    },
  }));
  appendStoryEvent(store, createBackgroundJobStoryEvent(job));
}

/**
 * Mutate an existing history entry in place by id. Used by the tool-call
 * lifecycle to flip `status: "running" → "ok" | "fail" | "abort"` and
 * inject a `resultOutput` once the dispatcher resolves the tool. Silently
 * no-ops when the id isn't found so bus subscriptions can fire lazily
 * without ordering hazards.
 */
function patchHistoryEntry(store: UIStore, id: string, patch: Partial<ShellHistoryEntry>): void {
  updateShell(store, (shell) => {
    const idx = shell.history.findIndex((entry) => entry.id === id);
    if (idx < 0) return shell;
    const next = shell.history.slice();
    next[idx] = { ...next[idx]!, ...patch };
    return { ...shell, history: next };
  });
}

/**
 * Safety-net: sweep the history for any tool-call entries still marked
 * `status: "running"` and flip them to `status` + optional `resultOutput`.
 * Called at turn boundaries so an aborted / errored turn doesn't leave
 * agent-driven `⏺` entries pulsing forever.
 */
function finalizeRunningToolCalls(
  store: UIStore,
  status: "ok" | "fail" | "abort",
  resultOutput?: string,
): void {
  updateShell(store, (shell) => {
    let mutated = false;
    const next = shell.history.map((entry) => {
      if (entry.type !== "tool-call" || entry.status !== "running") return entry;
      mutated = true;
      return {
        ...entry,
        status,
        ...(status === "abort" ? { abortStatus: "aborted" as const } : {}),
        ...(resultOutput ? { resultOutput } : {}),
        liveActivities: undefined,
        liveActivitiesDropped: undefined,
      };
    });
    return mutated ? { ...shell, history: next } : shell;
  });
}

/**
 * Push a short activity line onto a running tool-call's `liveActivities`
 * tail (newest at index 0). Silently no-ops when the id isn't a running
 * tool-call.
 */
const LIVE_ACTIVITY_CAP = 64;
const LIVE_ACTIVITY_TEXT_CAP = 80;
const LIVE_ACTIVITY_THROTTLE_MS = 100;
let liveActivitySeq = 0;
function pushLiveActivity(store: UIStore, id: string, text: string): void {
  const trimmed =
    text.length > LIVE_ACTIVITY_TEXT_CAP ? `${text.slice(0, LIVE_ACTIVITY_TEXT_CAP - 1)}…` : text;
  updateShell(store, (shell) => {
    const idx = shell.history.findIndex((entry) => entry.id === id);
    if (idx < 0) return shell;
    const entry = shell.history[idx]!;
    if (entry.type !== "tool-call" || entry.status !== "running") return shell;
    const prev = entry.liveActivities ?? [];
    // Dedupe consecutive identical text — no point pushing "scanning X"
    // three times in a row.
    if (prev[0]?.text === trimmed) return shell;
    const rawActivities = [{ id: `la-${Date.now()}-${liveActivitySeq++}`, text: trimmed }, ...prev];
    const dropped = Math.max(0, rawActivities.length - LIVE_ACTIVITY_CAP);
    const nextActivities = rawActivities.slice(0, LIVE_ACTIVITY_CAP);
    const next = shell.history.slice();
    next[idx] = {
      ...entry,
      liveActivities: nextActivities,
      liveActivitiesDropped: (entry.liveActivitiesDropped ?? 0) + dropped,
    };
    return { ...shell, history: next };
  });
}

interface PendingTaskOutput {
  entryId?: string;
  text: string;
  story?: ShellStoryEventDraft;
}

const pendingTaskOutputByStore = new WeakMap<
  UIStore,
  {
    latest?: PendingTaskOutput;
    lastFlushAt: number;
    timer?: ReturnType<typeof setTimeout>;
  }
>();

function pushTaskOutputThrottled(store: UIStore, output: PendingTaskOutput): void {
  const state = pendingTaskOutputByStore.get(store) ?? { lastFlushAt: 0 };
  state.latest = output;
  const now = Date.now();
  const flush = () => {
    state.timer = undefined;
    const latest = state.latest;
    state.latest = undefined;
    state.lastFlushAt = Date.now();
    if (!latest) return;
    if (latest.entryId) pushLiveActivity(store, latest.entryId, latest.text);
    if (latest.story) {
      appendStoryEvent(store, latest.story, { persistHistory: false, liveOnly: true });
    }
  };

  if (now - state.lastFlushAt >= LIVE_ACTIVITY_THROTTLE_MS && !state.timer) {
    pendingTaskOutputByStore.set(store, state);
    flush();
    return;
  }

  if (!state.timer) {
    state.timer = setTimeout(
      flush,
      Math.max(1, LIVE_ACTIVITY_THROTTLE_MS - (now - state.lastFlushAt)),
    );
    state.timer.unref?.();
  }
  pendingTaskOutputByStore.set(store, state);
}

/**
 * Tool names whose completion drains `state.lastHuntSnapshot` into a
 * `hunt-post-mortem` scrollback block. Currently just carlini-threat-hunt:run;
 * add other hunt-class tools here when they adopt the per-actor
 * `reportAgentActivity` + `done:true` pattern.
 */
const HUNT_CLASS_TOOLS = new Set([
  "carlini-threat-hunt:run",
  "taint-iris:hunt",
  "taint-iris-next:hunt",
]);

function isHuntClassTool(toolName: string): boolean {
  return HUNT_CLASS_TOOLS.has(toolName);
}

interface HuntStats {
  findingsCount: number;
  reviewCandidateCount: number;
  costUsd: number;
  agentRuntimeBackend?: string;
  agentStatus?: string;
  candidateCount?: number;
  linkedStoryCount?: number;
  backendPathCount?: number;
  warningCount?: number;
}

/**
 * Read `totalFindings` + `totalCostUsd` off a hunt tool's `ToolResult.data`.
 * `runSingleTaskPipeline` populates these under `data.stats`; the unknown
 * cast is guarded by runtime shape checks so a shape drift produces zeros
 * rather than a crash.
 */
function extractHuntStats(result: { data?: unknown }): HuntStats {
  const data = result.data as
    | {
        stats?: {
          totalFindings?: unknown;
          totalReviewCandidates?: unknown;
          totalCostUsd?: unknown;
          totalCandidates?: unknown;
          totalLinkedStories?: unknown;
          backendPathCount?: unknown;
        };
        agentRuntimeBackend?: unknown;
        agentStatus?: unknown;
        warnings?: unknown;
      }
    | undefined;
  const stats = data?.stats;
  const findingsCount =
    typeof stats?.totalFindings === "number" && Number.isFinite(stats.totalFindings)
      ? stats.totalFindings
      : 0;
  const reviewCandidateCount =
    typeof stats?.totalReviewCandidates === "number" && Number.isFinite(stats.totalReviewCandidates)
      ? stats.totalReviewCandidates
      : 0;
  const costUsd =
    typeof stats?.totalCostUsd === "number" && Number.isFinite(stats.totalCostUsd)
      ? stats.totalCostUsd
      : 0;
  const candidateCount = finiteOptionalNumber(stats?.totalCandidates);
  const linkedStoryCount = finiteOptionalNumber(stats?.totalLinkedStories);
  const backendPathCount = finiteOptionalNumber(stats?.backendPathCount);
  const warningCount = Array.isArray(data?.warnings) ? data.warnings.length : undefined;
  return {
    findingsCount,
    reviewCandidateCount,
    costUsd,
    ...(typeof data?.agentRuntimeBackend === "string"
      ? { agentRuntimeBackend: data.agentRuntimeBackend }
      : {}),
    ...(typeof data?.agentStatus === "string" ? { agentStatus: data.agentStatus } : {}),
    ...(candidateCount !== undefined ? { candidateCount } : {}),
    ...(linkedStoryCount !== undefined ? { linkedStoryCount } : {}),
    ...(backendPathCount !== undefined ? { backendPathCount } : {}),
    ...(warningCount !== undefined ? { warningCount } : {}),
  };
}

function finiteOptionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function formatHuntSummaryLine(
  actorCount: number,
  findingsCount: number,
  costUsd: number,
  reviewCandidateCount = 0,
  agentStatus?: string,
): string {
  const actorsLabel = `${actorCount} actor${actorCount === 1 ? "" : "s"}`;
  const findingsLabel = `${findingsCount} finding${findingsCount === 1 ? "" : "s"}`;
  const reviewLabel =
    reviewCandidateCount > 0
      ? ` · ${reviewCandidateCount} review candidate${reviewCandidateCount === 1 ? "" : "s"}`
      : "";
  const agentLabel = agentStatus ? ` · ${agentStatus}` : "";
  const costLabel = `$${costUsd.toFixed(2)}`;
  return `${actorsLabel} · ${findingsLabel}${reviewLabel}${agentLabel} · ${costLabel}`;
}

function formatHuntActorLabel(fingerprint: string): string {
  const parts = fingerprint.split(":");
  if (parts.length < 3) return fingerprint;
  const actorSlug = parts[parts.length - 2]!.replace(/_/g, " ");
  const runIndex = parts[parts.length - 1]!;
  return runIndex === "0" ? actorSlug : `${actorSlug} (run ${runIndex})`;
}

function formatAgentActivityStory(payload: import("../bus/events.js").TaskAgentActivityPayload): {
  message: string;
  detail?: string;
  kind: ShellStoryEventDraft["kind"];
} {
  const actor = formatHuntActorLabel(payload.fingerprint);
  const summary = payload.summary?.trim();
  const tool = payload.toolName?.trim();
  if (payload.done) {
    return {
      kind: "result",
      message: `${actor} finished`,
      ...(summary ? { detail: summary } : {}),
    };
  }
  if (payload.kind === "tool-start") {
    return {
      kind: "tool",
      message: tool ? `${actor} using ${tool}` : `${actor} using tool`,
      ...(summary ? { detail: summary } : {}),
    };
  }
  if (payload.kind === "tool-complete") {
    return {
      kind: "tool",
      message: tool ? `${actor} completed ${tool}` : `${actor} completed tool`,
      ...(summary ? { detail: summary } : {}),
    };
  }
  if (payload.kind === "reasoning") {
    return {
      kind: "activity",
      message: `${actor} reasoning`,
      ...(summary ? { detail: summary } : {}),
    };
  }
  return {
    kind: "activity",
    message: `${actor} working`,
    ...((summary ?? tool) ? { detail: summary ?? tool } : {}),
  };
}

function moduleRunOwnsCarliniThreatHuntActivity(shell: ShellState | null | undefined): boolean {
  return (
    shell?.moduleRun?.toolName === "carlini-threat-hunt:run" &&
    shell.moduleRun.status === "running" &&
    (shell.shellView === "module-run" || shell.shellView === "actor-detail")
  );
}

function beginShellTurn(
  store: UIStore,
  input: string,
  focusedModule: string | null,
  turnId: string,
  options: { preserveTaskStory?: boolean; processing?: boolean } = {},
): void {
  // Stale notices from the previous turn (e.g. "Review complete" from a just-
  // finished scan) shouldn't linger into the next command's output window —
  // they visually attach themselves to unrelated views (module home, catalog)
  // and confuse operators about what just happened. Clear before the new
  // turn's own notices can accumulate.
  store.clearNotices();
  updateShell(store, (shell) => ({
    ...shell,
    history: [
      ...shell.history,
      {
        type: "input",
        text: input,
        prompt: buildShellPrompt(focusedModule),
        timestamp: Date.now(),
      },
    ],
    commandHistory: capShellHistory([...shell.commandHistory, input]),
    processing: options.processing ?? true,
    pendingAssistantText: undefined,
    currentTool: undefined,
    llmHeartbeat: undefined,
    taskStory: options.preserveTaskStory
      ? shell.taskStory
      : {
          activeTurnId: turnId,
          activeRunIds: [],
          startedAt: Date.now(),
          abortStatus: "idle",
          backgroundJobs: shell.taskStory?.backgroundJobs,
          events: [],
        },
  }));
}

function setProcessing(store: UIStore, processing: boolean): void {
  updateShell(store, (shell) => ({
    ...shell,
    processing,
  }));
}

const INITIAL_PROCESSING_COMMANDS = new Set([
  "ask",
  "auth",
  "config",
  "connect",
  "context",
  "load",
  "logs",
  "macro",
  "prompt",
  "replay",
  "resume",
  "resource",
  "sleep",
  "trace",
  "wait_for",
]);

function shouldStartTurnBusy(
  input: string,
  core: CopilotCore,
  focusedModule: string | null,
): boolean {
  const trimmed = input.trim();
  if (!trimmed) return false;
  if (trimmed.startsWith("?")) return true;

  const { cmd, args } = parseCommand(trimmed);
  const command = cmd.replace(/^\//, "").toLowerCase();
  if (INITIAL_PROCESSING_COMMANDS.has(command)) return true;
  if (command === "recipes" && args[0]?.toLowerCase() === "run") return true;
  if (cmd.includes(":")) return true;
  if (focusedModule && core.registry.resolveTool(`${focusedModule}:${cmd}`)) return true;
  return !!resolveToolName(cmd, core, null);
}

function setAbortHandler(store: UIStore, onAbort?: () => void): void {
  updateShell(store, (shell) => ({
    ...shell,
    onAbort,
  }));
}

function markAbortRequested(store: UIStore, reason: string): void {
  const now = Date.now();
  const shell = store.getState().shell;
  appendStoryEvent(
    store,
    createAbortStoryEvent(reason, "aborting", {
      ...(shell?.taskStory?.activeTurnId ? { turnId: shell.taskStory.activeTurnId } : {}),
      ...(shell?.currentTool?.runId ? { runId: shell.currentTool.runId } : {}),
      ...(shell?.currentTool?.name ? { source: shell.currentTool.name } : {}),
    }),
  );
  updateShell(store, (shell) => ({
    ...shell,
    taskStory: {
      activeTurnId: shell.taskStory?.activeTurnId,
      activeRunIds: shell.taskStory?.activeRunIds ?? [],
      startedAt: shell.taskStory?.startedAt ?? now,
      events: shell.taskStory?.events ?? [],
      abortStatus: "aborting",
      abortReason: reason,
      backgroundJobs: shell.taskStory?.backgroundJobs,
    },
    currentTool: shell.currentTool
      ? {
          ...shell.currentTool,
          abortStatus: "aborting",
          lastEventAt: now,
        }
      : shell.currentTool,
  }));
}

function markAbortSettled(store: UIStore, reason: string): void {
  const shell = store.getState().shell;
  appendStoryEvent(
    store,
    createAbortStoryEvent(reason, "aborted", {
      ...(shell?.taskStory?.activeTurnId ? { turnId: shell.taskStory.activeTurnId } : {}),
      ...(shell?.currentTool?.runId ? { runId: shell.currentTool.runId } : {}),
      ...(shell?.currentTool?.name ? { source: shell.currentTool.name } : {}),
    }),
  );
  updateShell(store, (shell) => ({
    ...shell,
    taskStory: shell.taskStory
      ? {
          ...shell.taskStory,
          abortStatus: "aborted",
          abortReason: reason,
          endedAt: Date.now(),
        }
      : shell.taskStory,
    currentTool: shell.currentTool
      ? {
          ...shell.currentTool,
          abortStatus: "aborted",
          lastEventAt: Date.now(),
        }
      : shell.currentTool,
  }));
}

/**
 * Re-enable stdin raw mode if it's been turned off. The Claude Agent SDK
 * subprocess (used by `randori` and friends) opens `/dev/tty` and disables
 * raw mode on the parent; when it exits it doesn't restore it. Once raw
 * mode is off, Ink's `useInput` stops receiving Ctrl+C as `0x03` and the
 * terminal falls back to line-buffered cooked mode — typed characters echo
 * below the Ink frame, which is exactly what the user reported.
 *
 * Calling this after every turn edge (abort handler, finally block around
 * driver.handle / agent query) closes the window. Do not trust
 * `stdin.isRaw`: subprocesses can change terminal mode through another
 * `/dev/tty` fd without updating Node's cached flag.
 */
/**
 * Opt-in tracer for the abort path. Enable with `KUZUSHI_ABORT_DEBUG=1`.
 * Writes to stderr so Ink's scrollback isn't disturbed (Ink owns stdout).
 * Use to pinpoint which hop of the Ctrl+C chain actually fires in a repro.
 */
function abortDebug(msg: string): void {
  if (!process.env.KUZUSHI_ABORT_DEBUG) return;
  try {
    process.stderr.write(`[abort] ${msg}\n`);
  } catch {
    /* best-effort */
  }
}

function ensureRawMode(): void {
  const stdin = process.stdin as NodeJS.ReadStream & {
    isRaw?: boolean;
    setRawMode?: (mode: boolean) => void;
  };
  if (!stdin.isTTY || !stdin.setRawMode) return;
  try {
    stdin.setRawMode(true);
  } catch {
    /* best-effort — terminal may be in a weird state */
  }
}

function setPendingAssistantText(store: UIStore, text: string | undefined): void {
  updateShell(store, (shell) => ({
    ...shell,
    pendingAssistantText: text,
  }));
}

function appendPendingAssistantText(store: UIStore, text: string): void {
  if (!text) return;
  updateShell(store, (shell) => ({
    ...shell,
    pendingAssistantText: `${shell.pendingAssistantText ?? ""}${text}`,
  }));
}

/**
 * Keep `shellView` consistent with `focusedModule`. The `/use <mod>` slash
 * path sets shellView="module" via its own updater, but the bare dispatcher
 * path (`use <mod>`) only pushes a ModuleDispatcher and lands here with
 * shellView still "catalog" — which makes the StatusFooter lie ("you are
 * in catalog" while the prompt reads `kuzushi/<mod>>`). Mirror the
 * module-scoped views `/back` already recognises so we don't clobber an
 * explicit `/findings`, `/tune`, finding detail, or threat-* sub-view.
 */
export function reconcileShellView(
  currentView: ShellView,
  focusedModule: string | null,
): ShellView {
  if (focusedModule && currentView === "catalog") return "module";
  if (
    !focusedModule &&
    (currentView === "module" || currentView === "tune" || currentView === "options")
  ) {
    return "catalog";
  }
  return currentView;
}

export function reconcileShellViewAfterFocusChange(
  currentView: ShellView,
  focusedModule: string | null,
): ShellView {
  if (focusedModule && (currentView === "catalog" || currentView === "threats")) return "module";
  return reconcileShellView(currentView, focusedModule);
}

export function reconcileShellViewAfterPlainOutput(
  currentView: ShellView,
  focusedModule: string | null,
  input: string,
): ShellView {
  if (currentView !== "threats") return currentView;
  if (preservesThreatViewForPlainOutput(input)) return currentView;
  return focusedModule ? "module" : "catalog";
}

function preservesThreatViewForPlainOutput(input: string): boolean {
  const lower = input.trim().toLowerCase();
  if (!lower) return true;
  if (/^\/?threats(?:\s|$)/.test(lower)) return true;
  if (/^\/?context\s+dfd(?:\s|$)/.test(lower)) return true;
  if (/^\/?context\s+(?:regen|regenerate)(?:\s|$)/.test(lower)) return true;
  if (lower === "dfd") return true;
  if (lower === "/back" || lower === "/b") return true;
  if (/^[1-5]$/.test(lower)) return true;
  return false;
}

function withPlainOutputShellViewReconciliation(
  result: LocalCommandResult,
  input: string,
  focusedModule: string | null,
  shellState: ShellState,
): LocalCommandResult {
  if (!result.output) return result;
  const nextView = reconcileShellViewAfterPlainOutput(shellState.shellView, focusedModule, input);
  if (nextView === shellState.shellView) return result;
  const priorUpdater = result.shellStateUpdater;
  return {
    ...result,
    shellStateUpdater: (shell) => {
      const next = priorUpdater ? priorUpdater(shell) : shell;
      return { ...next, shellView: nextView };
    },
  };
}

function syncShellState(
  store: UIStore,
  opts: ShellOptions,
  focusedModule: string | null,
  workspaceManager?: import("../workspace/manager.js").WorkspaceManager,
): void {
  updateShell(store, (shell) => ({
    ...shell,
    focusedModule,
    shellView: reconcileShellView(shell.shellView, focusedModule),
    target: opts.target ?? null,
    workspace: workspaceDisplayName(opts, workspaceManager),
  }));
}

function updateToolActivity(store: UIStore, toolName: string, elapsedSeconds: number): void {
  updateShell(store, (shell) => {
    const prev = shell.currentTool;
    const sameTool = prev && prev.name === toolName;
    return {
      ...shell,
      currentTool: {
        name: toolName,
        elapsedSeconds,
        startedAt: sameTool ? prev.startedAt : Date.now(),
        phase: sameTool ? prev.phase : undefined,
        step: sameTool ? prev.step : undefined,
        total: sameTool ? prev.total : undefined,
        subLabel: sameTool ? prev.subLabel : undefined,
        activities: sameTool ? prev.activities : undefined,
        storyTail: sameTool ? prev.storyTail : undefined,
        abortStatus: sameTool ? prev.abortStatus : undefined,
        turnId: sameTool ? prev.turnId : undefined,
        historyEntryId: sameTool ? prev.historyEntryId : undefined,
        displayName: sameTool ? prev.displayName : undefined,
        lastEventAt: Date.now(),
        runId: sameTool ? prev.runId : undefined,
        backgroundJobId: sameTool ? prev.backgroundJobId : undefined,
        backgrounded: sameTool ? prev.backgrounded : undefined,
      },
    };
  });
}

const PHASE_COUNT_RE = /\((\d+)\s*\/\s*(\d+)\)/;
const PROGRESS_EVENT_THROTTLE_MS = 100;

/**
 * Update the current tool's phase label. Parses a trailing "(N/M)" into
 * step/total so the UI can render a separate "phase 2/15" strip.
 */
function pushToolPhase(store: UIStore, phase: string): void {
  const match = phase.match(PHASE_COUNT_RE);
  const step = match ? Number(match[1]) : undefined;
  const total = match ? Number(match[2]) : undefined;
  updateShell(store, (shell) => {
    if (!shell.currentTool) return shell;
    return {
      ...shell,
      currentTool: {
        ...shell.currentTool,
        phase,
        step,
        total,
        subLabel: phase,
        lastEventAt: Date.now(),
      },
    };
  });
}

const ACTIVITY_BUFFER_CAP = 5;
const ACTIVITY_TEXT_CAP = 80;

/**
 * Prepend a new activity line to the rolling tail. Dedupes by matching the
 * most recent entry's text (just bumps its timestamp) and caps the buffer.
 */
function pushToolActivity(store: UIStore, text: string): void {
  const trimmed =
    text.length > ACTIVITY_TEXT_CAP ? `${text.slice(0, ACTIVITY_TEXT_CAP - 1)}…` : text;
  const now = Date.now();
  updateShell(store, (shell) => {
    if (!shell.currentTool) return shell;
    const prev = shell.currentTool.activities ?? [];
    let next: ToolActivityLine[];
    if (prev[0]?.text === trimmed) {
      next = [{ text: trimmed, ts: now }, ...prev.slice(1)];
    } else {
      next = [{ text: trimmed, ts: now }, ...prev].slice(0, ACTIVITY_BUFFER_CAP);
    }
    return {
      ...shell,
      currentTool: {
        ...shell.currentTool,
        activities: next,
        lastEventAt: now,
      },
    };
  });
}

/**
 * Batch-apply progress updates from `task:phase-progress` / `task:activity`
 * in a single store mutation. This avoids 3-4 independent `store.update()`
 * calls per bus event (phase + activity + live tail + scrollback), which
 * caused visible Ink redraw flicker during noisy module runs.
 */
/**
 * Stamp the in-flight phase's most recent `tool-progress` entry with its
 * elapsed time, so the scrollback reads as a finalized build log:
 * `scanning repo structure · 3s`. Safe to call when no phase is active —
 * it's a no-op.
 */
function finalizeCurrentPhase(store: UIStore, outcome: "ok" | "fail" | "abort"): void {
  updateShell(store, (shell) => {
    const current = shell.currentTool;
    if (!current?.phase) return shell;
    const startedAt = current.phaseStartedAt ?? current.startedAt;
    if (!startedAt) return shell;
    const elapsedLabel = formatDuration(Math.max(0, Date.now() - startedAt));
    const hist = shell.history;
    for (let i = hist.length - 1; i >= 0; i--) {
      const entry = hist[i]!;
      if (entry.type !== "tool-progress") continue;
      if (entry.text !== current.phase) continue;
      // Already finalized (has a " · " elapsed suffix)? Leave it alone so
      // repeat calls are idempotent.
      if (entry.progressKind === "ok" || entry.progressKind === "fail") return shell;
      const nextHistory = hist.slice();
      nextHistory[i] = {
        ...entry,
        text: `${current.phase} · ${elapsedLabel}`,
        progressKind: outcome === "fail" ? "fail" : outcome === "abort" ? "info" : "ok",
      };
      return { ...shell, history: nextHistory };
    }
    return shell;
  });
}

interface AppendProgressEventInput {
  text: string;
  kind?: ShellHistoryEntry["progressKind"];
  phase?: string;
  activity?: string;
  liveActivity?: string;
  story?: ShellStoryEventDraft;
  /**
   * When true, skip appending a `tool-progress` history entry but still
   * update `currentTool.activities` + the running tool's `liveActivities`
   * tail. Used to suppress the scrollback echo of sub-agent tool-call-
   * start / tool_use lines whose summaries are already captured by the
   * matching `tool-summary` row.
   */
  skipHistory?: boolean;
}

function appendProgressEvent(store: UIStore, event: AppendProgressEventInput): void {
  const now = Date.now();
  const progressText = event.text;
  const phase = event.phase;
  const activity = event.activity;
  const liveActivity = event.liveActivity;
  const phaseMatch = phase ? phase.match(PHASE_COUNT_RE) : null;
  const phaseStep = phaseMatch ? Number(phaseMatch[1]) : undefined;
  const phaseTotal = phaseMatch ? Number(phaseMatch[2]) : undefined;
  const trimmedActivity =
    activity && activity.length > ACTIVITY_TEXT_CAP
      ? `${activity.slice(0, ACTIVITY_TEXT_CAP - 1)}…`
      : activity;
  const trimmedLiveActivity =
    liveActivity && liveActivity.length > LIVE_ACTIVITY_TEXT_CAP
      ? `${liveActivity.slice(0, LIVE_ACTIVITY_TEXT_CAP - 1)}…`
      : liveActivity;
  const storyEvent = event.story ? createShellStoryEvent(event.story, now) : undefined;

  updateShell(store, (shell) => {
    let nextShell: ShellState = shell;

    if (storyEvent) {
      nextShell = applyStoryEventToShell(nextShell, storyEvent, {
        persistHistory: false,
        liveOnly: event.skipHistory,
      });
    }

    if (nextShell.currentTool && (phase || trimmedActivity)) {
      const current = nextShell.currentTool;
      let nextCurrent = current;
      if (phase) {
        // Detect a phase transition. When the phase label changes, rewrite
        // the most recent tool-progress entry for the previous phase to
        // carry an elapsed-time suffix so the scrollback reads like a
        // progressively-built log: "scanning repo structure · 3s" →
        // "enriching context · 12s" → "building threat model …".
        const prevPhase = current.phase;
        const prevPhaseStartedAt = current.phaseStartedAt ?? current.startedAt;
        if (prevPhase && prevPhase !== phase && prevPhaseStartedAt) {
          const elapsedMs = Math.max(0, now - prevPhaseStartedAt);
          const elapsedLabel = formatDuration(elapsedMs);
          const hist = nextShell.history;
          for (let i = hist.length - 1; i >= 0; i--) {
            const entry = hist[i]!;
            if (entry.type === "tool-progress" && entry.text === prevPhase) {
              const nextHistory = hist.slice();
              nextHistory[i] = {
                ...entry,
                text: `${prevPhase} · ${elapsedLabel}`,
                progressKind: "ok",
              };
              nextShell = { ...nextShell, history: nextHistory };
              break;
            }
          }
        }
        nextCurrent = {
          ...nextCurrent,
          phase,
          phaseStartedAt: prevPhase !== phase ? now : nextCurrent.phaseStartedAt,
          step: phaseStep,
          total: phaseTotal,
          subLabel: phase,
          lastEventAt: now,
        };
      }
      if (trimmedActivity) {
        const prev = nextCurrent.activities ?? [];
        const nextActivities =
          prev[0]?.text === trimmedActivity
            ? [{ text: trimmedActivity, ts: now }, ...prev.slice(1)]
            : [{ text: trimmedActivity, ts: now }, ...prev].slice(0, ACTIVITY_BUFFER_CAP);
        nextCurrent = {
          ...nextCurrent,
          activities: nextActivities,
          lastEventAt: now,
        };
      }
      nextShell = { ...nextShell, currentTool: nextCurrent };
    }

    if (trimmedLiveActivity && nextShell.currentTool?.historyEntryId) {
      const id = nextShell.currentTool.historyEntryId;
      const idx = nextShell.history.findIndex((entry) => entry.id === id);
      if (idx >= 0) {
        const entry = nextShell.history[idx]!;
        if (entry.type === "tool-call" && entry.status === "running") {
          const prev = entry.liveActivities ?? [];
          if (prev[0]?.text !== trimmedLiveActivity) {
            const rawActivities = [
              { id: `la-${now}-${liveActivitySeq++}`, text: trimmedLiveActivity },
              ...prev,
            ];
            const dropped = Math.max(0, rawActivities.length - LIVE_ACTIVITY_CAP);
            const nextActivities = rawActivities.slice(0, LIVE_ACTIVITY_CAP);
            const nextHistory = nextShell.history.slice();
            nextHistory[idx] = {
              ...entry,
              liveActivities: nextActivities,
              liveActivitiesDropped: (entry.liveActivitiesDropped ?? 0) + dropped,
            };
            nextShell = { ...nextShell, history: nextHistory };
          }
        }
      }
    }

    if (event.skipHistory) return nextShell;

    if (storyEvent && shouldPersistStoryEvent(storyEvent)) {
      return {
        ...nextShell,
        history: [
          ...nextShell.history,
          {
            type: "story",
            text: formatStoryEventPlain(storyEvent),
            timestamp: now,
            storyEvent,
          },
        ],
      };
    }

    return {
      ...nextShell,
      history: [
        ...nextShell.history,
        {
          type: "tool-progress",
          text: progressText,
          timestamp: now,
          ...(event.kind ? { progressKind: event.kind } : {}),
        },
      ],
    };
  });
}

const pendingProgressByStore = new WeakMap<
  UIStore,
  {
    latest?: AppendProgressEventInput;
    lastFlushAt: number;
    timer?: ReturnType<typeof setTimeout>;
  }
>();

function appendProgressEventThrottled(store: UIStore, event: AppendProgressEventInput): void {
  const state = pendingProgressByStore.get(store) ?? { lastFlushAt: 0 };
  state.latest = event;
  const now = Date.now();
  const flush = () => {
    state.timer = undefined;
    const latest = state.latest;
    state.latest = undefined;
    state.lastFlushAt = Date.now();
    if (latest) appendProgressEvent(store, latest);
  };

  if (now - state.lastFlushAt >= PROGRESS_EVENT_THROTTLE_MS && !state.timer) {
    pendingProgressByStore.set(store, state);
    flush();
    return;
  }

  if (!state.timer) {
    state.timer = setTimeout(
      flush,
      Math.max(1, PROGRESS_EVENT_THROTTLE_MS - (now - state.lastFlushAt)),
    );
    state.timer.unref?.();
  }
  pendingProgressByStore.set(store, state);
}

function clearTransientShellState(store: UIStore): void {
  updateShell(store, (shell) => ({
    ...shell,
    currentTool: undefined,
    pendingAssistantText: undefined,
    onAbort: undefined,
    llmHeartbeat: undefined,
  }));
}

function settleAbortedShellTurn(store: UIStore, reason: string, resultOutput: string): void {
  finalizeRunningToolCalls(store, "abort", resultOutput);
  markAbortSettled(store, reason);
  store.clearNotices();
  updateShell(store, (shell) => {
    const nextShell: ShellState = {
      ...shell,
      processing: false,
      currentTool: undefined,
      pendingAssistantText: undefined,
      onAbort: undefined,
      llmHeartbeat: undefined,
    };
    if (nextShell.moduleRun?.status === "running") {
      nextShell.moduleRun = {
        ...nextShell.moduleRun,
        status: "aborted",
        completedAtMs: Date.now(),
      };
    }
    if (nextShell.contextBuild?.status === "running") {
      nextShell.contextBuild = {
        ...nextShell.contextBuild,
        status: "aborted",
        errorMessage: nextShell.contextBuild.errorMessage ?? resultOutput,
      };
    }
    if (nextShell.shellView === "module-run" || nextShell.shellView === "actor-detail") {
      nextShell.shellView = nextShell.focusedModule ? "module" : "catalog";
      nextShell.focusedActor = null;
    }
    return nextShell;
  });

  const rootPatch: Partial<UIState> = {
    ctrlCArmedAt: undefined,
    costCapHalted: false,
  };
  const state = store.getState();
  if (state.mode === "running") {
    rootPatch.mode = "shell";
    rootPatch.phase = "idle";
  }
  store.update(rootPatch);
}

async function closeShellSession(session: AgentSession | undefined): Promise<void> {
  try {
    await session?.close();
  } catch {
    // Best-effort cleanup.
  }
}

/**
 * Start the interactive copilot shell.
 *
 * TTY: Ink UI renders the conversation stream.
 * Non-TTY: readline fallback with plain text.
 */
export async function startShell(opts: ShellOptions): Promise<void> {
  // Surface a one-line banner before Ink takes over the terminal when the
  // operator is pointed at a non-Anthropic proxy. Goes to stderr so it
  // survives the Ink stdout takeover. See `warnIfNonAnthropicProxy` for the
  // detection rules and the `KUZUSHI_DISABLE_THINKING` / `KUZUSHI_QUIET_PROXY_BANNER`
  // escape hatches.
  warnIfNonAnthropicProxy();
  warnIfStaleModel(opts.config.model);
  applyImplicitShellTarget(opts);
  // Bare `kuzushi` should still feel scoped to the current repository.
  // Resolve the display name before DB startup so the shell has a useful
  // fallback even when persistence is unavailable.
  if (!opts.workspace) {
    opts.workspace = readDefaultWorkspaceName() ?? inferWorkspaceNameFromTarget(opts.target);
  }
  if (opts.workspace && !opts.workspaceName) {
    opts.workspaceName = opts.workspace;
  }

  const bus = createBus(opts.config);
  const dataDir = path.resolve(process.cwd(), ".kuzushi");
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
  }

  // Initialize workspace persistence
  let workspaceManager: import("../workspace/manager.js").WorkspaceManager | undefined;
  let loadedSnapshot: ContextSnapshot | null = null;
  try {
    const { initDb } = await import("../store.js");
    const dbPath = path.join(dataDir, "findings.sqlite3");
    const db = initDb(dbPath);
    const { WorkspaceManager } = await import("../workspace/manager.js");
    workspaceManager = new WorkspaceManager(db);

    if (opts.workspace) {
      const ws = workspaceManager.getOrCreate(opts.workspace, opts.target ? [opts.target] : []);
      workspaceManager.touchAccessed(ws.id);
      opts.workspace = ws.id;
      opts.workspaceName = ws.name;
      if (opts.target) workspaceManager.addTarget(ws.id, opts.target);
      loadedSnapshot = workspaceManager.loadLatestSnapshot(ws.id);
    }
  } catch {
    // Workspace persistence is optional — degrade gracefully
  }

  // No-workspace fallback: if the target repo has a prior on-disk
  // `<target>/.kuzushi/context-snapshot.json` from an earlier
  // `context:build` run, auto-load it so dependent modules
  // (carlini-threat-hunt, agentic-sast, taint-iris) find their appModel
  // prerequisites without the operator having to re-run context:build
  // on every session.
  //
  // `opts.target` may be undefined when the operator runs `kuzushi`
  // from within a repo with no flags; every other tool-dispatch path
  // treats cwd as the implicit target (see the `currentCwd()`
  // helper pattern used throughout this file), so the snapshot
  // loader falls back to cwd too.
  if (!loadedSnapshot) {
    try {
      const snapshotTarget = opts.target ?? process.cwd();
      const { loadContextSnapshot } = await import("../modules/sast/context-persist.js");
      loadedSnapshot = loadContextSnapshot(snapshotTarget);
    } catch {
      /* best-effort */
    }
  }

  const core = new CopilotCore({
    runtime: opts.runtime,
    bus,
    config: opts.config,
    dataDir,
    modules: opts.modules,
    excludeBuiltinModules: opts.excludeBuiltinModules,
  });

  await core.init();

  // M1: migrate any legacy `taskConfig[<old-id>]` entries to their canonical
  // module ids so per-task overrides survive a module rename. The registry
  // owns the alias map (populated from each module's `legacyIds`) — we walk
  // it once here and merge legacy keys forward (canonical wins on conflict).
  migrateLegacyTaskConfigKeys(opts.config, core.registry.listModuleIdAliases());

  const systemPrompt = core.buildSystemPromptPrefix();

  if (process.stdout.isTTY && process.stdin.isTTY) {
    await startInkShell(core, opts, bus, systemPrompt, dataDir, loadedSnapshot, workspaceManager);
  } else {
    await startReadlineShell(
      core,
      opts,
      bus,
      systemPrompt,
      dataDir,
      loadedSnapshot,
      workspaceManager,
    );
  }
}

// Ink-powered shell (TTY) — conversation stream rendered through React

async function startInkShell(
  core: CopilotCore,
  opts: ShellOptions,
  bus: MessageBus,
  systemPrompt: string,
  dataDir: string,
  loadedSnapshot?: ContextSnapshot | null,
  workspaceManager?: import("../workspace/manager.js").WorkspaceManager,
): Promise<void> {
  const { createUIRenderer } = await import("../ui/render.js");
  const renderer = await createUIRenderer();
  const { store, cleanup: cleanupUI } = renderer;

  const modules = core.listModules();
  const tools = core.registry.allTools();
  const commandHistory = loadShellCommandHistory(dataDir);
  const catalogRuns = await readRunHistoryForCatalog(dataDir, opts.target);

  let alive = true;
  let session: AgentSession | undefined;
  let sessionCwd: string | undefined;
  let sessionError: string | undefined;
  let assistantDisabledReason: string | undefined;
  /** True iff disable reason is "no creds yet" (cancelled or never offered). */
  let credentialsMissing = false;
  let activeActionKind: "tool" | "agent" | null = null;
  let activeAbortRequested = false;
  let activeTurnId: string | undefined;
  let turnSeq = 0;
  const nextTurnId = (): string => `turn-${Date.now()}-${++turnSeq}`;
  /**
   * Epoch ms the most recent tool/agent abort fired. The SIGINT fallback uses
   * a short grace period to distinguish a duplicate signal from the same
   * physical keypress from an intentional second Ctrl+C that should exit.
   */
  let lastAbortFiredAt = 0;

  // runId-based blacklist for the task:phase-progress / task:activity bus
  // subscribers. When the operator Ctrl+Cs a tool that doesn't honor
  // `ctx.signal` (many context-pipeline tasks don't), it keeps emitting
  // progress events afterwards. Without this, those events would leak
  // into the *next* turn's history once processing=true flips back on.
  //
  // Strategy: every event we accept adds its runId to `seenRunIdsThisTurn`.
  // On abort, we migrate that set into `abortedRunIds` so any future event
  // with one of those runIds is dropped unconditionally. New turns get new
  // task runIds (fresh UUIDs from the DAG execution context), so legitimate
  // progress still flows. Cap the blacklist FIFO to bound memory over
  // a long shell session.
  const seenRunIdsThisTurn = new Set<string>();
  const abortedRunIds = new Set<string>();
  const runIdTurnIds = new Map<string, string>();
  const ABORTED_RUNIDS_CAP = 512;
  const blacklistCurrentTurnRunIds = (): void => {
    for (const id of seenRunIdsThisTurn) {
      abortedRunIds.add(id);
    }
    seenRunIdsThisTurn.clear();
    if (abortedRunIds.size > ABORTED_RUNIDS_CAP) {
      // Drop oldest entries (Set preserves insertion order) until under cap.
      const overflow = abortedRunIds.size - ABORTED_RUNIDS_CAP;
      let dropped = 0;
      for (const id of abortedRunIds) {
        abortedRunIds.delete(id);
        if (++dropped >= overflow) break;
      }
    }
  };
  const acceptProgressRunId = (runId: string): boolean => {
    if (abortedRunIds.has(runId)) return false;
    if (activeAbortRequested || store.getState().shell?.processing !== true) return false;
    const turnId = activeTurnId;
    if (turnId) {
      const existing = runIdTurnIds.get(runId);
      if (existing && existing !== turnId) return false;
      runIdTurnIds.set(runId, turnId);
    }
    seenRunIdsThisTurn.add(runId);
    return true;
  };

  const noteAbortFired = (): void => {
    lastAbortFiredAt = Date.now();
    store.update({ ctrlCArmedAt: undefined });
  };

  const currentCwd = (): string => (opts.target ? path.resolve(opts.target) : process.cwd());
  const shellCtx: ShellContext = {
    focusedModule: null,
    uiStore: store,
    workspaceManager,
    dataDir,
  };

  // Live-session registry — used by WorkspaceDispatcher's `sessions -i/-k` and
  // by the session requirement preflight. Only meaningful when a workspace is
  // active (sessions are workspace-scoped).
  const sessionManager = workspaceManager
    ? new SessionManager(workspaceManager.sessions)
    : (undefined as unknown as SessionManager);

  // msfconsole-style CommandDispatcher — first-pass router for help / use /
  // set / setg / unset / show / info / search / history / resource / makerc /
  // banner / exit. Unknown commands fall through to routeInput (second pass)
  // and ultimately the LLM agent (third pass).
  // Audit-trail tee controller. `spool <file>` opens; `spool off` closes.
  const spoolController = new SpoolController();

  const dispatcherPrint: PrintSink = createPrintSink({
    color: false,
    // Swallow direct writes — Ink owns the render surface. We only care about
    // the onPrint tap, which appends every emitted line to shell.history as an
    // "output" entry so it shows up in the conversation stream.
    write: () => {},
    onPrint: (line: string, level: PrintLevel) => {
      appendToHistory(store, {
        type: level === "error" ? "error" : "output",
        text: line,
        timestamp: Date.now(),
      });
      // Mirror to the spool file if one is active. The tap() call is a no-op
      // when spooling is off, so the hot path pays ~one map lookup.
      spoolController.tap(line);
    },
  });

  const globals = new Datastore();
  // Tell CopilotCore about the globals Datastore so BUDGET_USD + <MOD>_MODEL
  // live-settings land. Only needs to happen once per shell boot.
  core.setGlobals(globals);
  // M3: seed the active shell target into globals so per-module DelegatingDatastores
  // can fall through to it. Without this, `run` (no args) errors with
  // "Missing required: target" even when the home view shows an active target —
  // because the per-module datastore's "target" OptionSpec is empty and the
  // missingRequired() check doesn't know about opts.target. Re-synced after
  // /target updates the active target.
  syncShellTargetToGlobals(opts, globals);

  const runToolFromDispatcher = async (
    tool: ModuleTool,
    input: Record<string, unknown>,
    signal?: AbortSignal,
    datastore?: Datastore,
  ) => {
    const shell = store.getState().shell;
    const snapshot = shell?.contextSnapshot ?? null;
    const seedTarget = opts.target ?? currentCwd();
    const threatModel =
      shell?.threatModel ??
      (!/^[a-z][a-z0-9+.-]*:\/\//i.test(seedTarget)
        ? loadPersistentThreatModel(path.resolve(seedTarget))
        : null);
    const seedTaskOutputs = snapshot
      ? buildSeedMapFromSnapshot(snapshot, {
          ...(threatModel ? { threatModel } : {}),
        })
      : undefined;
    const execOpts: Parameters<CopilotCore["executeTool"]>[2] = {
      cwd: currentCwd(),
      uiStore: store,
    };
    if (opts.target) execOpts.target = opts.target;
    if (opts.workspace) execOpts.workspaceId = opts.workspace;
    if (signal) execOpts.signal = signal;
    if (seedTaskOutputs) execOpts.seedTaskOutputs = seedTaskOutputs;
    if (datastore) execOpts.datastore = datastore;
    if (workspaceManager) execOpts.workspace = workspaceManager;
    const storedShellOptions = store.getState().shell?.moduleOptions[tool.name];
    const localModelOverride = readStoredModelOption(storedShellOptions ?? {});
    if (localModelOverride && datastore) {
      datastore.set("model", localModelOverride);
    }
    const effectiveInput = applyStoredShellOptionsToInput(tool, input, storedShellOptions);
    // Emit the cc-repo-style `⏺ tool(hint)` header once, up front. The
    // scrollback is now the primary progress surface; `⎿  …` progress lines
    // will accumulate beneath it as `task:activity` / `task:phase-progress`
    // events arrive (see bus subscriptions near `startShell`). The entry
    // has a stable `id` so the finally-block can flip its status on
    // resolution (cyan `⏺` → green / red / dim) without appending a
    // duplicate completion line.
    const inputDisplay = renderToolInputHint(tool, effectiveInput);
    const displayName = tool.displayName;
    const headerText = inputDisplay
      ? `⏺ ${displayName ?? tool.name}(${inputDisplay})`
      : `⏺ ${displayName ?? tool.name}`;
    const historyEntryId = `tc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const turnId = activeTurnId;
    const startStory = createShellStoryEvent({
      kind: "tool",
      status: "running",
      importance: "primary",
      message: `${displayName ?? tool.name} started`,
      source: tool.name,
      ...(inputDisplay ? { detail: inputDisplay } : {}),
      ...(turnId ? { turnId } : {}),
      durable: true,
    });
    // Seed `currentTool` so ToolRunningStatus has something to render the
    // moment the dispatcher kicks off a direct `run` — otherwise the
    // `task:activity` events that fire during the tool would hit an empty
    // slot and be dropped.
    const startedAt = Date.now();
    const toolModuleId = tool.name.includes(":") ? tool.name.split(":", 1)[0] : null;
    const runModel = localModelOverride ?? datastore?.get<string>("model");
    // Batch the initial run state so Ink never renders a blank processing
    // frame between `run` and the module-run screen.
    updateShell(store, (shell) => {
      let next: ShellState = applyStoryEventToShell(
        {
          ...shell,
          processing: true,
          history: [
            ...shell.history,
            {
              type: "tool-call",
              id: historyEntryId,
              tool: tool.name,
              ...(displayName ? { displayName } : {}),
              ...(inputDisplay ? { inputHint: inputDisplay } : {}),
              status: "running",
              text: headerText,
              timestamp: Date.now(),
              storyEvent: startStory,
            },
          ],
        },
        startStory,
        { persistHistory: false },
      );
      next = {
        ...next,
        currentTool: {
          name: tool.name,
          startedAt,
          lastEventAt: startedAt,
          historyEntryId,
          ...(displayName ? { displayName } : {}),
          ...(turnId ? { turnId } : {}),
          storyTail: [startStory],
        },
      };
      // Foreground runs from a focused module are shell-owned: keep the
      // conversation visible and let bus/report events populate this slice.
      if (toolModuleId && shell.focusedModule === toolModuleId) {
        next.moduleRun = {
          moduleId: toolModuleId,
          source: "shell",
          toolName: tool.name,
          ...(displayName ? { displayName } : {}),
          ...(inputDisplay ? { inputSummary: inputDisplay } : {}),
          ...(tool.runLifecycle?.liveControl ? { liveControl: tool.runLifecycle.liveControl } : {}),
          ...(runModel ? { model: runModel } : {}),
          startedAtMs: startedAt,
          status: "running",
          steps: [],
          evidenceTail: [],
          findingCount: 0,
          costUsd: 0,
        };
        next.shellView = "module-run";
      }
      return next;
    });
    let ok = false;
    let aborted = false;
    let finalResult: Awaited<ReturnType<CopilotCore["executeTool"]>> | undefined;
    try {
      const result = await core.executeTool(tool.name, effectiveInput, execOpts);
      finalResult = result;
      if (signal?.aborted) aborted = true;
      else ok = !!result?.ok;
      return result;
    } catch (err) {
      if (signal?.aborted) aborted = true;
      throw err;
    } finally {
      // Before the ⏺ entry flips to its terminal state, stamp the
      // currently-active phase entry in scrollback with its elapsed time
      // so the last line of the "progressive build" log isn't left
      // unlabeled. Phase transitions handle this for all prior phases.
      finalizeCurrentPhase(store, aborted ? "abort" : ok ? "ok" : "fail");
      const elapsed = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
      const status: "ok" | "fail" | "abort" = aborted ? "abort" : ok ? "ok" : "fail";
      // Per-tool renderResult() may return a concise summary like
      // "Read 559 lines". Fall back to the generic verb when omitted.
      const customResult =
        status === "ok" && finalResult ? tool.renderResult?.(finalResult) : undefined;
      const verb = aborted ? "aborted" : ok ? "done" : "failed";
      const resultOutput =
        customResult && customResult.length > 0 ? customResult : `${verb} in ${elapsed}s`;
      appendStoryEvent(store, {
        kind: "result",
        status: aborted ? "aborted" : ok ? "ok" : "fail",
        importance: "primary",
        message: `${displayName ?? tool.name} ${verb}`,
        detail: resultOutput,
        source: tool.name,
        ...(turnId ? { turnId } : {}),
        ...(status === "ok" && finalResult?.costUsd ? { costUsd: finalResult.costUsd } : {}),
        durable: true,
      });
      patchHistoryEntry(store, historyEntryId, {
        status,
        elapsedSeconds: elapsed,
        resultOutput,
        ...(status === "abort" ? { abortStatus: "aborted" as const } : {}),
        // Clear the live tail — the tool is done, scrollback already has
        // the per-activity entries for the audit trail.
        liveActivities: undefined,
        liveActivitiesDropped: undefined,
      });
      updateShell(store, (shell) => {
        const next: ShellState = {
          ...shell,
          currentTool: undefined,
          lastUsedTool: tool.name,
          moduleCatalog: applyModuleRunTelemetry(
            shell.moduleCatalog,
            tool.name,
            status,
            status === "ok" ? finalResult?.costUsd : undefined,
          ),
        };
        // Stamp the active module run with the terminal status + cost. Keep
        // the module-run surface visible so the completed run remains
        // inspectable instead of hiding the shell history behind RunningView.
        if (
          shell.moduleRun &&
          shell.moduleRun.toolName === tool.name &&
          shell.moduleRun.status === "running"
        ) {
          const huntStats =
            finalResult && isHuntClassTool(tool.name) ? extractHuntStats(finalResult) : undefined;
          next.moduleRun = {
            ...shell.moduleRun,
            status: aborted ? "aborted" : ok ? "done" : "error",
            completedAtMs: Date.now(),
            ...(huntStats ? { findingCount: huntStats.findingsCount } : {}),
            ...(huntStats ? { reviewCandidateCount: huntStats.reviewCandidateCount } : {}),
            ...(huntStats?.agentRuntimeBackend
              ? { agentRuntimeBackend: huntStats.agentRuntimeBackend }
              : {}),
            ...(huntStats?.agentStatus ? { agentStatus: huntStats.agentStatus } : {}),
            ...(huntStats?.candidateCount !== undefined
              ? { candidateCount: huntStats.candidateCount }
              : {}),
            ...(huntStats?.linkedStoryCount !== undefined
              ? { linkedStoryCount: huntStats.linkedStoryCount }
              : {}),
            ...(huntStats?.backendPathCount !== undefined
              ? { backendPathCount: huntStats.backendPathCount }
              : {}),
            ...(huntStats?.warningCount !== undefined
              ? { warningCount: huntStats.warningCount }
              : {}),
            ...(finalResult?.costUsd != null ? { costUsd: finalResult.costUsd } : {}),
          };
        }
        return next;
      });
      try {
        await hydrateShellStore(store, core, opts, dataDir);
      } catch {
        /* best-effort */
      }
      // Hunt post-mortem — after carlini-threat-hunt (and future hunt-class tools
      // whose runs publish per-actor `agent-activity` events) resolves,
      // drain the archived per-actor snapshots into a collapsed scrollback
      // block so operators can expand it to see which actor made the last
      // move. HeartbeatStrip only renders during `mode === "running"`, so
      // without this the breakdown disappears the instant the tool returns.
      if (status === "ok" && isHuntClassTool(tool.name)) {
        const perActor = store.consumeHuntSnapshot();
        if (perActor.length > 0 && finalResult) {
          const stats = extractHuntStats(finalResult);
          appendToHistory(store, {
            type: "hunt-post-mortem",
            text: formatHuntSummaryLine(
              perActor.length,
              stats.findingsCount,
              stats.costUsd,
              stats.reviewCandidateCount,
              stats.agentStatus,
            ),
            timestamp: Date.now(),
            huntSummary: {
              actorCount: perActor.length,
              findingsCount: stats.findingsCount,
              costUsd: stats.costUsd,
              perActor,
            },
          });
        }
      }
    }
  };

  let driver: DispatcherDriver;

  // Background job registry — shared between the ModuleDispatcher (for
  // `run --bg` backgrounding) and the CoreDispatcher (for the `jobs` family).
  const jobManager = new JobManager();

  const mirrorBackgroundJob = (job: ReturnType<JobManager["list"]>[number]): void => {
    updateBackgroundJobStory(store, {
      id: job.id,
      label: job.label,
      status: job.state,
      startedAt: job.startedAt,
      ...(job.endedAt ? { endedAt: job.endedAt } : {}),
    });
  };
  jobManager.on("started", mirrorBackgroundJob);
  jobManager.on("completed", mirrorBackgroundJob);
  jobManager.on("failed", mirrorBackgroundJob);
  jobManager.on("cancelled", mirrorBackgroundJob);

  // Scheduler — layered on JobManager. Forward-declared here; the
  // `runCommand` callback closes over `driver` so we instantiate lazily
  // just before driver construction below. Actual setup lives at a
  // `const scheduler = new Scheduler(...)` line further down.
  let scheduler: import("../scheduler/core.js").Scheduler | undefined;

  // Desktop notification bridge. Jobs that run longer than NOTIFY_THRESHOLD_SECS
  // fire a system toast on terminal transitions. Opt-in via `setg NOTIFY_ON_COMPLETE true`.
  {
    const { sendCompletionNotification } = await import("../ui/notify.js");
    const { postSlack } = await import("../ui/slack.js");
    const notifyIfOptedIn = (label: string, verb: string, record: { startedAt: number }) => {
      const thresholdRaw = String(globals.get("NOTIFY_THRESHOLD_SECS") ?? "30");
      const threshold = Number.parseInt(thresholdRaw, 10);
      const elapsedSecs = (Date.now() - record.startedAt) / 1000;
      if (!Number.isFinite(threshold) || elapsedSecs < threshold) return;

      // Desktop toast
      if (String(globals.get("NOTIFY_ON_COMPLETE") ?? "").toLowerCase() === "true") {
        sendCompletionNotification(`Kuzushi: job ${verb}`, `${label} (${elapsedSecs.toFixed(0)}s)`);
      }
      // Slack webhook
      if (String(globals.get("SLACK_NOTIFY") ?? "").toLowerCase() === "true") {
        const webhookUrl = String(globals.get("SLACK_WEBHOOK_URL") ?? "");
        if (webhookUrl) {
          void postSlack({
            webhookUrl,
            text: `🔐 Kuzushi: job *${verb}* — ${label} (${elapsedSecs.toFixed(0)}s)`,
          });
        }
      }
    };
    jobManager.on("completed", (job) => notifyIfOptedIn(job.label, "completed", job));
    jobManager.on("failed", (job) => notifyIfOptedIn(job.label, "failed", job));
    jobManager.on("cancelled", (job) => notifyIfOptedIn(job.label, "cancelled", job));
  }

  // Auto-triage bridge — when `setg AutoTriage true`, every scan:finding whose
  // severity meets AUTO_TRIAGE_MIN_SEVERITY queues a triage:run as a
  // background job. Demonstrates the framework-event model: the scanner
  // module doesn't know triage exists; the wiring is operator-controlled.
  const SEVERITY_ORDER: Record<string, number> = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
  };
  bus.subscribe<import("../bus/events.js").ScanFindingEvent>("scan:finding", (event) => {
    if (String(globals.get("AutoTriage") ?? "").toLowerCase() !== "true") return;
    const minSev = String(globals.get("AUTO_TRIAGE_MIN_SEVERITY") ?? "high").toLowerCase();
    const minRank = SEVERITY_ORDER[minSev] ?? SEVERITY_ORDER.high ?? 3;
    const findingSev = String(event.payload.finding.severity ?? "").toLowerCase();
    const findingRank = SEVERITY_ORDER[findingSev] ?? 0;
    if (findingRank < minRank) return;
    const fingerprint = event.payload.finding.fingerprint;
    if (!fingerprint) return;
    jobManager.start({ label: `auto-triage:${fingerprint}`, kind: "tool" }, async (jobCtx) => {
      jobCtx.log(`[*] AutoTriage ${fingerprint} (severity ${findingSev})`);
      const result = await core.executeTool(
        "triage:run",
        { fingerprint },
        {
          cwd: currentCwd(),
          ...(opts.workspace ? { workspaceId: opts.workspace } : {}),
          ...(workspaceManager ? { workspace: workspaceManager } : {}),
          signal: jobCtx.signal,
        },
      );
      jobCtx.log(result.ok ? `[+] AutoTriage done` : `[-] AutoTriage failed: ${result.output}`);
      return result.output;
    });
  });

  // Auto-verify bridge — when `setg AutoVerify true`, any triage:result with
  // verdict="tp" queues verify:finding as a background job. Chains off the
  // AutoTriage output: operator opts in once, the scan → triage → verify loop
  // runs without further intervention. Ignored for fp / needs_review / by_design.
  bus.subscribe<import("../bus/events.js").TriageResultEvent>("triage:result", (event) => {
    if (String(globals.get("AutoVerify") ?? "").toLowerCase() !== "true") return;
    const verdict = event.payload.result.verdict;
    if (verdict !== "tp") return;
    const fingerprint = event.payload.finding.fingerprint;
    if (!fingerprint) return;
    jobManager.start({ label: `auto-verify:${fingerprint}`, kind: "tool" }, async (jobCtx) => {
      jobCtx.log(`[*] AutoVerify ${fingerprint} (verdict ${verdict})`);
      const result = await core.executeTool(
        "verify:finding",
        { fingerprint },
        {
          cwd: currentCwd(),
          ...(opts.workspace ? { workspaceId: opts.workspace } : {}),
          ...(workspaceManager ? { workspace: workspaceManager } : {}),
          signal: jobCtx.signal,
        },
      );
      jobCtx.log(result.ok ? `[+] AutoVerify done` : `[-] AutoVerify failed: ${result.output}`);
      return result.output;
    });
  });

  // LLM heartbeat — subscribe to runtime-level call events so the shell can
  // show a live "model · N calls · $cost" line under the spinner. Without
  // this the spinner freezes at a stage name and the operator can't tell a
  // slow LLM call from a hang.
  bus.subscribe<import("../bus/events.js").LlmCallStartEvent>("llm:call-start", (event) => {
    updateShell(store, (shell) => ({
      ...shell,
      llmHeartbeat: {
        activeCalls: (shell.llmHeartbeat?.activeCalls ?? 0) + 1,
        completedCalls: shell.llmHeartbeat?.completedCalls ?? 0,
        latestModel: event.payload.model,
        totalCostUsd: shell.llmHeartbeat?.totalCostUsd ?? 0,
      },
    }));
  });
  bus.subscribe<import("../bus/events.js").LlmCallCompleteEvent>("llm:call-complete", (event) => {
    updateShell(store, (shell) => {
      const prev = shell.llmHeartbeat;
      return {
        ...shell,
        llmHeartbeat: {
          activeCalls: Math.max(0, (prev?.activeCalls ?? 1) - 1),
          completedCalls: (prev?.completedCalls ?? 0) + 1,
          latestModel: prev?.latestModel ?? event.payload.model,
          totalCostUsd: (prev?.totalCostUsd ?? 0) + (event.payload.costUsd ?? 0),
        },
      };
    });
  });
  bus.subscribe<import("../bus/events.js").LlmCallErrorEvent>("llm:call-error", (_event) => {
    updateShell(store, (shell) => {
      const prev = shell.llmHeartbeat;
      return {
        ...shell,
        llmHeartbeat: {
          activeCalls: Math.max(0, (prev?.activeCalls ?? 1) - 1),
          completedCalls: (prev?.completedCalls ?? 0) + 1,
          ...(prev?.latestModel ? { latestModel: prev.latestModel } : {}),
          totalCostUsd: prev?.totalCostUsd ?? 0,
        },
      };
    });
  });

  // Tool progress rail — `task:phase-progress` updates the current tool's
  // phase strip and also appends a permanent history entry so operators see
  // each phase transition accumulate downward (cc-repo style) instead of
  // watching one line update in place. `task:activity` does the same for
  // sub-step descriptions. The in-place spinner below just shows elapsed;
  // the scrollback is the source of truth for what has happened so far.
  bus.subscribe<import("../bus/events.js").TaskPhaseProgressEvent>(
    "task:phase-progress",
    (event) => {
      // Drop events from any task the operator has already Ctrl+C'd. Many
      // pipeline tasks (notably `context:build` sub-agents) don't honor
      // `ctx.signal`, so they keep emitting after abort. Without this their
      // output would appear under the operator's next prompt.
      const runId = event.meta.runId;
      if (!acceptProgressRunId(runId)) return;
      appendProgressEvent(store, {
        text: event.payload.phase,
        phase: event.payload.phase,
        liveActivity: event.payload.phase,
        story: {
          kind: "phase",
          status: "running",
          importance: "primary",
          message: event.payload.phase,
          source: "task:phase-progress",
          runId,
          ...(activeTurnId ? { turnId: activeTurnId } : {}),
        },
      });
    },
  );
  bus.subscribe<import("../bus/events.js").TaskActivityEvent>("task:activity", (event) => {
    const runId = event.meta.runId;
    if (!acceptProgressRunId(runId)) return;
    const description = event.payload.description;
    const isSubagentTool = looksLikeSubagentToolLine(description);
    // `task:activity` is live-tail material, not durable transcript. Keep
    // sub-agent tool echoes and free-form module pulses such as "scanning
    // repo structure" under the running `⏺` row / task details only. Durable
    // story beats come from phase-progress, artifacts, warnings, aborts, and
    // final results, which prevents the context build from printing both old
    // `⎿ activity` rows and curated story rows for the same work.
    const skipHistory = true;
    appendProgressEventThrottled(store, {
      text: description,
      activity: description,
      liveActivity: description,
      skipHistory,
      story: {
        kind: isSubagentTool ? "tool" : "activity",
        status: "running",
        importance: isSubagentTool ? "debug" : "secondary",
        message: description,
        source: "task:activity",
        runId,
        ...(activeTurnId ? { turnId: activeTurnId } : {}),
      },
      ...(event.payload.phase ? { phase: event.payload.phase } : {}),
      ...(isSubagentTool ? { kind: "invocation" as const } : {}),
    });
  });
  // Ephemeral subprocess stdout / tool-use preview — shows in the running
  // `⏺` entry's live tail but never lands in scrollback. cc-repo's
  // `ShellProgressMessage` analogue: operators see live Bash output during
  // execution, then it's gone once the tool resolves.
  bus.subscribe<import("../bus/events.js").TaskOutputEvent>("task:output", (event) => {
    const runId = event.meta.runId;
    if (!acceptProgressRunId(runId)) return;
    const entryId = store.getState().shell?.currentTool?.historyEntryId;
    pushTaskOutputThrottled(store, {
      ...(entryId ? { entryId } : {}),
      text: event.payload.line,
      story: {
        kind: "activity",
        status: "running",
        importance: "debug",
        message: event.payload.line,
        source: "task:output",
        runId,
        ...(activeTurnId ? { turnId: activeTurnId } : {}),
      },
    });
  });

  // Carlini threat-hunt actor rail — direct shell runs publish one event stream per
  // actor. Keep most actor/tool chatter live-only, but persist terminal actor
  // summaries so the transcript tells a compact progressive story.
  bus.subscribe<import("../bus/events.js").TaskAgentActivityEvent>(
    "carlini-threat-hunt:agent-activity",
    (event) => {
      const runId = event.meta.runId || event.payload.context.runId;
      if (!runId || !acceptProgressRunId(runId)) return;
      if (!event.payload.done && moduleRunOwnsCarliniThreatHuntActivity(store.getState().shell)) {
        return;
      }
      const story = formatAgentActivityStory(event.payload);
      appendProgressEvent(store, {
        text: story.detail ? `${story.message} · ${story.detail}` : story.message,
        activity: story.detail ? `${story.message} · ${story.detail}` : story.message,
        liveActivity: story.detail ? `${story.message} · ${story.detail}` : story.message,
        skipHistory: !event.payload.done,
        story: {
          kind: story.kind,
          status: event.payload.done ? "ok" : "running",
          importance: event.payload.done ? "primary" : "secondary",
          message: story.message,
          ...(story.detail ? { detail: story.detail } : {}),
          source: "carlini-threat-hunt:agent-activity",
          runId,
          ...(activeTurnId ? { turnId: activeTurnId } : {}),
          durable: event.payload.done,
        },
      });
    },
  );

  // Auto-patch bridge — when `setg AutoPatch true`, any verification:result
  // with exploitable=true queues patch:finding as a background job. Closes
  // the scan → triage → verify → patch loop. Intentionally gated on
  // exploitable-only to avoid patching false positives.
  bus.subscribe<import("../bus/events.js").VerificationResultEvent>(
    "verification:result",
    (event) => {
      if (String(globals.get("AutoPatch") ?? "").toLowerCase() !== "true") return;
      if (!event.payload.result.exploitable) return;
      const fingerprint = event.payload.finding.fingerprint;
      if (!fingerprint) return;
      jobManager.start({ label: `auto-patch:${fingerprint}`, kind: "tool" }, async (jobCtx) => {
        jobCtx.log(`[*] AutoPatch ${fingerprint}`);
        const result = await core.executeTool(
          "patch:finding",
          { fingerprint },
          {
            cwd: currentCwd(),
            ...(opts.workspace ? { workspaceId: opts.workspace } : {}),
            ...(workspaceManager ? { workspace: workspaceManager } : {}),
            signal: jobCtx.signal,
          },
        );
        jobCtx.log(result.ok ? `[+] AutoPatch done` : `[-] AutoPatch failed: ${result.output}`);
        return result.output;
      });
    },
  );

  const coreDispatcher = new CoreDispatcher({
    registry: core.registry,
    globals,
    agentRuntimeBackend: opts.config.agentRuntimeBackend,
    history: () => store.getState().shell?.commandHistory ?? [],
    clearHistory: () => {
      updateShell(store, (shell) => ({ ...shell, commandHistory: [] }));
    },
    runResource: async (file: string, signal?: AbortSignal) => {
      await loadAndRunResource(file, {
        driver,
        cwd: currentCwd(),
        ...(signal ? { signal } : {}),
      });
    },
    makeResource: async (file: string) => {
      const history = store.getState().shell?.commandHistory ?? [];
      // Exclude the `makerc ...` line itself; drop empty + `resource`/`makerc`
      // recursive commands.
      const commands = history.filter(
        (line) => !line.startsWith("makerc") && !line.startsWith("resource"),
      );
      await saveResourceScript(file, { commands });
    },
    runTool: runToolFromDispatcher,
    resolveRecipePath: (name: string) => resolveRecipePath(name, currentCwd()),
    listRecipes: () => listRecipes(currentCwd()),
    // Bridge for `edit <NAME>`. Suspending the Ink render while $EDITOR owns
    // the TTY is a future refinement — today we just spawn inheriting stdio.
    openEditor: (initial: string) => openInEditor(initial),
    // Dev escape hatch — `repl` drops into node:repl with framework objects
    // bound so developers can poke at live registry / bus / workspace state
    // without restarting the shell. Non-TTY shells decline gracefully.
    openRepl: async () => {
      if (!process.stdin.isTTY) {
        dispatcherPrint.error("[-] REPL requires an interactive TTY.");
        return;
      }
      await openDevRepl({
        context: {
          core,
          registry: core.registry,
          events: core.events,
          moduleCache: core.moduleCache,
          workspace: workspaceManager,
          sessions: sessionManager,
          jobs: jobManager,
          bus,
          globals,
          print: dispatcherPrint,
        },
      });
    },
    jobManager,
    spool: spoolController,
    events: core.events,
    frameworkVersion: resolveFrameworkVersion(),
    getLogPath: () => resolveAuditLogPath(opts.config, dataDir),
    scheduler: () => scheduler,
  });

  driver = new DispatcherDriver({
    base: coreDispatcher,
    cwd: currentCwd(),
    print: dispatcherPrint,
    promptBase: "kuzushi",
    // Expose the live ShellState to module preflight checks (CopilotModule.requires).
    getShellState: () => {
      const shell = store.getState().shell;
      return shell
        ? { contextSnapshot: shell.contextSnapshot, threatModel: shell.threatModel }
        : undefined;
    },
    // Workspace-DB finding count for triage/verify/patch requires. Walks
    // BOTH stores: the workspace vulns table AND the scan_findings table
    // (where carlini-threat-hunt / scan-mode tasks persist). Operators who
    // run a hunt in shell mode then ask for triage previously got "run a
    // scanner first" because the dispatcher only knew about workspace vulns.
    getFindingCount: () => {
      const wsId = opts.workspace;
      let workspaceVulns = 0;
      if (wsId && workspaceManager) {
        workspaceVulns = workspaceManager.vulns.listForWorkspace(wsId).length;
      }
      let scanFindings = 0;
      if (workspaceManager) {
        try {
          const row = workspaceManager
            .rawDb()
            .prepare("SELECT COUNT(*) AS n FROM scan_findings")
            .get() as { n?: number } | undefined;
          scanFindings = typeof row?.n === "number" ? row.n : 0;
        } catch {
          // scan_findings table may not exist on first-run dbs — ignore
        }
      }
      return workspaceVulns + scanFindings;
    },
    getHostCount: () => {
      const wsId = opts.workspace;
      if (!wsId || !workspaceManager) return 0;
      return workspaceManager.hosts.list(wsId).length;
    },
    getLiveSessionCount: (kind?: string) => {
      const wsId = opts.workspace;
      if (!wsId) return 0;
      const live = sessionManager.liveForWorkspace(wsId);
      return kind ? live.filter((h) => h.record.kind === kind).length : live.length;
    },
    jobManager,
  });

  // Mount the WorkspaceDispatcher — exposes hosts/services/vulns/loot/notes/
  // creds/sessions as shell commands. Only pushed when a workspace is actually
  // available; otherwise the dispatcher would report "no active workspace"
  // for every command.
  if (workspaceManager) {
    driver.push(
      new WorkspaceDispatcher({
        workspaces: workspaceManager,
        activeWorkspaceId: () => opts.workspace,
        sessions: sessionManager,
      }),
    );
  }

  // Prompt status line — msfconsole-style bracketed telemetry segments.
  // Each provider returns a short string (or undefined to suppress).
  driver.addStatusProvider(() => {
    const n = jobManager.activeCount();
    return n > 0 ? `${n} ${n === 1 ? "job" : "jobs"}` : undefined;
  });
  driver.addStatusProvider(() => {
    const wsId = opts.workspace;
    if (!wsId || !workspaceManager) return undefined;
    const ws = workspaceManager.get(wsId);
    const cost =
      typeof ws?.metadata.totalCostUsd === "number" ? ws.metadata.totalCostUsd : undefined;
    return cost && cost > 0 ? `$${cost.toFixed(2)}` : undefined;
  });
  driver.addStatusProvider(() => (opts.workspace ? `ws: ${opts.workspace}` : undefined));
  driver.addStatusProvider(() => {
    if (!opts.workspace || !workspaceManager) return undefined;
    const live = sessionManager.liveForWorkspace(opts.workspace).length;
    return live > 0 ? `${live} ${live === 1 ? "session" : "sessions"}` : undefined;
  });
  driver.addStatusProvider(() => spoolController.status());

  // Instantiate the Scheduler now that the driver exists (it references
  // `driver.handle` to replay commands). Late assignment lands in the
  // `scheduler` binding that the CoreDispatcher's `schedule()` accessor
  // reads. Backed by the workspace DB when one's available.
  {
    const { Scheduler } = await import("../scheduler/core.js");
    let store: import("../scheduler/core.js").SchedulerStore | undefined;
    if (workspaceManager) {
      const { SqliteScheduleStore } = await import("../scheduler/store.js");
      store = new SqliteScheduleStore(workspaceManager.rawDb());
    }
    scheduler = new Scheduler({
      jobs: jobManager,
      store,
      runCommand: async (command: string) => {
        const out = await driver.handle(command);
        return out.output;
      },
    });
    scheduler.start();
  }

  // Load ~/.kuzushi/startup.rc if present — lets operators preload setg,
  // aliases, favorites, etc. on every shell launch. Errors are non-fatal;
  // they show up as dispatcher output but don't abort shell start.
  try {
    const os = await import("node:os");
    const fs = await import("node:fs");
    const startupPath = path.join(os.homedir(), ".kuzushi", "startup.rc");
    if (fs.existsSync(startupPath)) {
      await loadAndRunResource(startupPath, { driver, cwd: currentCwd() });
    }
  } catch {
    // Best-effort — a broken startup.rc shouldn't block shell use.
  }

  /**
   * Sync `shellCtx.focusedModule` from the dispatcher stack so bare-tool
   * dispatch (`resolveDirectToolDispatch`) and prompt rendering stay in sync
   * with `use <module>` / `back`.
   */
  const syncFocusFromDispatcher = (): void => {
    const top = driver.current();
    if (top instanceof ModuleDispatcher) {
      shellCtx.focusedModule = top.module.id;
    } else {
      shellCtx.focusedModule = null;
    }
    updateShell(store, (shell) => ({
      ...shell,
      focusedModule: shellCtx.focusedModule,
      shellView: reconcileShellViewAfterFocusChange(shell.shellView, shellCtx.focusedModule),
      target: opts.target ?? null,
      workspace: workspaceDisplayName(opts, workspaceManager),
    }));
  };

  const closeSession = async (): Promise<void> => {
    const currentSession = session;
    session = undefined;
    sessionCwd = undefined;
    await closeShellSession(currentSession);
  };

  const lazyPromptForCredentials = async (): Promise<boolean> => {
    const { runCredentialPrompt } = await import("../ui/setup.js");
    if (await hasActiveShellCredentials(opts)) {
      // Creds appeared from env between calls — clear the disabled flag.
      assistantDisabledReason = undefined;
      credentialsMissing = false;
      return true;
    }
    const credentialOutcome = await runCredentialPrompt(store, "shell");
    const result = await applyCredentialOutcome(credentialOutcome, opts);
    if (result.message) {
      appendToHistory(store, {
        type: "output",
        text: result.message,
        timestamp: Date.now(),
      });
    }
    if (!result.enabled) {
      assistantDisabledReason = result.message ?? CREDENTIALS_CANCELLED_MESSAGE;
      credentialsMissing = true;
      return false;
    }
    assistantDisabledReason = undefined;
    credentialsMissing = false;
    return true;
  };

  const ensureSession = async (): Promise<AgentSession | undefined> => {
    if (assistantDisabledReason) {
      // If the only reason is missing creds, give the user a chance to provide them now.
      if (credentialsMissing) {
        const ok = await lazyPromptForCredentials();
        if (!ok) return undefined;
      } else {
        return undefined;
      }
    }

    const desiredCwd = currentCwd();
    if (session && sessionCwd === desiredCwd) {
      return session;
    }

    if (session) {
      await closeSession();
    }

    const outcome = createShellSession(opts.runtime, {
      ...buildSessionOptions(opts, systemPrompt),
      cwd: desiredCwd,
    });
    session = outcome.session;
    sessionCwd = outcome.session ? desiredCwd : undefined;
    sessionError = outcome.error;
    return session;
  };

  const abortActiveAction = (): void => {
    if (!activeActionKind) {
      abortDebug("abortActiveAction: no active action, skipping");
      return;
    }
    // Belt-and-suspenders: hard-kill every tracked Claude subprocess
    // before running the cooperative abort. If the onAbort handler
    // (or anything it calls) is stuck on an await, at least the
    // subprocess dies immediately. Per-session abort listeners still
    // fire their own kills — those are idempotent with this one.
    const killed = killAllClaudeSubprocesses();
    const onAbort = store.getState().shell?.onAbort;
    abortDebug(
      `abortActiveAction: kind=${activeActionKind} killed=${killed} onAbort=${
        onAbort ? "set" : "missing"
      }`,
    );
    // Pure delegation. Each setXAbort installer owns the
    // activeAbortRequested flag AND the kind-specific teardown
    // (controller.abort() for tools, closeSession + controller.abort()
    // for agents). We must NOT pre-set the flag here — the installed
    // handler's dedupe guard would then see the flag already set and
    // skip the real work, which is exactly why SIGINT-triggered
    // aborts silently no-op'd.
    onAbort?.();
  };

  const setToolAbort = (controller: AbortController): void => {
    activeActionKind = "tool";
    activeAbortRequested = false;
    abortDebug("setToolAbort: handler installed, flag reset");
    setAbortHandler(store, () => {
      if (activeAbortRequested) {
        abortDebug("tool onAbort: duplicate, swallowed by guard");
        return;
      }
      activeAbortRequested = true;
      noteAbortFired();
      abortDebug("tool onAbort: firing controller.abort()");
      markAbortRequested(store, "tool execution");
      controller.abort(new Error("Shell tool execution aborted"));
      // Immediately return the operator to the prompt instead of waiting
      // for the tool to notice the signal. A tool that ignores the signal
      // will still finish in the background; its cleanup path is idempotent
      // with what we do here. This is the core "Ctrl+C once goes back"
      // behavior — the alternative (waiting for the tool to unwind) felt
      // like the shell was hung even though the abort had fired.
      blacklistCurrentTurnRunIds();
      settleAbortedShellTurn(store, "tool execution", CANCELLED_TOOL_MESSAGE);
      activeActionKind = null;
      // Restore raw mode in case a Claude SDK subprocess disabled it. Must
      // happen before the next keystroke or the terminal echoes chars
      // below Ink's frame and Ctrl+C keeps missing `useInput`.
      ensureRawMode();
    });
  };

  const setAgentAbort = (): void => {
    activeActionKind = "agent";
    activeAbortRequested = false;
    abortDebug("setAgentAbort: handler installed, flag reset");
    setAbortHandler(store, () => {
      if (activeAbortRequested) {
        abortDebug("agent onAbort: duplicate, swallowed by guard");
        return;
      }
      activeAbortRequested = true;
      noteAbortFired();
      markAbortRequested(store, "agent request");
      // Mirror the tool-abort path: immediately return the operator to the
      // prompt instead of waiting for the LLM stream to unwind. Some backends
      // (notably the Claude Agent SDK subprocess) won't fully tear down the
      // HTTP stream on close() right away — without this, the shell looked
      // frozen until the stream naturally ended.
      blacklistCurrentTurnRunIds();
      const pendingAssistantText = store.getState().shell?.pendingAssistantText;
      if (pendingAssistantText) {
        appendToHistory(store, {
          type: "output",
          text: pendingAssistantText,
          timestamp: Date.now(),
        });
        setPendingAssistantText(store, undefined);
      }
      settleAbortedShellTurn(store, "agent request", CANCELLED_AGENT_MESSAGE);
      activeActionKind = null;
      // Restore raw mode — the session's subprocess almost certainly
      // disabled it. Without this the next keystroke echoes below Ink.
      ensureRawMode();
      // Tear down the session in the background. Any straggler messages the
      // for-await loop drains are swallowed via the `activeAbortRequested`
      // guard inside the loop; `ensureSession()` lazily opens a fresh
      // session on the next agent turn.
      void closeSession();
    });
  };

  const finishActiveAction = (): boolean => {
    const wasAborted = activeAbortRequested;
    activeActionKind = null;
    activeAbortRequested = false;
    return wasAborted;
  };

  function handleExit(): void {
    alive = false;
  }

  async function handleInput(input: string): Promise<void> {
    if (!alive) return;

    // Fresh per-turn runId set — previous turn's task runIds were either
    // consumed normally (tasks done, no more events) or blacklisted on
    // abort. Clearing here keeps `blacklistCurrentTurnRunIds()` tied to
    // the turn that actually got aborted.
    seenRunIdsThisTurn.clear();
    const preserveTaskStory = isTaskStoryNavigationInput(input);
    activeTurnId = preserveTaskStory
      ? (store.getState().shell?.taskStory?.activeTurnId ?? activeTurnId ?? nextTurnId())
      : nextTurnId();
    const startBusy = shouldStartTurnBusy(input, core, shellCtx.focusedModule);
    beginShellTurn(store, input, shellCtx.focusedModule, activeTurnId, {
      preserveTaskStory,
      processing: startBusy,
    });
    if (!preserveTaskStory) {
      appendStoryEvent(
        store,
        {
          kind: "phase",
          status: "running",
          importance: "primary",
          message: `Started ${input}`,
          source: "shell",
          ...(activeTurnId ? { turnId: activeTurnId } : {}),
        },
        { persistHistory: false },
      );
    }

    // First pass: msfconsole-style dispatcher. A few Ink shell sub-views have
    // view-local bare verbs (`show build` in the prompts editor, focused
    // `show options`) that must route through the shell state before the core
    // dispatcher claims generic `show`/`set`.
    const shellBeforeDispatch = store.getState().shell;
    const useShellRouterFirst = shouldRouteShellInputBeforeDispatcher(
      input,
      shellBeforeDispatch,
      shellCtx,
    );
    let dispatched: Awaited<ReturnType<typeof driver.handle>>;
    if (useShellRouterFirst) {
      dispatched = { matched: false };
    } else {
      const controller = new AbortController();
      setToolAbort(controller);
      try {
        dispatched = await driver.handle(input, controller.signal);
      } catch (err) {
        // Tasks that honor `ctx.signal` bubble AbortError up through the
        // dispatcher. The abort handler already rendered `[aborted]` and
        // returned the operator to the prompt — swallow the error here so
        // there's no unhandled-rejection noise.
        if (controller.signal.aborted) {
          finishActiveAction();
          return;
        }
        appendToHistory(store, {
          type: "error",
          text: toErrorMessage(err),
          timestamp: Date.now(),
        });
        finishActiveAction();
        clearTransientShellState(store);
        setProcessing(store, false);
        return;
      } finally {
        // Any tool invocation might have spawned a Claude SDK subprocess that
        // disabled raw mode; re-assert so the next keystroke lands in Ink.
        ensureRawMode();
      }
      // If Ctrl+C fired during dispatch, the abort handler already returned the
      // operator to the prompt and marked `processing: false`. Swallow the
      // late output/exit from the now-cancelled tool so it doesn't append
      // after the operator has moved on. Gate on the per-turn controller so a
      // racing next-turn's `setToolAbort` (which resets `activeAbortRequested`)
      // can't let this turn's output through.
      if (controller.signal.aborted) {
        finishActiveAction();
        return;
      }
    }
    if (dispatched.matched) {
      if (dispatched.push || dispatched.pop) syncFocusFromDispatcher();
      if (dispatched.push || dispatched.pop) {
        try {
          await hydrateShellStore(store, core, opts, dataDir);
        } catch {
          /* best-effort */
        }
      }
      if (dispatched.output) {
        const latestSummary = latestToolCallResultOutput(store.getState().shell);
        if (shouldAppendSeparateBodyOutput(dispatched.output, latestSummary)) {
          appendToHistory(store, {
            type: "output",
            text: dispatched.output,
            timestamp: Date.now(),
          });
        }
        if (!dispatched.push && !dispatched.pop) {
          const nextView = reconcileShellViewAfterPlainOutput(
            shellBeforeDispatch?.shellView ?? "catalog",
            shellCtx.focusedModule,
            input,
          );
          if (shellBeforeDispatch && nextView !== shellBeforeDispatch.shellView) {
            updateShell(store, (shell) => ({ ...shell, shellView: nextView }));
          }
        }
      }
      finishActiveAction();
      if (dispatched.exit) {
        clearTransientShellState(store);
        setProcessing(store, false);
        handleExit();
        return;
      }
      clearTransientShellState(store);
      setProcessing(store, false);
      return;
    }
    // Not matched — clear the controller registered above; subsequent routers
    // register their own AbortController as needed.
    if (!useShellRouterFirst) finishActiveAction();

    const shellState = store.getState().shell;
    if (!shellState) {
      appendToHistory(store, {
        type: "error",
        text: "Shell state missing — cannot route input.",
        timestamp: Date.now(),
      });
      clearTransientShellState(store);
      setProcessing(store, false);
      return;
    }
    const localResult = routeInput(input, core, opts, shellCtx, shellState);

    if (localResult.setFocus !== undefined) {
      shellCtx.focusedModule = localResult.setFocus;
    }
    if (localResult.targetUpdated) {
      syncShellTargetToGlobals(opts, globals);
    }
    if (localResult.shellStateUpdater) {
      updateShell(store, localResult.shellStateUpdater);
    }
    syncShellState(store, opts, shellCtx.focusedModule, workspaceManager);
    if (
      localResult.setFocus !== undefined ||
      localResult.shellStateUpdater ||
      localResult.targetUpdated
    ) {
      try {
        await hydrateShellStore(store, core, opts, dataDir);
      } catch {
        /* best-effort */
      }
    }
    if (localResult.output && !localResult.shellStateUpdater) {
      const nextView = reconcileShellViewAfterPlainOutput(
        shellState.shellView,
        shellCtx.focusedModule,
        input,
      );
      if (nextView !== shellState.shellView) {
        updateShell(store, (shell) => ({ ...shell, shellView: nextView }));
      }
    }

    if (localResult.exit) {
      setProcessing(store, false);
      clearTransientShellState(store);
      handleExit();
      return;
    }

    if (localResult.resetSession) {
      await closeSession();
    }

    if (localResult.clearHistory) {
      updateShell(store, (shell) => ({
        ...shell,
        history: [],
      }));
    }

    if (localResult.asyncExecute) {
      setProcessing(store, true);
      const controller = new AbortController();
      setToolAbort(controller);
      const asyncStartedAt = Date.now();
      const asyncTool = localResult.executedToolName
        ? core.registry.resolveTool(localResult.executedToolName)?.tool
        : undefined;
      const asyncToolLabel =
        asyncTool?.displayName ?? localResult.executedToolName ?? "shell action";
      if (localResult.executedToolName) {
        const startStory = appendStoryEvent(
          store,
          {
            kind: "tool",
            status: "running",
            importance: "primary",
            message: `${asyncToolLabel} started`,
            source: localResult.executedToolName,
            ...(activeTurnId ? { turnId: activeTurnId } : {}),
            durable: true,
          },
          { persistHistory: false },
        );
        updateShell(store, (shell) => ({
          ...shell,
          currentTool: {
            name: localResult.executedToolName!,
            startedAt: asyncStartedAt,
            lastEventAt: asyncStartedAt,
            ...(asyncTool?.displayName ? { displayName: asyncTool.displayName } : {}),
            ...(activeTurnId ? { turnId: activeTurnId } : {}),
            storyTail: [startStory],
          },
        }));
        if (asyncTool) {
          const liveShell = store.getState().shell;
          if (liveShell) {
            seedFocusedModuleRun(store, liveShell, asyncTool, asyncStartedAt);
          }
        }
      }
      try {
        const execResult = normalizeAsyncExecutionResult(
          await localResult.asyncExecute(controller.signal),
        );
        // Gate on the per-turn controller rather than the shared
        // `activeAbortRequested` flag so a racing next-turn's setToolAbort
        // can't let this turn's stale output through.
        if (controller.signal.aborted) {
          finishActiveAction();
          return;
        }
        if (localResult.executedToolName) {
          updateShell(store, (shell) => ({
            ...shell,
            lastUsedTool: localResult.executedToolName,
            moduleCatalog: applyModuleRunTelemetry(
              shell.moduleCatalog,
              localResult.executedToolName!,
              execResult.ok === false ? "fail" : "ok",
              execResult.costUsd,
            ),
          }));
        }
        if (localResult.executedToolName) {
          patchCheckpointModuleRunTerminal(
            store,
            localResult.executedToolName,
            execResult.ok === false ? "error" : "done",
            execResult.costUsd,
          );
          const elapsed = Math.max(0, Math.floor((Date.now() - asyncStartedAt) / 1000));
          appendStoryEvent(store, {
            kind: "result",
            status: execResult.ok === false ? "fail" : "ok",
            importance: "primary",
            message: `${asyncToolLabel} ${execResult.ok === false ? "failed" : "done"}`,
            detail: execResult.output
              ? (execResult.output.split("\n", 1)[0] ?? execResult.output)
              : `${elapsed}s`,
            source: localResult.executedToolName,
            ...(activeTurnId ? { turnId: activeTurnId } : {}),
            ...(execResult.costUsd ? { costUsd: execResult.costUsd } : {}),
            durable: true,
          });
        }
        try {
          await hydrateShellStore(store, core, opts, dataDir);
        } catch {
          /* best-effort */
        }
        if (
          shouldAppendSeparateBodyOutput(
            execResult.output,
            latestToolCallResultOutput(store.getState().shell),
          )
        ) {
          appendToHistory(store, {
            type: "output",
            text: execResult.output,
            timestamp: Date.now(),
          });
        } else {
          appendToHistory(store, {
            type: execResult.ok === false ? "error" : "output",
            text: `${asyncToolLabel} ${execResult.ok === false ? "failed." : "done."}`,
            timestamp: Date.now(),
          });
        }
      } catch (error) {
        const wasAborted = controller.signal.aborted;
        finishActiveAction();
        if (localResult.executedToolName) {
          patchCheckpointModuleRunTerminal(
            store,
            localResult.executedToolName,
            wasAborted ? "aborted" : "error",
          );
          updateShell(store, (shell) => ({
            ...shell,
            moduleCatalog: applyModuleRunTelemetry(
              shell.moduleCatalog,
              localResult.executedToolName!,
              wasAborted ? "abort" : "fail",
            ),
          }));
        }
        if (wasAborted) {
          // Abort handler already rendered `[aborted]` — no need to also
          // append CANCELLED_TOOL_MESSAGE.
          return;
        }
        if (localResult.executedToolName) {
          appendStoryEvent(store, {
            kind: "result",
            status: "fail",
            importance: "primary",
            message: `${asyncToolLabel} failed`,
            detail: toErrorMessage(error),
            source: localResult.executedToolName,
            ...(activeTurnId ? { turnId: activeTurnId } : {}),
            durable: true,
          });
        }
        appendToHistory(store, {
          type: "error",
          text: toErrorMessage(error),
          timestamp: Date.now(),
        });
        try {
          await hydrateShellStore(store, core, opts, dataDir);
        } catch {
          /* best-effort */
        }
        clearTransientShellState(store);
        setProcessing(store, false);
        return;
      } finally {
        // Tool may have spawned a subprocess that disabled raw mode.
        ensureRawMode();
      }

      finishActiveAction();
      clearTransientShellState(store);
      setProcessing(store, false);
      return;
    }

    // Only `/ask` (and the `?` prefix) set `askQuestion` to route through
    // the agent session; every other unknown input gets an "Unknown command"
    // message from routeInput, never a silent handoff.
    if (localResult.askQuestion === undefined) {
      if (localResult.output) {
        appendToHistory(store, { type: "output", text: localResult.output, timestamp: Date.now() });
      }
      if (localResult.keepProcessing) {
        setProcessing(store, true);
      } else {
        clearTransientShellState(store);
        setProcessing(store, false);
      }
      return;
    }

    const agentInput = localResult.askQuestion;
    setProcessing(store, true);
    const currentSession = await ensureSession();
    if (!currentSession) {
      appendToHistory(store, {
        type: "error",
        text: assistantDisabledReason ?? sessionError ?? DEFAULT_NO_SESSION_MESSAGE,
        timestamp: Date.now(),
      });
      clearTransientShellState(store);
      setProcessing(store, false);
      return;
    }

    setAgentAbort();
    appendStoryEvent(
      store,
      {
        kind: "phase",
        status: "running",
        importance: "primary",
        message: "Agent request started",
        source: "agent",
        ...(activeTurnId ? { turnId: activeTurnId } : {}),
        durable: true,
      },
      { persistHistory: false },
    );

    let pendingErrorText: string | undefined;
    let fallbackResultText = "";

    try {
      for await (const message of currentSession.query(agentInput)) {
        if (!alive) break;
        // Ctrl+C already handed the operator back the prompt and rendered
        // `[cancelled]` via the abort handler. Drain the rest of the stream
        // silently so late tool-use / assistant / result events don't
        // append to history after the fact.
        if (activeAbortRequested) continue;

        switch (message.type) {
          case "assistant": {
            const text = extractAssistantText(message.content);
            if (text) {
              appendPendingAssistantText(store, text);
            }
            // Surface each tool-use block as a cc-repo-style `⏺ tool(hint)`
            // header. Dedupe against an immediately-preceding tool-call for
            // the same tool name (e.g. when the shell dispatcher's own
            // `runToolFromDispatcher` header was just emitted). Progress
            // body lines accumulate naturally via `task:activity` bus events
            // subscribed elsewhere.
            const headers = extractToolUseHeaders(message.content);
            for (const header of headers) {
              const historyArr = store.getState().shell?.history ?? [];
              const last = historyArr[historyArr.length - 1];
              const isDuplicate =
                last?.type === "tool-call" &&
                last.tool === header.name &&
                last.inputHint === header.inputHint;
              if (isDuplicate) continue;
              // Best-effort lookup of the tool's displayName so agent-driven
              // calls also surface human-friendly labels. Misses fall back
              // to the raw `module:action` name.
              const matchedTool = core.registry.resolveTool(header.name)?.tool;
              const agentDisplayName = matchedTool?.displayName;
              const label = agentDisplayName ?? header.name;
              const headerText = header.inputHint
                ? `⏺ ${label}(${header.inputHint})`
                : `⏺ ${label}`;
              pushToolActivity(store, header.inputHint ? `${label} · ${header.inputHint}` : label);
              // Use the Anthropic tool_use.id as the history entry's `id`
              // when available — lets `tool-summary` messages correlate
              // by `precedingToolUseIds` to flip status on resolution.
              // Fall back to a synthetic id so the entry is still
              // mutable (liveActivities tail, Static exclusion).
              const entryId =
                header.id ?? `atc-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
              appendToHistory(store, {
                type: "tool-call",
                id: entryId,
                ...(header.id ? { toolUseId: header.id } : {}),
                tool: header.name,
                ...(agentDisplayName ? { displayName: agentDisplayName } : {}),
                ...(header.inputHint ? { inputHint: header.inputHint } : {}),
                status: "running",
                text: headerText,
                timestamp: Date.now(),
              });
            }
            break;
          }

          case "tool-progress": {
            updateToolActivity(store, message.toolName, message.elapsedSeconds);
            // Also feed the live tail of the matching agent-driven
            // `⏺` entry so operators watching the scrollback see a
            // ticking "12s" / tool-specific heartbeat under the header.
            const history = store.getState().shell?.history ?? [];
            const entry = history.find(
              (e) => e.type === "tool-call" && e.toolUseId === message.toolUseId,
            );
            if (entry?.id && entry.status === "running") {
              pushLiveActivity(store, entry.id, `${message.elapsedSeconds}s`);
            }
            break;
          }

          case "tool-summary": {
            // Flip any agent-driven `⏺` entries whose toolUseId is in the
            // batch's `precedingToolUseIds` from "running" → "ok" AND attach
            // the summary text as `resultOutput` so ToolCallEntry renders
            // `⎿  Read path (42 lines)` under the `⏺` header — same shape
            // as operator-typed direct dispatches get via `renderResult`.
            // Previously the summary went to a separate "output" history
            // entry *in addition to* the bus-path tool-progress echo,
            // producing three rows per tool call; now it's one.
            const precedingIds = message.precedingToolUseIds ?? [];
            const firstSummaryLine = message.summary.split("\n", 1)[0]?.trim() ?? message.summary;
            for (const toolUseId of precedingIds) {
              const history = store.getState().shell?.history ?? [];
              const entry = history.find(
                (e) => e.type === "tool-call" && e.toolUseId === toolUseId,
              );
              if (entry?.id) {
                patchHistoryEntry(store, entry.id, {
                  status: "ok",
                  liveActivities: undefined,
                  liveActivitiesDropped: undefined,
                  ...(firstSummaryLine ? { resultOutput: firstSummaryLine } : {}),
                });
              }
            }
            // Drop currentTool so ToolRunningStatus stops rendering; no
            // separate scrollback append — the tool-call entry owns the
            // visible record now.
            updateShell(store, (shell) => ({ ...shell, currentTool: undefined }));
            const trailer = formatContextTrailer(
              opts.target ? path.resolve(opts.target) : process.cwd(),
            );
            if (trailer) {
              appendToHistory(store, {
                type: "output",
                text: trailer,
                timestamp: Date.now(),
              });
            }
            break;
          }

          case "result": {
            if ("result" in message) {
              fallbackResultText = message.result;
            } else if (message.subtype === "error_aborted") {
              pendingErrorText = CANCELLED_AGENT_MESSAGE;
            } else {
              pendingErrorText = `Error: ${message.errors.join("; ")}`;
            }
            break;
          }
        }
      }
    } catch (error) {
      const wasAborted = finishActiveAction();
      // The abort handler already flushed pending text, rendered the
      // cancel message, and cleared processing. Common cause of landing
      // here post-abort: the HTTP client throws an AbortError when the
      // internal signal fires. Swallow it.
      if (wasAborted) {
        ensureRawMode();
        return;
      }
      const message = toErrorMessage(error);
      appendStoryEvent(store, {
        kind: "result",
        status: "fail",
        importance: "primary",
        message: "Agent request failed",
        detail: message,
        source: "agent",
        ...(activeTurnId ? { turnId: activeTurnId } : {}),
        durable: true,
      });
      const pendingAssistantText = store.getState().shell?.pendingAssistantText;
      if (pendingAssistantText) {
        appendToHistory(store, {
          type: "output",
          text: pendingAssistantText,
          timestamp: Date.now(),
        });
      }
      setPendingAssistantText(store, undefined);
      // Seal any agent-driven `⏺` entries that were still pulsing when
      // the error / abort fired. Otherwise they'd stay "running" forever.
      finalizeRunningToolCalls(store, wasAborted ? "abort" : "fail");
      appendToHistory(store, {
        type: "error",
        text: message,
        timestamp: Date.now(),
      });
      clearTransientShellState(store);
      setProcessing(store, false);
      ensureRawMode();
      return;
    }

    const wasAborted = finishActiveAction();
    if (!wasAborted) {
      appendStoryEvent(store, {
        kind: "result",
        status: pendingErrorText ? "fail" : "ok",
        importance: "primary",
        message: pendingErrorText ? "Agent request failed" : "Agent request complete",
        ...(pendingErrorText ? { detail: pendingErrorText } : {}),
        source: "agent",
        ...(activeTurnId ? { turnId: activeTurnId } : {}),
        durable: true,
      });
    }
    // Clean end-of-turn — mark any still-"running" tool-call entries as
    // resolved. Most should already be `ok` from `tool-summary`, but if
    // the SDK didn't emit one for every batch (or we missed the
    // correlation), this catches the leak.
    finalizeRunningToolCalls(store, wasAborted ? "abort" : "ok");
    const pendingAssistantText = store.getState().shell?.pendingAssistantText;
    if (pendingAssistantText) {
      appendToHistory(store, {
        type: "output",
        text: finalizeAssistantText(pendingAssistantText, fallbackResultText),
        timestamp: Date.now(),
      });
      setPendingAssistantText(store, undefined);
    } else if (fallbackResultText) {
      appendToHistory(store, {
        type: "output",
        text: fallbackResultText,
        timestamp: Date.now(),
      });
    }

    if (pendingErrorText) {
      appendToHistory(store, {
        type: pendingErrorText === CANCELLED_AGENT_MESSAGE ? "output" : "error",
        text: pendingErrorText,
        timestamp: Date.now(),
      });
    }

    clearTransientShellState(store);
    setProcessing(store, false);
    // Agent turn may have spawned Claude SDK subprocesses; restore raw mode.
    ensureRawMode();
  }

  // Pre-compute the .kuzushi/ artifact banner so it lands in the FIRST
  // shell-state render. Appending it after `store.update` would grow the
  // <Static> stream mid-stream and Ink's previous dynamic frame escapes
  // the clearing region — the catalog appears to render twice in scrollback.
  const initialHistory: ShellHistoryEntry[] = [];
  {
    const banner = formatArtifactBanner(opts.target ? path.resolve(opts.target) : process.cwd());
    if (banner) {
      initialHistory.push({ type: "output", text: banner, timestamp: Date.now() });
    }
  }
  const initialThreatTarget = opts.target ? path.resolve(opts.target) : process.cwd();
  const initialThreatModel = loadPersistentThreatModel(initialThreatTarget);
  const initialThreatModelSource = initialThreatModel
    ? {
        path: path.join(initialThreatTarget, ".kuzushi", "threat-model.json"),
        mtimeMs: safeMtimeMs(path.join(initialThreatTarget, ".kuzushi", "threat-model.json")),
      }
    : undefined;

  let initialShell: ShellState = {
    modules: modules.map((module) => module.id),
    moduleCatalog: buildModuleCatalog(modules, core, catalogRuns),
    tools: tools.map(({ tool }) => tool.name),
    focusedModule: null,
    shellView: "catalog",
    openFindingId: null,
    target: opts.target ?? null,
    workspace: workspaceDisplayName(opts, workspaceManager),
    tuneSnapshot: buildTuneSnapshot(opts.config, dataDir, null),
    history: initialHistory,
    commandHistory,
    moduleOptions: {},
    contextSnapshot: loadedSnapshot ?? undefined,
    threatModel: initialThreatModel,
    ...(initialThreatModelSource ? { threatModelSource: initialThreatModelSource } : {}),
    processing: false,
    onInput: handleInput,
    onExit: handleExit,
    onAbort: abortActiveAction,
  };
  const initialHydration = await hydrateShellArtifacts(initialShell, core, opts, dataDir);
  initialShell = {
    ...initialHydration.shell,
    onInput: handleInput,
    onExit: handleExit,
    onAbort: abortActiveAction,
  };

  // Splash policy: render the wordmark splash on the operator's first ever
  // boot for this workspace (catalogRuns empty), and skip it thereafter so
  // returning sessions get straight to the catalog. The chrome strip
  // (workspace/target/scope) carries the same identity context, so the
  // splash earns its 8 vertical rows only when there's nothing else on
  // screen to greet the operator.
  const isFirstBoot = catalogRuns.length === 0;
  store.update({
    mode: "shell",
    shell: initialShell,
    ...(initialHydration.summary !== undefined ? { summary: initialHydration.summary } : {}),
    ...(isFirstBoot ? {} : { shellSplashShown: true }),
  });

  // Process-level SIGINT fallback. Ink's `useInput` is the primary Ctrl+C
  // path — terminal raw mode delivers the 0x03 byte to stdin and Ink dispatches
  // it. But the Claude Agent SDK subprocess (spawned by randori and similar
  // tools) can momentarily break raw mode or steal keystrokes, at which point
  // the terminal falls back to sending SIGINT. Without this handler, cli.ts's
  // default SIGINT listener would kill the whole process on that fallback
  // path; with it, we abort the in-flight action and stay in the shell.
  //
  // We take over SIGINT/SIGTERM for the shell's lifetime so our handler wins.
  // On shell exit (`/exit` → `handleExit`), the process exits anyway, so no
  // restore step is needed.
  const priorSigintListeners = process.listeners("SIGINT").slice();
  const priorSigtermListeners = process.listeners("SIGTERM").slice();
  process.removeAllListeners("SIGINT");
  process.removeAllListeners("SIGTERM");
  const isLikelyDuplicateAbortSignal = (now: number): boolean => {
    return lastAbortFiredAt > 0 && now - lastAbortFiredAt < SIGNAL_DUPLICATE_GRACE_MS;
  };
  const forwardSigintToPriorListeners = (source: string): void => {
    handleExit();
    abortDebug(`${source}: exiting shell via prior SIGINT listeners`);
    for (const listener of priorSigintListeners) {
      try {
        (listener as NodeJS.SignalsListener)("SIGINT");
      } catch {
        /* best-effort */
      }
    }
  };
  const maybeSwallowDuplicateAbortSignal = (source: string): boolean => {
    const now = Date.now();
    if (isLikelyDuplicateAbortSignal(now)) {
      abortDebug(`${source}: duplicate immediately after abort, swallowing`);
      return true;
    }
    return false;
  };
  const shellSigintHandler = (): void => {
    if (maybeSwallowDuplicateAbortSignal("SIGINT")) return;
    if (activeActionKind) {
      // Belt-and-suspenders. The onAbort chain (abortActiveAction →
      // handler → controller.abort() → per-scope kill listener) is
      // supposed to reach the Claude SDK subprocess, but if any hop on
      // that path is racing / stuck / not yet wired (e.g. a subprocess
      // that just spawned hasn't had its abort listener attached yet),
      // the spinner keeps spinning. Hard-killing every tracked Claude
      // subprocess up front guarantees Ctrl+C actually stops work —
      // the cooperative abort still runs right after to tear the UI
      // down and return the operator to the prompt.
      const killed = killAllClaudeSubprocesses();
      abortDebug(`SIGINT: activeActionKind=${activeActionKind} killed=${killed}`);
      abortActiveAction();
      return;
    }
    // Idle — fall through to the original cli.ts shutdown behavior so
    // Ctrl+C at an empty prompt still exits cleanly.
    //
    // Guard: a SIGINT immediately after a tool/agent abort is almost certainly
    // a duplicate — pnpm/tsx and some terminal drivers forward the same
    // Ctrl+C twice (once as 0x03 byte, once as SIGINT) across the
    // raw-mode flip. Keep this window short so a real second Ctrl+C can
    // still force an exit while an aborting task is unwinding.
    if (isLikelyDuplicateAbortSignal(Date.now())) {
      abortDebug("SIGINT at idle — immediately after abort, swallowing duplicate");
      return;
    }
    abortDebug("SIGINT at idle — forwarding to prior listeners");
    forwardSigintToPriorListeners("SIGINT at idle");
  };
  const shellSigtermHandler = (): void => {
    for (const listener of priorSigtermListeners) {
      try {
        (listener as NodeJS.SignalsListener)("SIGTERM");
      } catch {
        /* best-effort */
      }
    }
  };
  process.on("SIGINT", shellSigintHandler);
  process.on("SIGTERM", shellSigtermHandler);

  // Raw-byte Ctrl+C watcher — independent of Ink's `useInput`. If the
  // Claude subprocess has grabbed /dev/tty as a separate fd and broken
  // raw mode, Ink's input pipeline can stop firing. But stdin itself
  // still receives the 0x03 byte whenever raw mode is on (which our
  // watchdog restores at 75ms intervals). Watching the byte stream
  // directly catches Ctrl+C even if Ink has lost the pipe, providing
  // a third independent abort path alongside SIGINT and useInput.
  const rawStdinAbortListener = (chunk: Buffer): void => {
    // 0x03 is the byte terminal raw mode sends for Ctrl+C. 0x04 is Ctrl+D;
    // both count as an abort trigger.
    if (!(chunk.includes(0x03) || chunk.includes(0x04))) return;
    if (maybeSwallowDuplicateAbortSignal("raw-stdin")) return;
    if (!activeActionKind) return;
    abortDebug(`raw-stdin: 0x03/0x04 detected, activeActionKind=${activeActionKind}`);
    const killed = killAllClaudeSubprocesses();
    abortDebug(`raw-stdin: killed=${killed} subprocesses`);
    abortActiveAction();
  };
  try {
    process.stdin.on("data", rawStdinAbortListener);
  } catch {
    /* best-effort — some test harnesses pipe stdin unusually */
  }

  // Independent Ctrl+C reader bolted directly to /dev/tty. The Claude
  // SDK subprocess calls TIOCSCTTY and becomes the terminal's
  // foreground process group leader, which means terminal keystrokes
  // (including Ctrl+C → SIGINT) stop reaching our parent's stdin or
  // our pgrp's signal handler. `/dev/tty` is a magic device that
  // always resolves to the *calling* process's controlling terminal,
  // so opening it as our own fd gives us a read channel the
  // subprocess can't intercept. We put it in raw mode on our fd and
  // watch for 0x03 bytes.
  //
  // Best-effort: the open can fail (no controlling terminal, CI mode,
  // etc.) and that's fine — the other three abort paths remain.
  let devTtyAbortTeardown: (() => void) | undefined;
  if (process.stdin.isTTY) {
    try {
      const ttyModule = await import("node:tty");
      const fsModule = await import("node:fs");
      const ttyFd = fsModule.openSync("/dev/tty", "r");
      const ttyStream = new ttyModule.ReadStream(ttyFd);
      try {
        ttyStream.setRawMode(true);
      } catch {
        /* setRawMode may be unavailable on some platforms */
      }
      const devTtyListener = (chunk: Buffer): void => {
        if (!(chunk.includes(0x03) || chunk.includes(0x04))) return;
        if (maybeSwallowDuplicateAbortSignal("dev-tty")) return;
        if (!activeActionKind) return;
        abortDebug(
          `dev-tty: 0x03/0x04 detected on /dev/tty fd, activeActionKind=${activeActionKind}`,
        );
        const killed = killAllClaudeSubprocesses();
        abortDebug(`dev-tty: killed=${killed} subprocesses`);
        abortActiveAction();
      };
      ttyStream.on("data", devTtyListener);
      ttyStream.on("error", (err) => {
        abortDebug(`dev-tty: stream error ${toErrorMessage(err)}`);
      });
      devTtyAbortTeardown = () => {
        try {
          ttyStream.off("data", devTtyListener);
          ttyStream.destroy();
          fsModule.closeSync(ttyFd);
        } catch {
          /* best-effort cleanup */
        }
      };
      abortDebug("dev-tty: reader installed on /dev/tty");
    } catch (err) {
      abortDebug(`dev-tty: could not open /dev/tty: ${toErrorMessage(err)}`);
    }
  }

  // The interactive shell uses the configured runtime. Built-in backends
  // expose createSession(); Claude is only swapped in as a compatibility
  // fallback for custom runtimes that cannot create shell sessions.
  await ensureClaudeShellRuntime(opts, store);
  {
    const { runCredentialPrompt } = await import("../ui/setup.js");
    if (!(await hasActiveShellCredentials(opts))) {
      const credentialOutcome = await runCredentialPrompt(store, "shell");
      const result = await applyCredentialOutcome(credentialOutcome, opts);
      if (!result.enabled) {
        assistantDisabledReason = result.message ?? CREDENTIALS_CANCELLED_MESSAGE;
        credentialsMissing = true;
      }
      if (result.message) {
        appendToHistory(store, {
          type: "output",
          text: result.message,
          timestamp: Date.now(),
        });
      }
      // Credentials were just provided — re-check the runtime can create
      // sessions (no-op if the current backend already supports sessions).
      await ensureClaudeShellRuntime(opts, store);
    }
  }

  try {
    while (alive) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  } finally {
    try {
      saveShellCommandHistory(dataDir, store.getState().shell?.commandHistory ?? []);
    } finally {
      try {
        process.stdin.off("data", rawStdinAbortListener);
      } catch {
        /* best-effort */
      }
      process.off("SIGINT", shellSigintHandler);
      process.off("SIGTERM", shellSigtermHandler);
      devTtyAbortTeardown?.();
      await closeSession();
      await jobManager.shutdown();
      scheduler?.stop();
      spoolController.stop();
      await core.dispose();
      await bus.close();
      cleanupUI();
    }
  }
}

// Readline fallback (non-TTY) — for piped input and CI

async function startReadlineShell(
  core: CopilotCore,
  opts: ShellOptions,
  bus: MessageBus,
  systemPrompt: string,
  dataDir: string,
  loadedSnapshot?: ContextSnapshot | null,
  workspaceManager?: import("../workspace/manager.js").WorkspaceManager,
): Promise<void> {
  const { createInterface } = await import("node:readline");

  const commandHistory = loadShellCommandHistory(dataDir);
  const modules = core.listModules();
  const tools = core.registry.allTools();
  const catalogRuns = await readRunHistoryForCatalog(dataDir, opts.target);
  const rlCtx: ShellContext = { focusedModule: null, workspaceManager, dataDir };
  const initialThreatTarget = opts.target ? path.resolve(opts.target) : process.cwd();
  const initialThreatModel = loadPersistentThreatModel(initialThreatTarget);
  const initialThreatModelSource = initialThreatModel
    ? {
        path: path.join(initialThreatTarget, ".kuzushi", "threat-model.json"),
        mtimeMs: safeMtimeMs(path.join(initialThreatTarget, ".kuzushi", "threat-model.json")),
      }
    : undefined;
  let rlState: ShellState = {
    modules: modules.map((module) => module.id),
    moduleCatalog: buildModuleCatalog(modules, core, catalogRuns),
    tools: tools.map(({ tool }) => tool.name),
    focusedModule: null,
    shellView: "catalog",
    openFindingId: null,
    target: opts.target ?? null,
    workspace: workspaceDisplayName(opts, workspaceManager),
    tuneSnapshot: buildTuneSnapshot(opts.config, dataDir, null),
    history: [],
    commandHistory,
    moduleOptions: {},
    contextSnapshot: loadedSnapshot ?? undefined,
    threatModel: initialThreatModel,
    ...(initialThreatModelSource ? { threatModelSource: initialThreatModelSource } : {}),
    processing: false,
  };
  try {
    rlState = (await hydrateShellArtifacts(rlState, core, opts, dataDir)).shell;
  } catch {
    /* best-effort */
  }

  let session: AgentSession | undefined;
  let sessionCwd: string | undefined;
  let sessionError: string | undefined;
  let assistantDisabledReason: string | undefined;
  let activeActionKind: "tool" | "agent" | null = null;
  let activeAbortRequested = false;
  let activeToolController: AbortController | null = null;

  const closeSession = async (): Promise<void> => {
    const currentSession = session;
    session = undefined;
    sessionCwd = undefined;
    await closeShellSession(currentSession);
  };

  const currentCwd = (): string => (opts.target ? path.resolve(opts.target) : process.cwd());

  const ensureSession = async (): Promise<AgentSession | undefined> => {
    if (assistantDisabledReason) {
      return undefined;
    }

    const desiredCwd = currentCwd();
    if (session && sessionCwd === desiredCwd) {
      return session;
    }

    if (session) {
      await closeSession();
    }

    const outcome = createShellSession(opts.runtime, {
      ...buildSessionOptions(opts, systemPrompt),
      cwd: desiredCwd,
    });
    session = outcome.session;
    sessionCwd = outcome.session ? desiredCwd : undefined;
    sessionError = outcome.error;
    return session;
  };

  const abortActiveAction = (): void => {
    if (!activeActionKind) {
      return;
    }
    activeAbortRequested = true;
    if (activeActionKind === "tool") {
      activeToolController?.abort(new Error("Shell tool execution aborted"));
      return;
    }
    void closeSession();
  };
  process.on("SIGINT", abortActiveAction);

  console.error(formatWelcome(core, opts));

  // Surface available .kuzushi/ context so operators see what may be reused
  // before they run anything. Silent on fresh dirs.
  {
    const banner = formatArtifactBanner(opts.target ? path.resolve(opts.target) : process.cwd());
    if (banner) console.error(`\n${banner}\n`);
  }

  // Startup credential prompt for the readline shell. Only runs when stderr is
  // a TTY (so users in CI/piped contexts aren't blocked) and the active
  // backend has no credentials available yet. Done BEFORE creating the main
  // `rl` so the prompt's own readline interface owns stdin uncontested.
  // Safety-net: swap in Claude only if the configured runtime doesn't expose
  // createSession(). Built-in backends (claude, pi-ai) both support sessions,
  // so this is a no-op for them. Done before the credential prompt so the
  // prompt can guide the user to enable whichever backend is active.
  await ensureClaudeShellRuntime(opts);
  if (process.stderr.isTTY) {
    const { runReadlineCredentialPrompt } = await import("../ui/setup.js");
    if (!(await hasActiveShellCredentials(opts))) {
      const credentialOutcome = await runReadlineCredentialPrompt();
      const result = await applyCredentialOutcome(credentialOutcome, opts);
      if (!result.enabled) {
        assistantDisabledReason = result.message ?? CREDENTIALS_CANCELLED_MESSAGE;
      }
      if (result.message) {
        process.stderr.write(`${result.message}\n`);
      }
      await ensureClaudeShellRuntime(opts);
    }
  }

  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const updatePrompt = (): void => {
    rl.setPrompt(buildShellPrompt(rlCtx.focusedModule));
  };
  updatePrompt();
  rl.prompt();

  try {
    for await (const line of rl) {
      const input = line.trim();
      if (!input) {
        rl.prompt();
        continue;
      }

      rlState = {
        ...rlState,
        commandHistory: capShellHistory([...rlState.commandHistory, input]),
      };

      const localResult = routeInput(input, core, opts, rlCtx, rlState);
      if (localResult.setFocus !== undefined) {
        rlCtx.focusedModule = localResult.setFocus;
        rlState = { ...rlState, focusedModule: rlCtx.focusedModule };
        updatePrompt();
      }
      if (localResult.shellStateUpdater) {
        rlState = localResult.shellStateUpdater(rlState);
      }
      rlState = {
        ...rlState,
        focusedModule: rlCtx.focusedModule,
        target: opts.target ?? null,
        workspace: workspaceDisplayName(opts, workspaceManager),
      };
      if (
        localResult.setFocus !== undefined ||
        localResult.shellStateUpdater ||
        localResult.targetUpdated
      ) {
        try {
          rlState = (await hydrateShellArtifacts(rlState, core, opts, dataDir)).shell;
        } catch {
          /* best-effort */
        }
      }
      if (localResult.exit) {
        break;
      }
      if (localResult.resetSession) {
        await closeSession();
      }
      if (localResult.clearHistory) {
        rlState = {
          ...rlState,
          history: [],
        };
      }
      if (localResult.asyncExecute) {
        const controller = new AbortController();
        activeActionKind = "tool";
        activeAbortRequested = false;
        activeToolController = controller;
        try {
          const execResult = normalizeAsyncExecutionResult(
            await localResult.asyncExecute(controller.signal),
          );
          if (localResult.executedToolName) {
            rlState = {
              ...rlState,
              lastUsedTool: localResult.executedToolName,
              moduleCatalog: applyModuleRunTelemetry(
                rlState.moduleCatalog,
                localResult.executedToolName,
                execResult.ok === false ? "fail" : "ok",
                execResult.costUsd,
              ),
            };
          }
          if (execResult.output) {
            await writeAndDrain(process.stdout, execResult.output);
          }
          try {
            rlState = (await hydrateShellArtifacts(rlState, core, opts, dataDir)).shell;
          } catch {
            /* best-effort */
          }
        } catch (error) {
          if (localResult.executedToolName) {
            rlState = {
              ...rlState,
              moduleCatalog: applyModuleRunTelemetry(
                rlState.moduleCatalog,
                localResult.executedToolName,
                activeAbortRequested ? "abort" : "fail",
              ),
            };
          }
          const message = activeAbortRequested ? CANCELLED_TOOL_MESSAGE : toErrorMessage(error);
          await writeAndDrain(process.stdout, message);
          try {
            rlState = (await hydrateShellArtifacts(rlState, core, opts, dataDir)).shell;
          } catch {
            /* best-effort */
          }
        }
        activeActionKind = null;
        activeAbortRequested = false;
        activeToolController = null;
        rl.prompt();
        continue;
      }

      // Only `/ask` (and the `?` prefix) set `askQuestion` to route through
      // the agent session; every other unknown input gets an "Unknown command"
      // message from routeInput, never a silent handoff.
      if (localResult.askQuestion === undefined) {
        if (localResult.output) {
          await writeAndDrain(process.stdout, localResult.output);
        }
        rl.prompt();
        continue;
      }

      const agentInput = localResult.askQuestion;
      const currentSession = await ensureSession();
      if (!currentSession) {
        await writeAndDrain(
          process.stdout,
          assistantDisabledReason ?? sessionError ?? DEFAULT_NO_SESSION_MESSAGE,
        );
        rl.prompt();
        continue;
      }

      let pendingAssistantText = "";
      let fallbackResultText = "";
      let pendingErrorText: string | undefined;
      activeActionKind = "agent";
      activeAbortRequested = false;

      try {
        for await (const message of currentSession.query(agentInput)) {
          if (message.type === "assistant") {
            pendingAssistantText += extractAssistantText(message.content);
            continue;
          }
          if (message.type === "tool-progress") {
            process.stderr.write(`  [${message.toolName}] ${message.elapsedSeconds}s\r`);
            continue;
          }
          if (message.type === "tool-summary") {
            process.stderr.write(`  ${message.summary}\n`);
            const trailer = formatContextTrailer(
              opts.target ? path.resolve(opts.target) : process.cwd(),
            );
            if (trailer) process.stderr.write(`${trailer}\n`);
            continue;
          }
          if (message.type !== "result") {
            continue;
          }
          if ("result" in message) {
            fallbackResultText = message.result;
          } else if (message.subtype === "error_aborted") {
            pendingErrorText = CANCELLED_AGENT_MESSAGE;
          } else {
            pendingErrorText = `Error: ${message.errors.join("; ")}`;
          }
        }
      } catch (error) {
        const message = activeAbortRequested ? CANCELLED_AGENT_MESSAGE : toErrorMessage(error);
        if (pendingAssistantText) {
          await writeAndDrain(process.stdout, pendingAssistantText);
        }
        await writeAndDrain(process.stdout, message);
        activeActionKind = null;
        activeAbortRequested = false;
        rl.prompt();
        continue;
      }

      if (pendingAssistantText || fallbackResultText) {
        await writeAndDrain(
          process.stdout,
          finalizeAssistantText(pendingAssistantText, fallbackResultText),
        );
      }
      if (pendingErrorText) {
        await writeAndDrain(process.stdout, pendingErrorText);
      } else if (activeAbortRequested && !pendingAssistantText && !fallbackResultText) {
        await writeAndDrain(process.stdout, CANCELLED_AGENT_MESSAGE);
      }

      activeActionKind = null;
      activeAbortRequested = false;
      activeToolController = null;
      rl.prompt();
    }
  } finally {
    process.off("SIGINT", abortActiveAction);
    rl.close();
    saveShellCommandHistory(dataDir, rlState.commandHistory);
    await closeSession();
    await core.dispose();
    await bus.close();
  }
}

// Local commands — handled without the LLM

async function writeAndDrain(
  stream: NodeJS.WritableStream & { write(chunk: string): boolean },
  text: string,
): Promise<void> {
  const output = text.endsWith("\n") ? text : `${text}\n`;
  if (!stream.write(output)) {
    await once(stream, "drain");
  }
}

/**
 * One-shot flag — on the operator's first bare-sentence input we prepend a
 * hint steering them to `/ask`. After that, the error message stays terse.
 * Module scope is fine: one shell per process.
 */
let firstBareSentenceHintShown = false;

/**
 * Input router:
 *   1. `?<question>` → `/ask <question>`.
 *   2. Slash commands (/help, /use, /options, /set, /ask, ...) — local only.
 *   3. exit / quit / q.
 *   4. Direct tool dispatch (sast:scan ., semgrep ., scan .).
 *   5. Anything else → explicit "Unknown command" error (never a silent
 *      handoff to the agent).
 *
 * Silent NL fallback was removed to prevent the agent from hallucinating
 * answers from cached `.kuzushi/` artifacts. `/ask` is the explicit door.
 */
function isTaskStoryNavigationInput(input: string): boolean {
  const normalized = input.trim().toLowerCase();
  return normalized === "story" || normalized === "/story";
}

function shouldRouteShellInputBeforeDispatcher(
  input: string,
  shellState: ShellState | null | undefined,
  ctx: ShellContext,
): boolean {
  const trimmed = input.trim();
  if (!trimmed || trimmed.startsWith("/")) return false;
  const lower = trimmed.toLowerCase();
  if (shellState?.shellView === "prompts-editor" && ctx.focusedModule) {
    return /^(edit|show|diff|reset|set)\s+/.test(lower);
  }
  if (!ctx.focusedModule) return false;
  if (shellState?.shellView === "options" && lower === "show advanced") {
    return true;
  }
  if (ctx.focusedModule === "vendor-assessment" && lower === "clear scope") {
    return true;
  }
  return (
    lower === "options" ||
    lower === "show options" ||
    lower.startsWith("show options ") ||
    lower.startsWith("set ")
  );
}

interface ShellRouteEnvironment {
  core: CopilotCore;
  opts: ShellOptions;
  shellContext: ShellContext;
  shellState: ShellState;
}

interface BareShellInput {
  raw: string;
  trimmed: string;
  lower: string;
  words: string[];
}

interface SlashShellInput {
  raw: string;
  command: string;
  args: string[];
}

type BareShellRoute = ShellRoute<BareShellInput, ShellRouteEnvironment, LocalCommandResult>;
type SlashShellRoute = ShellRoute<SlashShellInput, ShellRouteEnvironment, LocalCommandResult>;
type BareShellRouteDefinition = ShellRouteDefinition<
  BareShellInput,
  ShellRouteEnvironment,
  LocalCommandResult
>;
type SlashShellRouteDefinition = ShellRouteDefinition<
  SlashShellInput,
  ShellRouteEnvironment,
  LocalCommandResult
>;

const BARE_SHELL_ROUTES: readonly BareShellRoute[] = defineShellRoutes<
  BareShellInput,
  ShellRouteEnvironment,
  LocalCommandResult
>([
  {
    id: "exit",
    matches: ({ lower }) => ["exit", "quit", "q"].includes(lower),
    execute: () => ({ exit: true }),
  },
  {
    id: "help-advanced",
    matches: ({ lower }) => lower === "help advanced",
    execute: (_input, { core, opts, shellContext, shellState }) => {
      recordCommandUsage(shellContext, shellState, "/help");
      return { output: formatHelp(core, opts, { includeAdvanced: true }) };
    },
  },
  {
    id: "help",
    matches: ({ lower }) => lower === "help",
    execute: (_input, { core, opts, shellContext, shellState }) => {
      recordCommandUsage(shellContext, shellState, "/help");
      return { output: formatHelp(core, opts) };
    },
  },
  {
    id: "modules",
    matches: ({ lower }) => ["modules", "m"].includes(lower),
    execute: (_input, { core, shellState }) => ({
      output: formatModuleList(core, shellState.moduleCatalog),
    }),
  },
  {
    id: "tools",
    matches: ({ lower }) => lower === "tools",
    execute: (_input, { core, shellContext }) => ({
      output: formatTools(core, shellContext.focusedModule),
    }),
  },
  {
    id: "use",
    matches: ({ lower }) => lower.startsWith("use "),
    execute: ({ words }, { core, opts, shellContext }) =>
      handleUseCommand(words.slice(1), core, opts, shellContext),
  },
  {
    id: "back",
    matches: ({ lower }) => ["back", "b"].includes(lower),
    execute: (_input, { opts, shellContext, shellState }) =>
      handleBackCommand(opts, shellContext, shellState),
  },
  {
    id: "findings",
    matches: ({ lower }) => ["findings", "f"].includes(lower),
    execute: () => ({
      shellStateUpdater: (shell) => ({ ...shell, shellView: "findings", openFindingId: null }),
      output: "Showing current findings.",
    }),
  },
  {
    id: "tune",
    matches: ({ lower }) => ["tune", "t"].includes(lower),
    execute: (_input, { shellContext }) => openTuneView(shellContext),
  },
  {
    id: "kb",
    matches: ({ lower }) => ["kb", "attachments"].includes(lower),
    execute: (_input, { core, opts, shellContext, shellState }) =>
      handleKbCommand(core, opts, shellContext, shellState),
  },
  {
    id: "tasks",
    matches: ({ lower }) => lower === "tasks",
    execute: (_input, { core, opts, shellContext, shellState }) => {
      recordCommandUsage(shellContext, shellState, "/tasks");
      return handleSastTasksCommand(core, opts, shellContext, shellState);
    },
  },
  {
    id: "story",
    matches: ({ lower }) => lower === "story",
    execute: (_input, { shellContext, shellState }) => {
      recordCommandUsage(shellContext, shellState, "/story");
      return handleStoryCommand(shellState);
    },
  },
  {
    id: "prompts",
    matches: ({ lower }) => lower === "prompts",
    execute: (_input, { core, opts, shellContext, shellState }) => {
      recordCommandUsage(shellContext, shellState, "/prompts");
      return handlePromptsListCommand(core, opts, shellContext, shellState);
    },
  },
  {
    id: "resume",
    matches: ({ lower }) => lower === "resume" || lower.startsWith("resume "),
    execute: ({ words }, { core, opts, shellContext, shellState }) => {
      recordCommandUsage(shellContext, shellState, "/resume");
      return handleResumeCommand(words.slice(1), core, opts, shellContext, shellState);
    },
  },
  {
    id: "prompt-editor",
    matches: (input, { shellContext, shellState }) =>
      isPromptEditorInput(input, shellContext, shellState),
    execute: (input, environment) => routePromptEditorInput(input, environment),
  },
  {
    id: "sast-task-editor",
    matches: (input, { shellState }) => isSastTaskEditorInput(input, shellState),
    execute: ({ words }, { shellContext, shellState }) => {
      const [taskVerb = "", ...taskArgs] = words;
      recordCommandUsage(shellContext, shellState, `/task ${taskVerb.toLowerCase()}`);
      return handleSastTaskCommand([taskVerb.toLowerCase(), ...taskArgs], shellState);
    },
  },
  {
    id: "options",
    matches: ({ lower }) => lower === "options",
    execute: (_input, { core, opts, shellContext, shellState }) => {
      recordCommandUsage(shellContext, shellState, "/options");
      return handleOptionsCommand([], core, opts, shellContext, shellState);
    },
  },
  {
    id: "show-options",
    matches: ({ lower }) => lower === "show options" || lower.startsWith("show options "),
    execute: ({ words }, { core, opts, shellContext, shellState }) => {
      recordCommandUsage(shellContext, shellState, "/options");
      return handleOptionsCommand(words.slice(2), core, opts, shellContext, shellState);
    },
  },
  {
    id: "show-advanced-options",
    matches: ({ lower }, { shellState }) =>
      shellState.shellView === "options" && lower === "show advanced",
    execute: (_input, { core, opts, shellContext, shellState }) =>
      showAdvancedOptions(core, opts, shellContext, shellState),
  },
  {
    id: "set",
    matches: ({ lower }) => lower.startsWith("set "),
    execute: ({ words }, { core, opts, shellContext, shellState }) => {
      recordCommandUsage(shellContext, shellState, "/set");
      return handleSetCommand(words.slice(1), core, opts, shellContext.focusedModule, shellState);
    },
  },
  {
    id: "context-dfd",
    matches: ({ lower }, { shellContext }) =>
      shellContext.focusedModule === "context" && lower === "dfd",
    execute: (_input, { core, opts, shellContext, shellState }) => {
      recordCommandUsage(shellContext, shellState, "/context dfd");
      return handleContextCommand(["dfd"], core, opts, shellContext, shellState);
    },
  },
  {
    id: "context-regen",
    matches: ({ lower }, { shellContext }) =>
      shellContext.focusedModule === "context" && lower.startsWith("regen "),
    execute: ({ words }, { core, opts, shellContext, shellState }) => {
      recordCommandUsage(shellContext, shellState, "/context regen");
      return handleContextCommand(
        ["regen", ...words.slice(1)],
        core,
        opts,
        shellContext,
        shellState,
      );
    },
  },
  {
    id: "vendor-clear-scope",
    matches: ({ lower }, { shellContext }) =>
      shellContext.focusedModule === "vendor-assessment" && lower === "clear scope",
    execute: (_input, { core, opts, shellContext, shellState }) =>
      resolveToolExecution(
        "vendor-assessment:scope",
        ["clear=true"],
        core,
        opts,
        shellContext,
        shellState,
      ),
  },
  {
    id: "open",
    matches: ({ lower }) => lower.startsWith("open "),
    execute: ({ words }) => handleOpenCommand(words.slice(1)),
  },
  {
    id: "scan",
    matches: ({ lower }) => lower === "scan" || lower.startsWith("scan "),
    execute: ({ words }, { core, opts, shellContext, shellState }) =>
      resolveToolExecution("sast:scan", words.slice(1), core, opts, shellContext, shellState),
  },
] satisfies readonly BareShellRouteDefinition[]);

const SLASH_SHELL_ROUTES: readonly SlashShellRoute[] = defineShellRoutes<
  SlashShellInput,
  ShellRouteEnvironment,
  LocalCommandResult
>([
  {
    id: "help",
    aliases: ["help"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, opts }) => showHelp(args, core, opts),
  },
  {
    id: "modules",
    aliases: ["modules", "m"],
    matches: slashCommandMatches,
    execute: (_input, { core, shellState }) => ({
      output: formatModuleList(core, shellState.moduleCatalog),
    }),
  },
  {
    id: "tools",
    aliases: ["tools"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, shellContext }) => ({
      output: formatTools(core, shellContext.focusedModule, {
        includeHidden: args.includes("--all"),
      }),
    }),
  },
  {
    id: "scan",
    aliases: ["scan"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, opts, shellContext, shellState }) =>
      resolveToolExecution("sast:scan", args, core, opts, shellContext, shellState),
  },
  {
    id: "pause",
    aliases: ["pause"],
    matches: slashCommandMatches,
    execute: (_input, { core, shellContext, shellState }) =>
      handleLiveQueueControl(true, core, shellContext, shellState),
  },
  {
    id: "resume",
    aliases: ["resume"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, opts, shellContext, shellState }) =>
      isLivePauseResumeActive(shellState)
        ? handleLiveQueueControl(false, core, shellContext, shellState)
        : handleResumeCommand(args, core, opts, shellContext, shellState),
  },
  {
    id: "use",
    aliases: ["use"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, opts, shellContext }) =>
      handleUseCommand(args, core, opts, shellContext),
  },
  {
    id: "back",
    aliases: ["back", "b"],
    matches: slashCommandMatches,
    execute: (_input, { opts, shellContext, shellState }) =>
      handleBackCommand(opts, shellContext, shellState),
  },
  {
    id: "findings",
    aliases: ["findings", "f"],
    matches: slashCommandMatches,
    execute: ({ args }, { opts, shellContext }) => {
      if (args[0]?.toLowerCase() === "export") {
        return handleFindingsExportCommand(args.slice(1), opts, shellContext);
      }
      return {
        shellStateUpdater: (shell) => ({
          ...shell,
          shellView: "findings",
          openFindingId: null,
          diffSince: undefined,
          findingScope: { kind: "all" },
        }),
        output: "Showing all current findings.",
      };
    },
  },
  {
    id: "tune",
    aliases: ["tune", "t"],
    matches: slashCommandMatches,
    execute: (_input, { shellContext }) => openSlashTuneView(shellContext),
  },
  {
    id: "kb",
    aliases: ["kb"],
    matches: slashCommandMatches,
    execute: (_input, { core, opts, shellContext, shellState }) =>
      handleKbCommand(core, opts, shellContext, shellState),
  },
  {
    id: "story",
    aliases: ["story"],
    matches: slashCommandMatches,
    execute: (_input, { shellState }) => handleStoryCommand(shellState),
  },
  {
    id: "open",
    aliases: ["open"],
    matches: slashCommandMatches,
    execute: ({ args }) => handleOpenCommand(args),
  },
  {
    id: "plan",
    aliases: ["plan"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, opts, shellContext, shellState }) =>
      handlePlanCommand(args, core, opts, shellContext, shellState),
  },
  {
    id: "apply-plan",
    aliases: ["yes", "apply-plan"],
    matches: slashCommandMatches,
    execute: (_input, { core, shellState }) => handleApplyPlanCommand(core, shellState),
  },
  {
    id: "discard-plan",
    aliases: ["no", "discard-plan"],
    matches: slashCommandMatches,
    execute: (_input, { shellState }) => handleDiscardPlanCommand(shellState),
  },
  {
    id: "prompt",
    aliases: ["prompt"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, opts, shellContext, shellState }) =>
      handlePromptCommand(args, core, opts, shellContext, shellState),
  },
  {
    id: "prompts",
    aliases: ["prompts"],
    matches: slashCommandMatches,
    execute: (_input, { core, opts, shellContext, shellState }) =>
      handlePromptsListCommand(core, opts, shellContext, shellState),
  },
  {
    id: "actor",
    aliases: ["actor"],
    matches: slashCommandMatches,
    execute: ({ args }, { shellContext, shellState }) =>
      handleActorCommand(args, shellContext, shellState),
  },
  {
    id: "show",
    aliases: ["show"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, opts, shellContext, shellState }) =>
      handleShowCommand(args, core, opts, shellContext, shellState),
  },
  {
    id: "runs",
    aliases: ["runs"],
    matches: slashCommandMatches,
    execute: ({ args }, { shellContext }) => handleShowRunsCommand(args, shellContext),
  },
  {
    id: "replay",
    aliases: ["replay"],
    matches: slashCommandMatches,
    execute: ({ args }, { shellContext }) => handleReplayCommand(args, shellContext),
  },
  {
    id: "trace",
    aliases: ["trace"],
    matches: slashCommandMatches,
    execute: ({ args }, { shellContext }) => handleTraceCommand(args, shellContext),
  },
  {
    id: "options",
    aliases: ["options"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, opts, shellContext, shellState }) =>
      handleOptionsCommand(args, core, opts, shellContext, shellState),
  },
  {
    id: "tasks",
    aliases: ["tasks"],
    matches: slashCommandMatches,
    execute: (_input, { core, opts, shellContext, shellState }) =>
      handleSastTasksCommand(core, opts, shellContext, shellState),
  },
  {
    id: "task",
    aliases: ["task"],
    matches: slashCommandMatches,
    execute: ({ args }, { shellState }) => handleSastTaskCommand(args, shellState),
  },
  {
    id: "set",
    aliases: ["set"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, opts, shellContext, shellState }) =>
      handleSetCommand(args, core, opts, shellContext.focusedModule, shellState),
  },
  {
    id: "config",
    aliases: ["config"],
    matches: slashCommandMatches,
    execute: ({ args }, { shellContext }) => handleConfigCommand(args, shellContext),
  },
  {
    id: "auth",
    aliases: ["auth"],
    matches: slashCommandMatches,
    execute: ({ args }, { opts, shellContext }) => handleAuthCommand(args, opts, shellContext),
  },
  {
    id: "ask",
    aliases: ["ask"],
    matches: slashCommandMatches,
    execute: ({ args }, { opts, shellState }) => handleAskCommand(args, opts, shellState),
  },
  {
    id: "backend",
    aliases: ["backend"],
    matches: slashCommandMatches,
    execute: ({ args }, { opts }) => handleBackendCommand(args, opts),
  },
  {
    id: "cost",
    aliases: ["cost"],
    matches: slashCommandMatches,
    execute: (_input, { opts, shellState }) => handleCostCommand(opts, shellState),
  },
  {
    id: "provider",
    aliases: ["provider"],
    matches: slashCommandMatches,
    execute: ({ args }, { opts }) => handleProviderCommand(args, opts),
  },
  {
    id: "context",
    aliases: ["context"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, opts, shellContext, shellState }) =>
      handleContextCommand(args, core, opts, shellContext, shellState),
  },
  {
    id: "since",
    aliases: ["since"],
    matches: slashCommandMatches,
    execute: ({ args }, { opts, shellContext }) => handleSinceCommand(args, opts, shellContext),
  },
  {
    id: "threats",
    aliases: ["threats"],
    matches: slashCommandMatches,
    execute: ({ args }, { core, opts, shellContext, shellState }) =>
      handleThreatsCommand(args, core, opts, shellContext, shellState),
  },
  {
    id: "target",
    aliases: ["target"],
    matches: slashCommandMatches,
    execute: ({ args }, { opts, shellState }) => handleTargetCommand(args, opts, shellState),
  },
  {
    id: "workspace",
    aliases: ["workspace"],
    matches: slashCommandMatches,
    execute: ({ args }, { opts, shellContext }) => handleWorkspaceCommand(args, opts, shellContext),
  },
  {
    id: "clear",
    aliases: ["clear"],
    matches: slashCommandMatches,
    execute: () => ({
      clearHistory: true,
      resetSession: true,
      output: "Conversation cleared.",
    }),
  },
  {
    id: "history",
    aliases: ["history"],
    matches: slashCommandMatches,
    execute: (_input, { shellState }) => ({ output: formatHistory(shellState.commandHistory) }),
  },
  {
    id: "load",
    aliases: ["load"],
    matches: slashCommandMatches,
    execute: ({ args }, { core }) => handleLoadCommand(args, core),
  },
  {
    id: "exit",
    aliases: ["exit"],
    matches: slashCommandMatches,
    execute: () => ({ exit: true }),
  },
] satisfies readonly SlashShellRouteDefinition[]);

function routeInput(
  input: string,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const trimmed = input.trim();
  const lower = trimmed.toLowerCase();
  const environment = { core, opts, shellContext: ctx, shellState };

  if (trimmed.startsWith("?")) {
    recordCommandUsage(ctx, shellState, "/ask");
    return handleAskCommand([trimmed.slice(1).trim()], opts, shellState);
  }

  if (trimmed.startsWith("/")) {
    recordCommandUsage(ctx, shellState, trimmed);
    return handleSlashCommand(trimmed, core, opts, ctx, shellState);
  }

  const routed = routeShellInput(
    toBareShellInput(input, trimmed, lower),
    environment,
    BARE_SHELL_ROUTES,
  );
  if (routed) {
    return routed;
  }

  const toolResult = resolveDirectToolDispatch(trimmed, core, opts, ctx, shellState);
  if (toolResult !== undefined) {
    recordLocalUsageEvent(ctx.dataDir, {
      type: "command",
      timestamp: new Date().toISOString(),
      command: "tool-dispatch",
      surface: "advanced",
      view: shellState.shellView,
      outcome: "started",
    });
    return toolResult;
  }

  // Strip stray trailing quotes from the preview so error messages like
  // `/threats dfd"` (which sometimes occurs when an upstream parser splits
  // on whitespace and leaves a `"` in `trimmed`) don't carry the artefact
  // into the user-visible message.
  const preview = (() => {
    const raw = trimmed.length > 60 ? `${trimmed.slice(0, 60)}…` : trimmed;
    return raw.replace(/['"]+$/, "");
  })();
  if (lower.startsWith("ask ")) {
    return {
      output: `Natural-language chat is explicit. Use /ask ${trimmed.slice(4).trim()} or prefix the question with ?.`,
    };
  }
  if (lower.startsWith("show ")) {
    return {
      output: [
        `Unknown bare show command: "${preview}".`,
        "Canonical meta-command syntax uses slash commands:",
        "  /show prompts",
        "  /show options [tool]",
        "  /show runs",
        "  /show aliases [prefix]",
      ].join("\n"),
    };
  }
  const taxonomy = classifyShellInput(trimmed, ctx.focusedModule);
  const base =
    taxonomy === "module-action"
      ? `Unknown workspace action: "${preview}". Shell meta-commands start with /; module actions are bare after /use <module>. Try /help.`
      : `Unknown command: "${preview}". Try /help, or /ask <question> to ask Claude with current shell context.`;
  const hint = firstBareSentenceHintShown
    ? ""
    : "\n(hint: natural-language chat routes only through /ask or ?)";
  firstBareSentenceHintShown = true;
  return { output: base + hint };
}

function toBareShellInput(raw: string, trimmed: string, lower: string): BareShellInput {
  return { raw, trimmed, lower, words: splitShellWords(trimmed) };
}

function splitShellWords(input: string): string[] {
  return input.split(/\s+/).filter(Boolean);
}

function openTuneView(shellContext: ShellContext): LocalCommandResult {
  if (!shellContext.focusedModule) return { output: "Use a module first: use <module>" };
  return {
    shellStateUpdater: (shell) => ({ ...shell, shellView: "tune" }),
    output: `Tuning ${shellContext.focusedModule}. Use prompt edit <verb> for prompt overrides.`,
  };
}

function openSlashTuneView(shellContext: ShellContext): LocalCommandResult {
  if (!shellContext.focusedModule) {
    return { output: "Usage: /use <module> first, then /tune." };
  }
  return openTuneView(shellContext);
}

function isPromptEditorInput(
  input: BareShellInput,
  shellContext: ShellContext,
  shellState: ShellState,
): boolean {
  if (shellState.shellView !== "prompts-editor" || !shellContext.focusedModule) return false;
  if (input.words.length < 2) return false;
  return ["edit", "show", "diff", "reset", "set"].includes(input.words[0]?.toLowerCase() ?? "");
}

function routePromptEditorInput(
  input: BareShellInput,
  { core, opts, shellContext, shellState }: ShellRouteEnvironment,
): LocalCommandResult {
  const verb = input.words[0]?.toLowerCase();
  const promptName = input.words.slice(1).join(" ").trim() || undefined;
  if (verb === "edit") {
    recordCommandUsage(shellContext, shellState, "/prompt edit");
    return handlePromptEditCommand(promptName, core, opts, shellContext, shellState);
  }
  if (verb === "show") {
    recordCommandUsage(shellContext, shellState, "/prompt show");
    return handlePromptShowCommand(promptName, core, opts, shellContext, shellState);
  }
  if (verb === "diff") {
    recordCommandUsage(shellContext, shellState, "/prompt diff");
    return handlePromptDiffCommand(promptName, core, opts, shellContext, shellState);
  }
  if (verb === "reset") {
    recordCommandUsage(shellContext, shellState, "/prompt reset");
    return handlePromptResetCommand(promptName, core, opts, shellContext, shellState);
  }
  recordCommandUsage(shellContext, shellState, "/prompt set");
  return handlePromptInlineSetCommand(input.trimmed, core, opts, shellContext, shellState);
}

function isSastTaskEditorInput(input: BareShellInput, shellState: ShellState): boolean {
  if (shellState.shellView !== "sast-tasks") return false;
  return ["toggle", "block", "allow", "mode", "reset"].includes(
    input.words[0]?.toLowerCase() ?? "",
  );
}

function showAdvancedOptions(
  core: CopilotCore,
  opts: ShellOptions,
  shellContext: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const toolName = shellState.optionsView?.toolName ?? shellState.lastUsedTool;
  if (!toolName) {
    return { output: "No options are loaded. Run show options first." };
  }
  recordCommandUsage(shellContext, shellState, "/options");
  return { output: formatOptions(core, toolName, opts, shellState) };
}

function handleSlashCommand(
  input: string,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const { cmd, args } = parseCommand(input.slice(1));
  const slashInput = { raw: input, command: cmd.toLowerCase(), args };
  const environment = { core, opts, shellContext: ctx, shellState };
  return (
    routeShellInput(slashInput, environment, SLASH_SHELL_ROUTES) ?? {
      output: formatUnknownVerb(slashInput.command, collectKnownVerbs()),
    }
  );
}

function slashCommandMatches(
  input: SlashShellInput,
  _environment: ShellRouteEnvironment,
  route: SlashShellRoute,
): boolean {
  return commandMatches(input.command, route.aliases ?? []);
}

function showHelp(args: string[], core: CopilotCore, opts: ShellOptions): LocalCommandResult {
  if (args[0]?.toLowerCase() === "advanced") {
    return { output: formatHelp(core, opts, { includeAdvanced: true }) };
  }
  if (args[0]) return { output: formatHelpForVerb(args[0]) };
  return { output: formatHelp(core, opts) };
}

function handlePromptCommand(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  shellContext: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const subcommand = args[0]?.toLowerCase();
  const verb = args[1];
  if (subcommand === "edit") {
    return handlePromptEditCommand(verb, core, opts, shellContext, shellState);
  }
  if (subcommand === "show") {
    return handlePromptShowCommand(verb, core, opts, shellContext, shellState);
  }
  if (subcommand === "reset") {
    return handlePromptResetCommand(verb, core, opts, shellContext, shellState);
  }
  if (subcommand === "diff") {
    return handlePromptDiffCommand(verb, core, opts, shellContext, shellState);
  }
  if (subcommand === "list" || (subcommand === undefined && shellContext.focusedModule)) {
    return handlePromptsListCommand(core, opts, shellContext, shellState);
  }
  return { output: formatPromptCommandUsage() };
}

function formatPromptCommandUsage(): string {
  return [
    "Usage:",
    "  /prompt edit <verb>    open the operator override in $EDITOR",
    "  /prompt show <verb>    print the current effective prompt + source",
    "  /prompt diff <verb>    show the override file's path for git diff",
    "  /prompt reset <verb>   delete the override and revert to default",
    "  /prompt list           open the prompts editor for the focused module",
    "  /show prompts          cross-module audit of all *_PROMPT keys",
  ].join("\n");
}

function handleUseCommand(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
): LocalCommandResult {
  const moduleId = args[0];
  if (!moduleId) {
    return { output: `Usage: /use <module>\nAvailable modules: ${formatModuleChoices(core)}` };
  }
  if (!core.hasModule(moduleId)) {
    const loaded = core.listModules().map((m) => m.id);
    return { output: formatUnknownModule(moduleId, loaded) };
  }
  const mod = core.registry.get(moduleId);
  const tuneSnapshot = ctx.dataDir
    ? buildTuneSnapshot(opts.config, ctx.dataDir, moduleId)
    : undefined;
  const vendorAssessment =
    moduleId === "vendor-assessment"
      ? scopeToHomeSlice(shellTargetCwd(opts), loadDraftScope(shellTargetCwd(opts)))
      : undefined;
  return {
    setFocus: moduleId,
    shellStateUpdater: (shell) => ({
      ...shell,
      shellView: "module",
      openFindingId: null,
      tuneSnapshot: tuneSnapshot ?? shell.tuneSnapshot,
      vendorAssessment: vendorAssessment ?? shell.vendorAssessment,
    }),
    output: `Focused on ${mod.displayName}. ${mod.tools.length} tools available.`,
  };
}

function shellTargetCwd(opts: ShellOptions): string {
  if (opts.target && !/^[a-z][a-z0-9+.-]*:\/\//i.test(opts.target)) {
    return path.resolve(opts.target);
  }
  return process.cwd();
}

function handleBackCommand(
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  // Step up through the shellView stack before falling back to top-level.
  const currentView = shellState.shellView;
  if (currentView === "finding") {
    return {
      shellStateUpdater: (shell) => ({ ...shell, shellView: "findings", openFindingId: null }),
      output: "Back to findings.",
    };
  }
  if (
    currentView === "findings" ||
    currentView === "since" ||
    currentView === "tune" ||
    currentView === "options" ||
    currentView === "sast-tasks" ||
    currentView === "task-story" ||
    currentView === "threats" ||
    currentView === "context-build" ||
    currentView === "module-run" ||
    currentView === "prompts-editor"
  ) {
    return {
      shellStateUpdater: (shell) => ({
        ...shell,
        shellView: ctx.focusedModule ? "module" : "catalog",
      }),
      output: ctx.focusedModule ? "Back to module home." : "Back to catalog.",
    };
  }
  if (currentView === "actor-detail") {
    return {
      shellStateUpdater: (shell) => ({
        ...shell,
        shellView: "module-run",
        focusedActor: null,
      }),
      output: "Back to module run.",
    };
  }
  if (ctx.focusedModule) {
    const clearedTune = ctx.dataDir ? buildTuneSnapshot(opts.config, ctx.dataDir, null) : undefined;
    return {
      setFocus: null,
      shellStateUpdater: (shell) => ({
        ...shell,
        shellView: "catalog",
        openFindingId: null,
        tuneSnapshot: clearedTune ?? shell.tuneSnapshot,
      }),
      output: "Returned to top level.",
    };
  }
  return { output: "Already at top level." };
}

/**
 * Registry of KB-enabled modules that the `/kb` view knows how to load
 * directly from disk on view-entry. Each entry exposes the module's
 * KindSpec (for label rendering) plus an optional custom storage adapter
 * (vendor-assessment uses one to keep its `scope.draft.json` shape; the
 * three new modules use the default `.kuzushi/<id>/attachments.json`
 * adapter).
 *
 * The map is keyed by moduleId. `kbState[moduleId]` is patched as a side
 * effect of the shared attach/detach/reparse tools too — the view simply
 * reads it; this registry exists so the view can populate the slice the
 * very first time the operator types `/kb` after a fresh shell.
 */
const KB_REGISTRY: ReadonlyMap<
  string,
  {
    spec: KindSpec<string>;
    adapter?: AttachmentStorageAdapter<string>;
  }
> = new Map<string, { spec: KindSpec<string>; adapter?: AttachmentStorageAdapter<string> }>([
  ["threat-model", { spec: THREAT_MODEL_KIND_SPEC as KindSpec<string> }],
  ["context", { spec: CONTEXT_KIND_SPEC as KindSpec<string> }],
  ["carlini-threat-hunt", { spec: CARLINI_THREAT_HUNT_KIND_SPEC as KindSpec<string> }],
]);

/**
 * Open the focused module's KB view (`/kb` or bare `attachments`). Loads
 * any pre-existing attachments from disk so the view shows them on first
 * entry, even before any attach/detach has fired this session.
 */
function handleKbCommand(
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  if (!ctx.focusedModule) {
    return {
      output: [
        "Usage: /use <module> first, then /kb.",
        `KB-enabled modules: ${formatChoices([...KB_REGISTRY.keys()])}`,
        `Loaded modules: ${formatModuleChoices(core)}`,
      ].join("\n"),
    };
  }
  const moduleId = ctx.focusedModule;
  const entry = KB_REGISTRY.get(moduleId);
  if (!entry) {
    return {
      output: `${moduleId} does not expose a knowledge base. Available: ${[...KB_REGISTRY.keys()].join(", ")}.`,
    };
  }
  const cwd = opts.target ? path.resolve(opts.target) : process.cwd();
  const adapter = entry.adapter ?? defaultAttachmentAdapter<string>(moduleId);
  const docs = adapter.read(cwd);
  const scopePath = adapter.pathFor(cwd);
  const slice = buildHomeSlice(moduleId, scopePath, docs, entry.spec);
  const previousCursor =
    shellState.kb && shellState.kb.moduleId === moduleId
      ? Math.min(shellState.kb.cursor, Math.max(0, slice.documents.length - 1))
      : 0;
  return {
    shellStateUpdater: (shell) => ({
      ...shell,
      shellView: "kb",
      kb: { moduleId, cursor: previousCursor, collapsed: shell.kb?.collapsed ?? false },
      kbState: { ...(shell.kbState ?? {}), [moduleId]: slice },
    }),
    output:
      slice.documents.length === 0
        ? `${moduleId}: no attachments yet. Use \`attach <path-or-url>\` to add reference material.`
        : `${moduleId}: ${slice.documents.length} attachment(s).`,
  };
}

function handleStoryCommand(shellState: ShellState): LocalCommandResult {
  const eventCount = shellState.taskStory?.events.length ?? 0;
  return {
    shellStateUpdater: (shell) => ({ ...shell, shellView: "task-story" }),
    output:
      eventCount > 0
        ? `Showing task story (${eventCount} events).`
        : "No task story yet. Run a tool or ask the agent first.",
  };
}

function handleOpenCommand(args: string[]): LocalCommandResult {
  const findingId = args[0];
  if (!findingId) {
    return {
      output: [
        "Usage: /open <F-NNNN|fingerprint>",
        "Find aliases with /show aliases, or list findings with /findings.",
      ].join("\n"),
    };
  }
  return {
    shellStateUpdater: (shell) => ({
      ...shell,
      shellView: "finding",
      openFindingId: findingId,
    }),
    output: `Opening ${findingId}.`,
  };
}

function handlePlanCommand(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  // Natural-language → option-diff planner. Joins all args into the request
  // text so quoting is optional: `/plan run harder, focus on auth`.
  const text = args.join(" ").trim();
  if (!text) {
    return { output: 'Usage: /plan "<english>" — e.g. /plan run harder, focus on auth' };
  }
  if (!ctx.focusedModule) {
    return {
      output: `No focused module. Use /use <module> first.\nAvailable modules: ${formatModuleChoices(core)}`,
    };
  }
  const activeToolName = shellState.lastUsedTool;
  const fallbackToolName = activeToolName?.startsWith(`${ctx.focusedModule}:`)
    ? activeToolName
    : pickDefaultToolName(core, ctx.focusedModule);
  if (!fallbackToolName) {
    return {
      output: `No tool resolved for ${ctx.focusedModule}. Use /options <tool> first.\nAvailable tools: ${formatToolChoices(core, ctx.focusedModule)}`,
    };
  }
  const resolved = core.registry.resolveTool(fallbackToolName);
  if (!resolved) {
    return { output: formatUnknownToolMessage(fallbackToolName, core) };
  }
  const currentOptions = { ...(shellState.moduleOptions[fallbackToolName] ?? {}) };
  const runtime = opts.runtime;
  return {
    output: `Planning: "${text.slice(0, 80)}${text.length > 80 ? "…" : ""}"`,
    shellStateUpdater: (shell) => ({ ...shell, plannerBusy: true }),
    asyncExecute: async (signal) => {
      const abortController = new AbortController();
      if (signal) {
        if (signal.aborted) abortController.abort();
        else signal.addEventListener("abort", () => abortController.abort(), { once: true });
      }
      let plan: ShellPlan | undefined;
      let errorMsg: string | undefined;
      try {
        plan = await runPlanner({
          runtime,
          cwd: opts.target ? path.resolve(opts.target) : process.cwd(),
          tool: resolved.tool,
          currentOptions,
          text,
          toolName: fallbackToolName,
          abortController,
        });
      } catch (err) {
        errorMsg = toErrorMessage(err);
      }
      if (ctx.uiStore) {
        updateShell(ctx.uiStore, (shell) => ({
          ...shell,
          plannerBusy: false,
          pendingPlan: plan ?? null,
        }));
      }
      if (errorMsg) return `Planner error: ${errorMsg}`;
      if (!plan) return "Planner returned no plan.";
      if (plan.changes.length === 0 && plan.unsupported.length === 0) {
        return "Planner found nothing to change.";
      }
      return "Plan ready. Press y to apply, n to discard.";
    },
  };
}

function handleApplyPlanCommand(core: CopilotCore, shellState: ShellState): LocalCommandResult {
  const plan = shellState.pendingPlan;
  if (!plan) {
    return { output: 'No pending plan. Use /plan "<english>" first.' };
  }
  const result = applyShellPlan(plan, core, shellState);
  return {
    output: result.output,
    shellStateUpdater: (shell) => ({
      ...result.updater(shell),
      pendingPlan: null,
    }),
  };
}

function handleDiscardPlanCommand(shellState: ShellState): LocalCommandResult {
  if (!shellState.pendingPlan) {
    return { output: "No pending plan." };
  }
  return {
    output: "Plan discarded.",
    shellStateUpdater: (shell) => ({ ...shell, pendingPlan: null }),
  };
}

function handleShowCommand(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const sub = args[0]?.toLowerCase();
  if (sub === "prompts") {
    const cwd = opts.target ? path.resolve(opts.target) : process.cwd();
    const rows = readPromptAudit(core, shellState.moduleOptions, cwd);
    return withPlainOutputShellViewReconciliation(
      { output: formatPromptAuditTable(rows) },
      "/show prompts",
      ctx.focusedModule,
      shellState,
    );
  }
  if (sub === "runs") {
    return handleShowRunsCommand(args.slice(1), ctx);
  }
  if (sub === "aliases") {
    return handleShowAliasesCommand(args.slice(1), ctx, opts);
  }
  if (sub === "options") {
    return handleOptionsCommand(args.slice(1), core, opts, ctx, shellState);
  }
  return {
    output:
      "Usage: /show prompts  |  /show options [tool]  |  /show runs  |  /show aliases [prefix]",
  };
}

function handleOptionsCommand(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const resolved = resolveOptionsTool(core, args[0], ctx.focusedModule, shellState.lastUsedTool);
  if (!resolved.ok) {
    return { output: resolved.output };
  }
  const built = buildOptionsViewSlice(core, resolved.toolName, opts, shellState);
  if (!built.ok) {
    return { output: built.output };
  }
  const moduleId = resolved.toolName.split(":")[0] ?? ctx.focusedModule;
  return {
    setFocus: moduleId,
    output: `Showing options for ${resolved.toolName}.`,
    shellStateUpdater: (shell) => ({
      ...shell,
      focusedModule: moduleId,
      shellView: "options",
      lastUsedTool: resolved.toolName,
      optionsView: built.view,
    }),
  };
}

function handleSastTasksCommand(
  core: CopilotCore,
  _opts: ShellOptions,
  _ctx: ShellContext,
  _shellState: ShellState,
): LocalCommandResult {
  if (!core.hasModule("sast")) {
    return { output: "SAST module is not loaded." };
  }
  return {
    setFocus: "sast",
    output: "Showing SAST task selection.",
    shellStateUpdater: (shell) => ({
      ...shell,
      focusedModule: "sast",
      shellView: "sast-tasks",
      lastUsedTool: SAST_SCAN_TOOL_NAME,
      sastTaskCursor: shell.sastTaskCursor ?? 0,
    }),
  };
}

function handleSastTaskCommand(args: string[], shellState: ShellState): LocalCommandResult {
  const sub = args[0]?.toLowerCase();
  if (!sub) {
    return {
      output: [
        "Usage:",
        "  /task block <id>",
        "  /task allow <id>",
        "  /task toggle [id]",
        "  /task mode auto|manual|toggle",
        "  /task reset",
        `Available task IDs: ${formatSastTaskChoices()}`,
      ].join("\n"),
    };
  }

  const currentOptions = shellState.moduleOptions[SAST_SCAN_TOOL_NAME] ?? {};
  const feedback = (headline: string, options: Record<string, unknown>): string =>
    formatSastTaskFeedback(headline, options, shellState.tuneSnapshot);
  const updateOptions = (
    nextOptions: Record<string, unknown>,
    output: string,
  ): LocalCommandResult => ({
    output,
    shellStateUpdater: (shell) => {
      const moduleOptions = { ...shell.moduleOptions };
      if (Object.keys(nextOptions).length === 0) delete moduleOptions[SAST_SCAN_TOOL_NAME];
      else moduleOptions[SAST_SCAN_TOOL_NAME] = nextOptions;
      return {
        ...shell,
        focusedModule: "sast",
        shellView: "sast-tasks",
        moduleOptions,
        lastUsedTool: SAST_SCAN_TOOL_NAME,
      };
    },
  });

  if (sub === "block" || sub === "deny") {
    const id = args[1]?.trim();
    if (!id) {
      return {
        output: `Usage: /task block <id>\nAvailable task IDs: ${formatSastTaskChoices()}`,
      };
    }
    const next = updateDisabledSastTask(currentOptions, id, true);
    return updateOptions(next, feedback(`Blocked SAST task capability: ${id}`, next));
  }

  if (sub === "allow" || sub === "unblock") {
    const id = args[1]?.trim();
    if (!id) {
      return {
        output: `Usage: /task allow <id>\nAvailable task IDs: ${formatSastTaskChoices()}`,
      };
    }
    const next = updateDisabledSastTask(currentOptions, id, false);
    return updateOptions(next, feedback(`Allowed SAST task capability: ${id}`, next));
  }

  if (sub === "toggle") {
    const rawId = args[1]?.trim();
    const capability = rawId
      ? resolveSastTaskCapability(rawId)
      : resolveSastTaskAtCursor(shellState.sastTaskCursor);
    if (!capability) {
      return {
        output: `Unknown SAST task capability: ${rawId}\nAvailable task IDs: ${formatSastTaskChoices()}`,
      };
    }
    if (capability.toggleable === false) {
      return {
        output: `${capability.label} is required infrastructure. Use /task block <id> for an explicit hard override.`,
      };
    }
    const id = capability.id;
    const before = new Set(readDisabledSastTasks(currentOptions));
    const next = toggleDisabledSastTask(currentOptions, id);
    const blocked = !before.has(id);
    return updateOptions(
      next,
      feedback(`${blocked ? "Blocked" : "Allowed"} SAST task capability: ${id}`, next),
    );
  }

  if (sub === "mode") {
    const raw = args[1]?.toLowerCase();
    const current = readSastTaskMode(currentOptions);
    const mode: SastTaskMode =
      raw === "toggle" || raw == null
        ? current === "auto"
          ? "manual"
          : "auto"
        : raw === "manual"
          ? "manual"
          : "auto";
    if (raw && raw !== "toggle" && raw !== "auto" && raw !== "manual") {
      return { output: "Usage: /task mode auto|manual|toggle\nValid modes: auto, manual, toggle" };
    }
    const next = setSastTaskMode(
      currentOptions,
      mode,
      defaultManualSastTasks(currentOptions, shellState.tuneSnapshot),
    );
    return updateOptions(
      next,
      feedback(`SAST task mode: ${mode === "auto" ? "auto + denylist" : "manual allowlist"}`, next),
    );
  }

  if (sub === "reset") {
    const next = resetSastTaskOptions(currentOptions);
    return updateOptions(next, feedback("SAST task selection reset.", next));
  }

  return {
    output: `Unknown /task action: ${sub}\nValid actions: block, allow, toggle, mode, reset`,
  };
}

function handleContextCommand(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const sub = args[0]?.toLowerCase();

  if (sub === "dfd") {
    return {
      output:
        "DFD is now owned by threat-model. Use /threats dfd to view it or /threats regen dfd to rebuild it.",
    };
  }

  // /context build — Live Build screen. Runs the deterministic
  // `gatherContextForRoot` pipeline with a phase observer that streams
  // into `shell.contextBuild`, writes `.kuzushi/scan-context.json` on
  // completion, and returns to the prompt with a one-line summary.
  if (sub === "build") {
    const repoRoot = resolveActiveTarget(opts, shellState);
    if (!repoRoot) return { output: "No target set. Use /target <path> first." };
    return {
      output: "Building operator scan context…",
      shellStateUpdater: (shell) => ({
        ...shell,
        shellView: "context-build",
        contextBuild: initContextBuildState(repoRoot),
      }),
      executedToolName: "context:build",
      asyncExecute: async (signal) => {
        const { runContextBuildLive } = await import("./context-build-runner.js");
        return runContextBuildLive(ctx.uiStore, repoRoot, signal);
      },
    };
  }

  // /context edit — open the operator context intake editor
  if (sub === "edit") {
    const repoRoot = resolveActiveTarget(opts, shellState);
    if (!repoRoot) return { output: "No target set. Use /target <path> first." };
    return {
      output: "Opening operator context editor...",
      asyncExecute: async () => {
        const { loadOperatorScanContext, generateDefaultContext } = await import(
          "../operator-context.js"
        );
        const { runContextIntake } = await import("../ui/setup.js");
        let operatorCtx = loadOperatorScanContext(repoRoot);
        if (!operatorCtx) operatorCtx = generateDefaultContext();
        const outcome = await runContextIntake(
          ctx.uiStore,
          operatorCtx,
          path.basename(repoRoot),
          repoRoot,
          "shell",
        );
        if (outcome.action === "proceed") {
          return "Operator context saved to .kuzushi/scan-context.json";
        }
        return "Context intake skipped.";
      },
    };
  }

  // /context regenerate — force re-run
  if (sub === "regenerate" || sub === "regen") {
    const target = resolveActiveTarget(opts, shellState);
    if (!target) return { output: "No target set. Use /target <path> first." };
    const slice = parseContextRegenSlice(args[1]?.toLowerCase());
    if (!slice) {
      const movedSlice = parseThreatModelRegenSlice(args[1]?.toLowerCase());
      if (movedSlice) {
        return {
          output: `Threat-model slice "${movedSlice}" moved out of context. Run /threats regen ${movedSlice}.`,
        };
      }
      return {
        shellStateUpdater: (shell) => ({ ...shell, contextRegenPaletteOpen: true }),
        output: [
          "Regenerate a generated context slice:",
          "  /context regen all",
          "  /context regen repo",
          "  /context regen enrichment",
          "  /context regen app-model",
          "",
          "Threat-model slices moved to /threats regen <all|dfd|stride|stories|scope|scenarios>.",
        ].join("\n"),
      };
    }
    const result = resolveToolExecution(
      "context:build",
      [target, `scope=${slice}`],
      core,
      opts,
      ctx,
      shellState,
    );
    return {
      ...result,
      shellStateUpdater: (shell) => ({ ...shell, contextRegenPaletteOpen: false }),
    };
  }

  // /context <module-path> — drill into monorepo module
  if (sub && shellState.contextSnapshot?.modules?.[sub]) {
    return { output: formatContextSummary(shellState.contextSnapshot, sub) };
  }

  // /context — show current snapshot if valid for current target
  const activeTarget = resolveActiveTarget(opts, shellState);
  if (
    shellState.contextSnapshot &&
    activeTarget &&
    shellState.contextSnapshot.target === activeTarget
  ) {
    return { output: formatContextSummary(shellState.contextSnapshot) };
  }

  // No valid snapshot — trigger generation
  if (!activeTarget) return { output: "No target set. Use /target <path> first." };
  return resolveToolExecution("context:build", [], core, opts, ctx, shellState);
}

function handleSinceCommand(
  args: string[],
  opts: ShellOptions,
  ctx: ShellContext,
): LocalCommandResult {
  // `/since <ref>` — findings scope. Computes the changed-file set between
  // HEAD and `<ref>` via git, stores it on shell.diffSince, and keeps the
  // operator on the findings surface.
  const ref = args[0];
  if (!ref) {
    return { output: "Usage: /since <git-ref>  e.g.  /since main" };
  }
  if (ref.toLowerCase() === "reset") {
    return {
      output: "Diff scope cleared.",
      shellStateUpdater: (shell) => ({
        ...shell,
        diffSince: undefined,
        findingScope: { kind: "all" },
        shellView: "findings",
      }),
    };
  }
  if (!opts.target) {
    return { output: "No target set. Use /target <path> first." };
  }
  const repoRoot = path.resolve(opts.target);
  return {
    output: `Diffing HEAD against ${ref}…`,
    shellStateUpdater: (shell) => ({ ...shell, shellView: "since", openFindingId: null }),
    asyncExecute: async () => {
      const { computeDiffScope } = await import("./diff-scope.js");
      const scope = computeDiffScope(repoRoot, ref);
      if (ctx.uiStore) {
        updateShell(ctx.uiStore, (shell) => ({
          ...shell,
          diffSince: {
            ref: scope.ref,
            repoRoot: scope.repoRoot,
            changedFiles: scope.changedFiles,
            ...(scope.error ? { error: scope.error } : {}),
          },
          findingScope: {
            kind: "changed-files",
            ref: scope.ref,
            repoRoot: scope.repoRoot,
            changedFiles: scope.changedFiles,
            ...(scope.error ? { error: scope.error } : {}),
          },
        }));
      }
      if (!scope.ok) {
        return `git diff failed: ${scope.error ?? "unknown error"}`;
      }
      return `Findings are now scoped to ${scope.changedFiles.length} changed file${
        scope.changedFiles.length === 1 ? "" : "s"
      } since ${ref}.`;
    },
  };
}

async function loadThreatWorkspace(repoRoot: string, shellState: ShellState) {
  const { loadShellThreatModel } = await import("./threat-model-loader.js");
  const persistent = loadShellThreatModel(repoRoot);
  if (persistent) {
    const { loadContextSnapshot } = await import("../modules/sast/context-persist.js");
    const contextSnapshot =
      shellState.contextSnapshot?.target === repoRoot
        ? shellState.contextSnapshot
        : loadContextSnapshot(repoRoot);
    return {
      threatModel: persistent.document,
      contextSnapshot,
      sourcePath: persistent.sourcePath,
      mtimeMs: persistent.mtimeMs,
      sourceLabel: "persistent threat model",
    };
  }

  const { contextSnapshotPath, loadContextSnapshot } = await import(
    "../modules/sast/context-persist.js"
  );
  const snapshot =
    shellState.contextSnapshot?.target === repoRoot
      ? shellState.contextSnapshot
      : loadContextSnapshot(repoRoot);
  if (!snapshot) return null;
  const sourcePath = contextSnapshotPath(repoRoot);
  const mtimeMs = safeMtimeMs(sourcePath);
  return {
    threatModel: null,
    contextSnapshot: snapshot,
    sourcePath,
    mtimeMs,
    sourceLabel: "context snapshot",
  };
}

function safeMtimeMs(absPath: string): number {
  try {
    return statSync(absPath).mtimeMs;
  } catch {
    return 0;
  }
}

function handleThreatsCommand(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const sub = args[0]?.toLowerCase() ?? "summary";

  if (sub === "regenerate" || sub === "regen") {
    const target = resolveActiveTarget(opts, shellState);
    if (!target) return { output: "No target set. Use /target <path> first." };
    const slice = parseThreatModelRegenSlice(args[1]?.toLowerCase());
    if (!slice) {
      return {
        output: [
          "Regenerate a threat-model slice:",
          "  /threats regen all",
          "  /threats regen dfd",
          "  /threats regen stride",
          "  /threats regen stories",
          "  /threats regen scope",
          "  /threats regen scenarios",
        ].join("\n"),
      };
    }
    return resolveToolExecution(
      "threat-model:build",
      [target, `slice=${slice}`, "preserveUserEdits=true"],
      core,
      opts,
      ctx,
      shellState,
    );
  }

  if (sub === "ask") {
    const instruction = args.slice(1).join(" ").trim();
    if (!instruction) return { output: "Usage: /threats ask <instruction>" };
    const repoRoot = resolveActiveTarget(opts, shellState);
    if (!repoRoot) return { output: "No target set. Use /target <path> first." };
    return {
      output: "Asking AI for a reviewable threat-model patch…",
      asyncExecute: async (signal) => {
        const loaded = await loadThreatWorkspace(repoRoot, shellState);
        if (!loaded?.threatModel) {
          return "No threat model document available to patch. Run /threats regen dfd or /threats edit first.";
        }
        const proposal = await proposeThreatModelPatch({
          runtime: opts.runtime,
          cwd: repoRoot,
          threatModel: loaded.threatModel,
          instruction,
          signal,
        });
        if (ctx.uiStore) {
          updateShell(ctx.uiStore, (shell) => ({
            ...shell,
            shellView: "threats",
            threatTab: "dfd",
            threatModel: loaded.threatModel,
            contextSnapshot: loaded.contextSnapshot ?? shell.contextSnapshot,
            threatModelSource: { path: loaded.sourcePath, mtimeMs: loaded.mtimeMs },
            pendingThreatPatch: proposal,
          }));
        }
        return `AI proposed ${proposal.operations.length} threat-model change${
          proposal.operations.length === 1 ? "" : "s"
        }. Press y to accept, n to reject, or inspect the diff in /threats dfd.`;
      },
    };
  }

  if (sub === "apply" || sub === "accept" || sub === "yes") {
    const repoRoot = resolveActiveTarget(opts, shellState);
    if (!repoRoot) return { output: "No target set. Use /target <path> first." };
    const proposal = shellState.pendingThreatPatch;
    if (!proposal) return { output: "No pending threat-model patch to apply." };
    return {
      output: "Applying accepted threat-model patch…",
      asyncExecute: async () => {
        const loaded = await loadThreatWorkspace(repoRoot, shellState);
        if (!loaded?.threatModel) return "No threat model document available to patch.";
        const applied = applyThreatModelPatch(loaded.threatModel, proposal);
        if (!applied.ok)
          return `Patch rejected:\n${applied.errors.map((e) => `  - ${e}`).join("\n")}`;
        const { savePersistentThreatModel } = await import("../threat-model-renderer.js");
        savePersistentThreatModel(repoRoot, applied.document, true);
        const sourcePath = path.join(repoRoot, ".kuzushi", "threat-model.json");
        if (ctx.uiStore) {
          updateShell(ctx.uiStore, (shell) => ({
            ...shell,
            threatModel: applied.document,
            threatModelSource: { path: sourcePath, mtimeMs: Date.now() },
            pendingThreatPatch: null,
            threatModelDirty: false,
          }));
        }
        return "Threat-model patch accepted and saved to .kuzushi/threat-model.json.";
      },
    };
  }

  if (sub === "reject" || sub === "no") {
    return {
      output: "Pending threat-model patch rejected.",
      shellStateUpdater: (shell) => ({ ...shell, pendingThreatPatch: null }),
    };
  }

  // /threats dfd|stride|stories|scope|summary (and 1..5) — Phase C views.
  // Each routes to a tab within the single threats view; the component reads shell.threatModel which
  // this handler populates below.
  const viewRoute = resolveThreatView(sub);
  if (viewRoute) {
    const repoRoot = resolveActiveTarget(opts, shellState);
    if (!repoRoot) return { output: "No target set. Use /target <path> first." };
    return {
      output: `Loading threat model for ${viewRoute.label}…`,
      shellStateUpdater: (shell) => ({
        ...shell,
        shellView: viewRoute.shellView,
        threatTab: viewRoute.threatTab,
      }),
      asyncExecute: async () => {
        const loaded = await loadThreatWorkspace(repoRoot, shellState);
        if (!loaded) {
          return "No context or threat model found. Run /use context, then run .; then /threats regen dfd.";
        }
        if (viewRoute.threatTab !== "dfd" && !loaded.threatModel) {
          return "No threat model found for this tab. Run /threats regen dfd or /threats edit first.";
        }
        if (ctx.uiStore) {
          updateShell(ctx.uiStore, (shell) => ({
            ...shell,
            threatModel: loaded.threatModel,
            contextSnapshot: loaded.contextSnapshot ?? shell.contextSnapshot,
            threatModelSource: {
              path: loaded.sourcePath,
              mtimeMs: loaded.mtimeMs,
            },
          }));
        }
        return `Showing ${viewRoute.label}.`;
      },
    };
  }

  // /threats edit — open the threat model editor
  if (sub === "edit") {
    const repoRoot = resolveActiveTarget(opts, shellState);
    if (!repoRoot) return { output: "No target set. Use /target <path> first." };
    return {
      output: "Opening threat model editor...",
      asyncExecute: async () => {
        const {
          createEmptyThreatModelDocument,
          loadPersistentThreatModel,
          savePersistentThreatModel,
        } = await import("../threat-model-renderer.js");
        const { runThreatModelEditor } = await import("../ui/setup.js");
        let tm = loadPersistentThreatModel(repoRoot);
        let createdDraft = false;
        if (!tm) {
          tm = createEmptyThreatModelDocument();
          savePersistentThreatModel(repoRoot, tm, true);
          createdDraft = true;
        }
        if (ctx.uiStore) {
          updateShell(ctx.uiStore, (shell) => ({
            ...shell,
            shellView: "threats",
            threatTab: shell.threatTab ?? "summary",
            threatModel: tm,
            threatModelSource: {
              path: path.join(repoRoot, ".kuzushi", "threat-model.json"),
              mtimeMs: Date.now(),
            },
          }));
        }
        const outcome = await runThreatModelEditor(
          ctx.uiStore,
          tm,
          path.basename(repoRoot),
          repoRoot,
          "shell",
        );
        if (outcome.action === "proceed") {
          return "Threat model saved to .kuzushi/threat-model.json";
        }
        return createdDraft
          ? "Draft threat model created at .kuzushi/threat-model.json."
          : "Threat model editing skipped.";
      },
    };
  }

  return {
    output:
      "Usage: /threats [dfd|stride|stories|scope|summary|edit|regen <slice>]  (1..5 also switches views)",
  };
}

function resolveActiveTarget(opts: ShellOptions, shellState: ShellState): string | null {
  if (opts.target) return path.resolve(opts.target);
  const snapshotTarget = shellState.contextSnapshot?.target;
  if (!snapshotTarget) return null;
  const resolved = path.resolve(snapshotTarget);
  opts.target = resolved;
  return resolved;
}

function handleTargetCommand(
  args: string[],
  opts: ShellOptions,
  shellState: ShellState,
): LocalCommandResult {
  const newTarget = args.join(" ").trim();
  if (newTarget) {
    const hadContext = !!shellState.contextSnapshot;
    const changed = opts.target !== newTarget;
    opts.target = newTarget;
    if (changed && hadContext) {
      return {
        output: `Target set to: ${newTarget}\n  Context invalidated — run /context to regenerate.`,
        shellStateUpdater: (shell) => ({ ...shell, contextSnapshot: null }),
        targetUpdated: true,
      };
    }
    return { output: `Target set to: ${newTarget}`, targetUpdated: changed };
  }
  return {
    output: opts.target ? `Current target: ${opts.target}` : "No target set. Usage: /target <path>",
  };
}

function handleWorkspaceCommand(
  args: string[],
  opts: ShellOptions,
  ctx: ShellContext,
): LocalCommandResult {
  const sub = args[0]?.toLowerCase();
  const mgr = ctx.workspaceManager;

  // -a / -d / -r / -D / -v / -S — msfconsole-style flags. These live
  // alongside the positional subcommands (list / create / switch) so muscle
  // memory from either side keeps working.
  if (sub === "-a" && args[1] && mgr) {
    const name = args.slice(1).join(" ");
    if (mgr.getByName(name)) return { output: `[-] Workspace '${name}' already exists.` };
    const ws = mgr.create(name, opts.target ? [opts.target] : []);
    opts.workspace = ws.id;
    opts.workspaceName = ws.name;
    return { output: `[+] Workspace created: ${name} (${ws.id.slice(0, 8)})` };
  }
  if (sub === "-d" && args[1] && mgr) {
    const target = args.slice(1).join(" ");
    const existing = mgr.getByName(target);
    if (!existing) return { output: `[-] No workspace named '${target}'.` };
    mgr.delete(existing.id);
    if (opts.workspace === existing.id) {
      opts.workspace = undefined;
      opts.workspaceName = undefined;
    }
    return { output: `[+] Deleted workspace '${target}'.` };
  }
  if (sub === "-r" && args[1] && args[2] && mgr) {
    const oldName = args[1] as string;
    const newName = args[2] as string;
    const existing = mgr.getByName(oldName);
    if (!existing) return { output: `[-] No workspace named '${oldName}'.` };
    if (mgr.getByName(newName)) {
      return { output: `[-] A workspace named '${newName}' already exists.` };
    }
    mgr.update(existing.id, { name: newName });
    if (opts.workspace === existing.id) opts.workspaceName = newName;
    return { output: `[+] Renamed workspace '${oldName}' → '${newName}'.` };
  }
  // -D (capital): set default workspace for next shell launch. We check the
  // raw arg to distinguish from -d (delete). parseCommand splits on
  // whitespace but preserves case.
  if (args[0] === "-D" && args[1]) {
    const name = args.slice(1).join(" ");
    const defaultPath = path.join(homedir(), ".kuzushi", "default-workspace");
    mkdirSync(path.dirname(defaultPath), { recursive: true });
    writeFileSync(defaultPath, name, "utf8");
    return { output: `[+] Default workspace for next launch: ${name}` };
  }
  if (sub === "-v" && mgr) {
    const workspaces = mgr.list();
    if (workspaces.length === 0) return { output: "  No workspaces yet." };
    const pad = (s: string, w: number) => s + " ".repeat(Math.max(0, w - s.length));
    const rows = workspaces.map((ws) => {
      const hosts = mgr.hosts.list(ws.id).length;
      const vulns = mgr.vulns.listForWorkspace(ws.id).length;
      const loot = mgr.loot.listForWorkspace(ws.id).length;
      const notes = mgr.notes.listForWorkspace(ws.id).length;
      const creds = mgr.creds.listForWorkspace(ws.id).length;
      const sess = mgr.sessions.listForWorkspace(ws.id).length;
      const active = ws.id === opts.workspace ? " *" : "  ";
      return `${active}${pad(ws.name, 24)} hosts=${hosts} vulns=${vulns} loot=${loot} notes=${notes} creds=${creds} sessions=${sess}`;
    });
    return { output: ["Workspaces (counts):", ...rows].join("\n") };
  }
  if ((args[0] === "-S" || args[0] === "-s") && mgr) {
    if (!args[1]) return { output: "Usage: workspace -S <pattern>" };
    return filteredWorkspaceListing(mgr, args.slice(1).join(" "), opts.workspace);
  }

  // /workspace list
  if (sub === "list" && mgr) {
    const workspaces = mgr.list();
    if (workspaces.length === 0) return { output: "  No workspaces yet." };
    const rows = workspaces.map((ws) => {
      const targets = ws.targets.length > 0 ? ws.targets.join(", ") : "no targets";
      const active = ws.id === opts.workspace ? " (active)" : "";
      return `  ${ws.name}${active}  —  ${targets}  [${ws.lastAccessedAt.slice(0, 10)}]`;
    });
    return { output: formatSections([["  Workspaces", ...rows]]) };
  }

  // /workspace create <name>
  if (sub === "create" && args[1] && mgr) {
    const name = args.slice(1).join(" ");
    const ws = mgr.create(name, opts.target ? [opts.target] : []);
    opts.workspace = ws.id;
    opts.workspaceName = ws.name;
    return { output: `Workspace created: ${name} (${ws.id.slice(0, 8)})` };
  }

  // /workspace switch <name> or /workspace <name> (backward compat)
  const name = sub === "switch" ? args.slice(1).join(" ").trim() : args.join(" ").trim();
  if (name) {
    if (mgr) {
      const ws = mgr.getOrCreate(name, opts.target ? [opts.target] : []);
      mgr.touchAccessed(ws.id);
      opts.workspace = ws.id;
      opts.workspaceName = ws.name;
      return {
        output: `Workspace: ${ws.name} (${ws.targets.length} targets, last accessed ${ws.lastAccessedAt.slice(0, 10)})`,
      };
    }
    opts.workspace = name;
    opts.workspaceName = name;
    return { output: `Workspace set to: ${name}` };
  }

  // /workspace (show current)
  if (opts.workspace && mgr) {
    const ws = mgr.get(opts.workspace);
    if (ws) {
      const cost =
        typeof ws.metadata.totalCostUsd === "number"
          ? `$${ws.metadata.totalCostUsd.toFixed(2)}`
          : "—";
      return {
        output: formatSections([
          [
            `  Workspace: ${ws.name}`,
            ...formatLabelValueRows([
              ["ID:", ws.id.slice(0, 8)],
              ["Targets:", ws.targets.join(", ") || "none"],
              ["Created:", ws.createdAt.slice(0, 10)],
              ["Last accessed:", ws.lastAccessedAt.slice(0, 10)],
              ["Total cost:", cost],
            ]),
          ],
        ]),
      };
    }
  }

  return {
    output: opts.workspace
      ? `Current workspace: ${opts.workspaceName ?? opts.workspace}`
      : "No workspace set. Usage: /workspace <name>",
  };
}

function handleLoadCommand(args: string[], core: CopilotCore): LocalCommandResult {
  const specifier = args.join(" ").trim();
  if (!specifier) {
    return {
      output:
        "Usage: /load <module-specifier>\n  Examples: /load file:///path/to/module, /load package:@kuzushi/blackbox",
    };
  }
  return {
    asyncExecute: async () => {
      try {
        await core.loadModuleFromSpecifier(specifier);
        const modules = core.listModules();
        const tools = core.registry.allTools();
        return `Module loaded: ${specifier}\n  ${modules.length} modules, ${tools.length} tools available.`;
      } catch (err) {
        return `Failed to load module: ${toErrorMessage(err)}`;
      }
    },
  };
}

function resolveDirectToolDispatch(
  input: string,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult | undefined {
  const { cmd, args } = parseCommand(input);
  if (!cmd) {
    return undefined;
  }

  if (cmd.includes(":")) {
    return resolveToolExecution(cmd, args, core, opts, ctx, shellState);
  }

  // Focused-module shorthand takes precedence over the `run <tool>` escape.
  // Without this, inside a module whose primary tool is literally named `run`
  // (e.g. `carlini-threat-hunt:run`), typing `run .` is parsed as "dispatch tool `.`"
  // instead of "dispatch carlini-threat-hunt:run with positional `.`".
  if (ctx.focusedModule) {
    const qualifiedName = `${ctx.focusedModule}:${cmd}`;
    if (core.registry.resolveTool(qualifiedName)) {
      return resolveToolExecution(qualifiedName, args, core, opts, ctx, shellState);
    }
  }

  if (cmd.toLowerCase() === "run" && ctx.focusedModule && args.length === 0) {
    const defaultToolName = pickDefaultToolName(core, ctx.focusedModule);
    if (defaultToolName) {
      return resolveToolExecution(defaultToolName, args, core, opts, ctx, shellState);
    }
  }

  // `run <tool> [args]` explicit escape. Kept after focused-module resolution
  // so that a focused module whose tool is named `run` wins; still available
  // at top level and for explicit cross-module dispatch like `run sast:scan .`.
  if (cmd.toLowerCase() === "run" && args.length > 0) {
    if (ctx.focusedModule) {
      const explicitToolName = resolveToolName(args[0]!, core, ctx.focusedModule);
      const firstArgTargetsDefaultTool =
        looksLikePath(args[0]!) || args[0]!.includes("=") || args[0]!.startsWith("-");
      if (!explicitToolName && firstArgTargetsDefaultTool) {
        const defaultToolName = pickDefaultToolName(core, ctx.focusedModule);
        if (defaultToolName) {
          return resolveToolExecution(defaultToolName, args, core, opts, ctx, shellState);
        }
      }
    }
    return resolveToolExecution(args[0]!, args.slice(1), core, opts, ctx, shellState);
  }

  const resolvedToolName = resolveToolName(cmd, core, null);
  if (resolvedToolName) {
    return resolveToolExecution(resolvedToolName, args, core, opts, ctx, shellState);
  }

  return undefined;
}

function isLivePauseResumeActive(shellState: ShellState): boolean {
  return (
    shellState.moduleRun?.status === "running" &&
    shellState.moduleRun.liveControl === "pause-resume"
  );
}

function handleLiveQueueControl(
  paused: boolean,
  core: CopilotCore,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const toolName = shellState.moduleRun?.toolName;
  const tool = toolName ? core.registry.resolveTool(toolName)?.tool : undefined;
  if (tool?.runLifecycle?.liveControl !== "pause-resume") {
    return { output: "No live pause/resume control is active for this module run." };
  }
  const store = ctx.uiStore;
  if (!store) {
    return { output: "Live pause/resume requires the interactive shell UI." };
  }
  const current = store.getState().replState;
  store.update({
    replState: {
      skippedFingerprints: current?.skippedFingerprints ?? new Set<string>(),
      suppressedRules: current?.suppressedRules ?? new Set<string>(),
      focusPath: current?.focusPath ?? null,
      paused,
    },
  });
  return {
    keepProcessing: true,
    shellStateUpdater: (shell) => ({
      ...shell,
      processing: true,
      shellView: "module-run",
      moduleRun: shell.moduleRun
        ? {
            ...shell.moduleRun,
            status: shell.moduleRun.status === "running" ? "running" : shell.moduleRun.status,
          }
        : shell.moduleRun,
    }),
    output: paused
      ? "Paused queued triage. Current in-flight work will finish."
      : "Resumed queued triage.",
  };
}

function targetRepoCandidates(opts: ShellOptions, shellState: ShellState): Set<string> {
  const rawTarget = opts.target ?? shellState.target ?? process.cwd();
  const ids = new Set<string>([rawTarget, process.cwd(), path.resolve(process.cwd())]);
  try {
    ids.add(path.resolve(rawTarget));
  } catch {
    // URL/host targets are not path-resolvable in a useful way.
  }
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(rawTarget)) {
    ids.add(path.basename(path.resolve(rawTarget)));
  }
  return ids;
}

function normalizeShellTargetInput(value: unknown, activeTarget: string | undefined): unknown {
  if (typeof value !== "string" || !activeTarget) return value;
  const trimmed = value.trim();
  return trimmed === "." || trimmed === "./" ? activeTarget : value;
}

async function executeResumeTool(
  tool: ModuleTool,
  runId: string,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
  signal?: AbortSignal,
): Promise<AsyncExecutionResult> {
  const storedArgs = shellState.moduleOptions[tool.name] ?? {};
  const target = opts.target ?? shellState.target ?? process.cwd();
  const input: Record<string, unknown> = {
    ...storedArgs,
    target,
    resume: runId,
  };
  const modelDatastore = createShellModelDatastore(opts.config, input);
  if (modelDatastore.error) {
    return {
      output: modelDatastore.error,
      ok: false,
    };
  }
  const toolInput = stripSyntheticModelOptionFromInput(tool, input);
  const threatModel =
    shellState.threatModel ??
    (!/^[a-z][a-z0-9+.-]*:\/\//i.test(target)
      ? loadPersistentThreatModel(path.resolve(target))
      : null);
  const seedTaskOutputs = shellState.contextSnapshot
    ? buildSeedMapFromSnapshot(shellState.contextSnapshot, {
        ...(threatModel ? { threatModel } : {}),
      })
    : undefined;
  seedCheckpointModuleRun(
    ctx.uiStore,
    shellState,
    tool,
    Date.now(),
    `resume ${runId}`,
    modelDatastore.datastore?.get<string>("model"),
    readStoredEffortOption(input),
    readStoredThinkingDisabledOption(input),
  );
  const result = await core.executeTool(tool.name, toolInput, {
    cwd: /^[a-z][a-z0-9+.-]*:\/\//i.test(target) ? process.cwd() : path.resolve(target),
    target,
    workspaceId: opts.workspace,
    uiStore: ctx.uiStore,
    signal,
    seedTaskOutputs,
    ...(modelDatastore.datastore ? { datastore: modelDatastore.datastore } : {}),
  });
  return {
    output: result.output,
    ok: result.ok,
    costUsd: result.costUsd,
  };
}

/**
 * N3: dump the workspace's findings to disk via JSON / CSV / SARIF. Reads
 * `workspaceManager.vulns.listForWorkspace(...)` (the same source `/findings`
 * renders) so operators get the same view they see in the TUI. Format and
 * output path:
 *
 *   /findings export json [path]    → JSON
 *   /findings export csv  [path]    → CSV
 *   /findings export sarif [path]   → SARIF 2.1.0
 *
 * If no path is supplied we default to `<dataDir>/findings.<fmt>`. `dataDir`
 * comes from ShellContext (resolved at startup).
 */
function handleFindingsExportCommand(
  args: string[],
  opts: ShellOptions,
  ctx: ShellContext,
): LocalCommandResult {
  const fmt = args[0]?.toLowerCase().trim();
  if (!fmt || !["json", "csv", "sarif"].includes(fmt)) {
    return {
      output: "Usage: /findings export <json|csv|sarif> [path]",
    };
  }
  if (!opts.workspace || !ctx.workspaceManager) {
    return {
      output: "/findings export needs an active workspace. Use /workspace use <name> first.",
    };
  }
  const ws = ctx.workspaceManager;
  const wsId = opts.workspace;
  const dataDir = ctx.dataDir ?? path.resolve(".kuzushi");
  const outputPath = args[1]
    ? path.resolve(args[1]!)
    : path.join(dataDir, `findings.${fmt === "sarif" ? "sarif.json" : fmt}`);

  return {
    output: `Exporting findings to ${outputPath}…`,
    asyncExecute: async () => {
      const vulns = ws.vulns.listForWorkspace(wsId) as ReadonlyArray<{
        id: string;
        name: string;
        severity: string | null;
        checkCode: string | null;
        filePath?: string;
        startLine?: number;
        message?: string;
        references?: ReadonlyArray<unknown>;
      }>;
      if (vulns.length === 0) {
        return `No findings in workspace "${wsId}". Run a scan first.`;
      }
      const fs = await import("node:fs/promises");
      try {
        if (fmt === "json") {
          await fs.writeFile(
            outputPath,
            JSON.stringify({ workspace: wsId, count: vulns.length, findings: vulns }, null, 2),
          );
        } else if (fmt === "csv") {
          const header = "id,severity,checkCode,name,filePath,startLine,message";
          const rows = vulns
            .map((v) =>
              [
                csvEscape(v.id),
                csvEscape(v.severity ?? ""),
                csvEscape(v.checkCode ?? ""),
                csvEscape(v.name),
                csvEscape(v.filePath ?? ""),
                String(v.startLine ?? ""),
                csvEscape(v.message ?? ""),
              ].join(","),
            )
            .join("\n");
          await fs.writeFile(outputPath, `${header}\n${rows}\n`);
        } else {
          // SARIF 2.1.0 minimal envelope. The full pipeline-aware report
          // builder lives in src/report-sarif.ts but it requires a runs DB
          // and pipeline stats; the workspace-level export only needs the
          // findings themselves, so we emit the minimum viable shape that
          // every SARIF consumer accepts.
          const sarif = {
            version: "2.1.0",
            $schema: "https://json.schemastore.org/sarif-2.1.0.json",
            runs: [
              {
                tool: { driver: { name: "kuzushi", informationUri: "https://kuzushi.io" } },
                results: vulns.map((v) => ({
                  ruleId: v.checkCode ?? "kuzushi.finding",
                  level: severityToSarifLevel(v.severity),
                  message: { text: v.message ?? v.name },
                  locations: v.filePath
                    ? [
                        {
                          physicalLocation: {
                            artifactLocation: { uri: v.filePath },
                            region: { startLine: v.startLine ?? 1 },
                          },
                        },
                      ]
                    : [],
                })),
              },
            ],
          };
          await fs.writeFile(outputPath, JSON.stringify(sarif, null, 2));
        }
        return `Wrote ${vulns.length} finding${vulns.length === 1 ? "" : "s"} → ${outputPath}`;
      } catch (err) {
        return `Failed to write ${outputPath}: ${toErrorMessage(err)}`;
      }
    },
  };
}

function csvEscape(value: string): string {
  if (!value) return "";
  if (/[",\n\r]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

function severityToSarifLevel(severity: string | null): "error" | "warning" | "note" | "none" {
  switch ((severity ?? "").toLowerCase()) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
    case "info":
      return "note";
    default:
      return "none";
  }
}

function handleResumeCommand(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const moduleId = ctx.focusedModule;
  // N1: top-level `/resume` — when no module is focused, scan EVERY loaded
  // module's checkpoint candidates, pick the most recent, and resume it.
  // The catalog already shows the same candidates per module; this is the
  // shortcut that operators have been asking for.
  if (!moduleId) {
    return resumeMostRecentAcrossModules(args, core, opts, ctx, shellState);
  }

  const tool = pickCheckpointResumeTool(core, moduleId);
  if (!tool) {
    return {
      output: `${moduleId} does not expose checkpoint resume. Use run/restart for new work or replay for completed runs.`,
    };
  }

  const explicitRunId = args[0]?.trim();
  if (explicitRunId) {
    return {
      output: `Resuming ${explicitRunId} with ${tool.name}…`,
      executedToolName: tool.name,
      asyncExecute: (signal?: AbortSignal) =>
        executeResumeTool(tool, explicitRunId, core, opts, ctx, shellState, signal),
    };
  }

  return {
    output: `Looking for resumable ${moduleId} runs…`,
    executedToolName: tool.name,
    asyncExecute: async (signal?: AbortSignal) => {
      const db = await openRunsDb(ctx, opts.target ?? shellState.target ?? undefined);
      if (!db) {
        return `No runs database found. Run ${tool.name} first, then resume unfinished checkpoints.`;
      }
      try {
        const { listRuns } = await import("../store.js");
        const repoIds = targetRepoCandidates(opts, shellState);
        const runs = listRuns(db, { limit: 250 }).filter((run) => repoIds.has(run.repo));
        const candidates = selectResumeCandidates(runs, moduleId, tool);
        if (candidates.length === 0) {
          return `No resumable run for ${moduleId} on ${opts.target ?? shellState.target ?? process.cwd()}. Use run to start fresh or /show runs to inspect history.`;
        }
        if (candidates.length > 1) {
          return `${formatResumeChooser(candidates)}\n\nRun /resume <runId> to continue one.`;
        }
        const candidate = candidates[0]!;
        return executeResumeTool(tool, candidate.runId, core, opts, ctx, shellState, signal);
      } finally {
        db.close();
      }
    },
  };
}

/**
 * N1: bare `/resume` (no focused module). Walks every module that exposes
 * checkpoint resume, gathers candidates, picks the most recent by start
 * time, and resumes it. With an explicit runId argument, scans every
 * module for that run and dispatches to the owning module's resume tool.
 */
function resumeMostRecentAcrossModules(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const explicitRunId = args[0]?.trim();
  return {
    output: explicitRunId
      ? `Looking for run ${explicitRunId}…`
      : "Looking for the most recent resumable run across all modules…",
    asyncExecute: async (signal?: AbortSignal) => {
      const db = await openRunsDb(ctx, opts.target ?? shellState.target ?? undefined);
      if (!db) {
        return "No runs database found. Run a module first, then /resume to continue an unfinished checkpoint.";
      }
      try {
        const { listRuns } = await import("../store.js");
        const repoIds = targetRepoCandidates(opts, shellState);
        const runs = listRuns(db, { limit: 250 }).filter((run) => repoIds.has(run.repo));
        type Pick = {
          moduleId: string;
          tool: ModuleTool;
          candidate: ReturnType<typeof selectResumeCandidates>[number];
        };
        const picks: Pick[] = [];
        for (const mod of core.listModules()) {
          const tool = pickCheckpointResumeTool(core, mod.id);
          if (!tool) continue;
          const candidates = selectResumeCandidates(runs, mod.id, tool);
          for (const candidate of candidates) {
            if (explicitRunId && candidate.runId !== explicitRunId) continue;
            picks.push({ moduleId: mod.id, tool, candidate });
          }
        }
        if (picks.length === 0) {
          return explicitRunId
            ? `No resumable run with id "${explicitRunId}" found. /show runs to inspect history.`
            : "No resumable runs found across loaded modules. /show runs to inspect history.";
        }
        picks.sort((a, b) => Date.parse(b.candidate.startedAt) - Date.parse(a.candidate.startedAt));
        const winner = picks[0]!;
        const restored = { ...ctx, focusedModule: winner.moduleId };
        return executeResumeTool(
          winner.tool,
          winner.candidate.runId,
          core,
          opts,
          restored,
          shellState,
          signal,
        );
      } finally {
        db.close();
      }
    },
  };
}

/**
 * Build a tool execution result — runs the tool directly through CopilotCore.
 * Passes the UIStore so pipeline tools render through the Ink UI
 * (PipelineIndicator, StatusFooter, ResultLine — the full scan experience).
 */
function resolveToolExecution(
  toolName: string,
  toolArgs: string[],
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const resolvedToolName = resolveToolName(toolName, core, ctx.focusedModule);
  if (!resolvedToolName) {
    return { output: formatUnknownToolMessage(toolName, core) };
  }

  const finalToolName = resolvedToolName;
  const resolvedTool = core.registry.resolveTool(finalToolName);
  if (!resolvedTool) {
    return { output: formatUnknownToolMessage(finalToolName, core) };
  }

  const storedArgs = shellState.moduleOptions[finalToolName] ?? {};
  const parsedArgs = parseToolArgs(toolArgs);
  const mergedArgs: Record<string, unknown> = { ...storedArgs, ...parsedArgs };
  if ("target" in mergedArgs) {
    mergedArgs.target = normalizeShellTargetInput(mergedArgs.target, opts.target);
  }
  if (!("target" in mergedArgs) && opts.target) {
    mergedArgs.target = opts.target;
  }

  // Context gating — block tools that require context/threat-model state when missing.
  const contextRequirementError = getContextRequirementError(
    finalToolName,
    shellState,
    mergedArgs,
    opts,
  );
  if (contextRequirementError) {
    return { output: contextRequirementError };
  }

  return {
    executedToolName: finalToolName,
    asyncExecute: async (signal?: AbortSignal) => {
      const target =
        typeof mergedArgs.target === "string" && mergedArgs.target.trim()
          ? mergedArgs.target
          : opts.target;
      const threatModel =
        shellState.threatModel ??
        (target && !/^[a-z][a-z0-9+.-]*:\/\//i.test(target)
          ? loadPersistentThreatModel(path.resolve(target))
          : null);
      const seedTaskOutputs = shellState.contextSnapshot
        ? buildSeedMapFromSnapshot(shellState.contextSnapshot, {
            ...(threatModel ? { threatModel } : {}),
          })
        : undefined;
      const modelDatastore = createShellModelDatastore(opts.config, mergedArgs);
      if (modelDatastore.error) {
        return {
          output: modelDatastore.error,
          ok: false,
        };
      }
      const toolInput = stripSyntheticModelOptionFromInput(resolvedTool.tool, mergedArgs);
      const inputSummary = resolvedTool.tool.formatInput?.(toolInput) ?? undefined;
      seedFocusedModuleRun(
        ctx.uiStore,
        shellState,
        resolvedTool.tool,
        Date.now(),
        inputSummary,
        modelDatastore.datastore?.get<string>("model"),
        readStoredEffortOption(mergedArgs),
        readStoredThinkingDisabledOption(mergedArgs),
      );

      const result = await core.executeTool(finalToolName, toolInput, {
        cwd: opts.target ? path.resolve(opts.target) : process.cwd(),
        target: (mergedArgs.target as string) ?? opts.target,
        workspaceId: opts.workspace,
        uiStore: ctx.uiStore,
        signal,
        seedTaskOutputs,
        ...(modelDatastore.datastore ? { datastore: modelDatastore.datastore } : {}),
      });

      // Track cost in workspace
      if (result.costUsd && opts.workspace && ctx.workspaceManager) {
        try {
          const ws = ctx.workspaceManager.get(opts.workspace);
          if (ws) {
            const prevCost =
              typeof ws.metadata.totalCostUsd === "number" ? ws.metadata.totalCostUsd : 0;
            ctx.workspaceManager.update(ws.id, {
              metadata: { ...ws.metadata, totalCostUsd: prevCost + result.costUsd },
            });
          }
        } catch {
          /* non-critical */
        }
      }

      return {
        output: result.output,
        ok: result.ok,
        costUsd: result.costUsd,
      };
    },
  };
}

function getContextRequirementError(
  toolName: string,
  shellState: ShellState,
  input: Record<string, unknown>,
  opts: ShellOptions,
): string | undefined {
  if (!CONTEXT_REQUIRED_TOOLS.has(toolName)) return undefined;
  const snapshot = shellState.contextSnapshot;
  const inputTarget =
    typeof input.target === "string" && input.target.trim() ? input.target : undefined;
  const target = inputTarget ?? opts.target ?? snapshot?.target;
  const persistentThreatModel =
    target && !/^[a-z][a-z0-9+.-]*:\/\//i.test(target)
      ? loadPersistentThreatModel(path.resolve(target))
      : null;

  if (toolName === "taint-iris-next:hunt" && target && !/^[a-z][a-z0-9+.-]*:\/\//i.test(target)) {
    const artifacts = resolveTaintIrisNextPersistentArtifacts(path.resolve(target));
    if (artifacts.contextStatus.ok) return undefined;
    return [
      `Context incomplete for ${toolName}. Run /context, then rerun the module.`,
      `context: ${formatIrisNextArtifactStatus(artifacts.contextStatus)}`,
      `threat model: ${formatIrisNextArtifactStatus(artifacts.threatModelStatus)} (warning only)`,
    ].join("\n");
  }

  if (!snapshot) {
    if (toolName === "carlini-threat-hunt:run") {
      const nextStep = persistentThreatModel
        ? "Run /use context, then run . to build app/operator context."
        : "Run /use context, then run .; then /use threat-model and run .";
      return `Context required for ${toolName}. ${nextStep}`;
    }
    if (toolName === "taint-iris-next:hunt") {
      return `Context required for ${toolName}. Run /context first. /threats regen dfd improves ranking but is optional.`;
    }
    return `Context required for ${toolName}. Run /use context, then run .`;
  }

  const missing: string[] = [];
  const needsThreatModel = toolName === "carlini-threat-hunt:run";
  const needsAppModel =
    toolName === "taint-iris-next:hunt" ||
    toolName === "taint-iris:hunt" ||
    toolName === "sast:taint-iris";
  const hasThreatModel = !!(shellState.threatModel ?? persistentThreatModel);

  if (needsThreatModel && !hasThreatModel) {
    missing.push("threat model");
  }
  if (needsAppModel && !snapshot.appModel) {
    missing.push("app model");
  }

  if (missing.length === 0) return undefined;
  const hint = needsThreatModel
    ? "Run /use context, then run .; then /use threat-model and run ."
    : "Run /use context, then run .";
  return `Context incomplete for ${toolName}: missing ${missing.join(" and ")}. ${hint}`;
}

function formatIrisNextArtifactStatus(status: {
  ok: boolean;
  path?: string;
  reason: string;
}): string {
  const state = status.ok ? "loaded" : "missing/incomplete";
  return status.path
    ? `${state} (${status.path}; ${status.reason})`
    : `${state} (${status.reason})`;
}

function resolveOptionsTool(
  core: CopilotCore,
  toolName: string | undefined,
  focusedModule: string | null,
  lastUsedTool: string | undefined,
): { ok: true; toolName: string } | { ok: false; output: string } {
  if (toolName) {
    const resolved = resolveToolName(toolName, core, focusedModule);
    if (!resolved) {
      return { ok: false, output: formatUnknownToolMessage(toolName, core) };
    }
    return { ok: true, toolName: resolved };
  }

  if (!lastUsedTool) {
    if (focusedModule) {
      const fallbackToolName = pickDefaultToolName(core, focusedModule);
      if (fallbackToolName) return { ok: true, toolName: fallbackToolName };
    }
    return {
      ok: false,
      output: `Usage: /options <tool>\nAvailable tools: ${formatToolChoices(core, focusedModule)}`,
    };
  }

  if (focusedModule && !lastUsedTool.startsWith(`${focusedModule}:`)) {
    const fallbackToolName = pickDefaultToolName(core, focusedModule);
    if (fallbackToolName) return { ok: true, toolName: fallbackToolName };
    return {
      ok: false,
      output: `No active tool selected for ${focusedModule}. Use /options <tool> first.\nAvailable tools: ${formatToolChoices(core, focusedModule)}`,
    };
  }

  return { ok: true, toolName: lastUsedTool };
}

function formatOptions(
  core: CopilotCore,
  toolName: string,
  opts: ShellOptions,
  shellState: ShellState,
): string {
  const built = buildOptionsViewSlice(core, toolName, opts, shellState);
  if (!built.ok) {
    return built.output;
  }
  const view = built.view;
  if (view.rows.length === 0) {
    return `  ${toolName} has no configurable options.`;
  }

  const optionWidth = Math.max("Option".length, ...view.rows.map((row) => row.optionName.length));
  const valueWidth = Math.max("Value".length, ...view.rows.map((row) => row.valueLabel.length));
  const defaultWidth = Math.max(
    "Default".length,
    ...view.rows.map((row) => row.defaultLabel.length),
  );

  const sections: string[][] = [];
  if (view.taskSummary) {
    sections.push([
      "  Effective task selection",
      `  ${view.taskSummary.stateLine}`,
      `  ${view.taskSummary.commands}`,
    ]);
  }

  sections.push([
    `  ${view.toolName} options                              * = set`,
    "",
    `  ${"Option".padEnd(optionWidth)}  ${"Value".padEnd(valueWidth)}  ${"Default".padEnd(defaultWidth)}  Description`,
    `  ${"-".repeat(optionWidth)}  ${"-".repeat(valueWidth)}  ${"-".repeat(defaultWidth)}  -----------`,
    ...view.rows.map(
      (row) =>
        `  ${row.optionName.padEnd(optionWidth)}  ${row.valueLabel.padEnd(valueWidth)}  ${row.defaultLabel.padEnd(defaultWidth)}  ${row.description}`,
    ),
    ...(view.tip ? ["", `  ${view.tip}`] : []),
  ]);

  return formatSections(sections);
}

function buildOptionsViewSlice(
  core: CopilotCore,
  toolName: string,
  opts: ShellOptions,
  shellState: ShellState,
): { ok: true; view: OptionsViewSlice } | { ok: false; output: string } {
  const resolved = core.registry.resolveTool(toolName);
  if (!resolved) {
    return { ok: false, output: formatUnknownToolMessage(toolName, core) };
  }

  const properties = getEffectiveToolProperties(resolved.tool, opts.config);
  const optionNames = Object.keys(properties);
  const storedValues = shellState.moduleOptions[toolName] ?? {};
  const rows = optionNames.map((optionName) => {
    const schema = properties[optionName]!;
    const storedKey = Object.keys(storedValues).find(
      (key) => key.toUpperCase() === optionName.toUpperCase(),
    );
    const hasStoredValue = storedKey !== undefined;
    const value = storedKey
      ? storedValues[storedKey]
      : optionName === "target" && opts.target
        ? opts.target
        : undefined;
    return {
      optionName,
      valueLabel: formatEffectiveOptionValueLabel({
        toolName,
        optionName,
        value,
        hasStoredValue,
        storedValues,
      }),
      defaultLabel: formatValue(schema.default),
      description: formatEffectiveOptionDescription(toolName, optionName, schema),
      isSet: hasStoredValue,
    };
  });
  let taskSummary: OptionsViewSlice["taskSummary"];
  let tip: string | undefined;
  if (toolName === SAST_SCAN_TOOL_NAME) {
    const summary = buildSastTaskSelectionSummary({
      options: storedValues,
      tune: shellState.tuneSnapshot,
    });
    taskSummary = {
      stateLine: formatSastTaskStateLine(summary),
      commands: "commands: /tasks · /task toggle [id] · /task mode toggle · scan .",
    };
    tip = "tip: use /tasks from kuzushi/sast> to choose scanners and detectors.";
  }

  return {
    ok: true,
    view: {
      toolName,
      rows,
      ...(taskSummary ? { taskSummary } : {}),
      ...(tip ? { tip } : {}),
    },
  };
}

function formatEffectiveOptionValueLabel(input: {
  toolName: string;
  optionName: string;
  value: unknown;
  hasStoredValue: boolean;
  storedValues: Record<string, unknown>;
}): string {
  const { toolName, optionName, value, hasStoredValue, storedValues } = input;
  if (toolName !== SAST_SCAN_TOOL_NAME) {
    return hasStoredValue ? `* ${formatValue(value)}` : formatValue(value);
  }

  if (optionName === "taskMode" && !hasStoredValue) {
    return "auto";
  }

  if (optionName === "tasks") {
    const tasks = hasStoredValue ? readStringArrayOption(value) : readManualSastTasks(storedValues);
    if (tasks.length === 0) return hasStoredValue ? "* none" : "auto";
    return `${hasStoredValue ? "* " : ""}${tasks.join(",")}`;
  }

  if (optionName === "disabledTasks") {
    const disabled = hasStoredValue
      ? readStringArrayOption(value)
      : readDisabledSastTasks(storedValues);
    if (disabled.length === 0) return hasStoredValue ? "* none" : "none";
    return `${hasStoredValue ? "* " : ""}${disabled.join(",")}`;
  }

  return hasStoredValue ? `* ${formatValue(value)}` : formatValue(value);
}

function formatEffectiveOptionDescription(
  toolName: string,
  optionName: string,
  schema: ToolPropertySchema,
): string {
  const description = formatOptionDescription(schema);
  if (
    toolName === SAST_SCAN_TOOL_NAME &&
    (optionName === "taskMode" || optionName === "tasks" || optionName === "disabledTasks")
  ) {
    return `${description} Use /tasks to edit.`;
  }
  return description;
}

type PromptEditorAuditRows = NonNullable<NonNullable<ShellState["promptsEditor"]>["audit"]>;

interface PromptTarget {
  moduleId: string;
  toolName: string;
  /** Display/action name shown in the prompts editor. */
  name: string;
  promptKey: PromptOptionKey;
}

function buildPromptEditorAuditRows(
  core: CopilotCore,
  opts: ShellOptions,
  moduleOptions: Record<string, Record<string, unknown>>,
  moduleId: string,
): PromptEditorAuditRows {
  const cwd = opts.target ? path.resolve(opts.target) : process.cwd();
  return readPromptAudit(core, moduleOptions, cwd)
    .filter((r) => r.moduleId === moduleId)
    .map((r) => ({
      moduleId: r.moduleId,
      toolName: r.toolName,
      verb: r.verb,
      promptKey: String(r.promptKey),
      effective: {
        source: r.effective.source,
        ...(r.effective.filePath ? { filePath: r.effective.filePath } : {}),
        ...(r.effective.byteLen != null ? { byteLen: r.effective.byteLen } : {}),
        ...(r.effective.rawValue != null ? { rawValue: r.effective.rawValue } : {}),
      },
    }));
}

function resolvePromptTarget(
  nameArg: string | undefined,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): { ok: true; target: PromptTarget } | { ok: false; output: string } {
  if (!ctx.focusedModule) {
    return { ok: false, output: "No focused module. Use /use <module> first." };
  }
  const name = nameArg?.trim();
  if (!name) {
    return { ok: false, output: "Usage: /prompt <edit|show|diff|reset> <name>" };
  }

  const cwd = opts.target ? path.resolve(opts.target) : process.cwd();
  const rows = readPromptAudit(core, shellState.moduleOptions, cwd).filter(
    (r) => r.moduleId === ctx.focusedModule,
  );
  const normalized = name.toLowerCase();
  const row =
    rows.find((r) => r.verb.toLowerCase() === normalized) ??
    rows.find((r) => promptKeyToVerb(r.promptKey).toLowerCase() === normalized) ??
    rows.find((r) => r.toolName.toLowerCase() === `${ctx.focusedModule}:${normalized}`);

  if (!row) {
    const available = rows.map((r) => r.verb).sort();
    return {
      ok: false,
      output:
        available.length > 0
          ? `No prompt override named "${name}" for ${ctx.focusedModule}. Available: ${available.join(", ")}.`
          : `No tools in ${ctx.focusedModule} declare prompt overrides.`,
    };
  }

  return {
    ok: true,
    target: {
      moduleId: row.moduleId,
      toolName: row.toolName,
      name: row.verb,
      promptKey: row.promptKey,
    },
  };
}

function stripWrappingQuotes(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length >= 2) {
    const first = trimmed[0];
    const last = trimmed[trimmed.length - 1];
    if ((first === `"` && last === `"`) || (first === "'" && last === "'")) {
      return trimmed.slice(1, -1);
    }
  }
  return trimmed;
}

function promptOptionRef(toolName: string, promptKey: PromptOptionKey): string {
  return `\`${toolName}.${promptKey}\``;
}

/**
 * `/prompt edit <verb>` — opens $EDITOR on `.kuzushi/prompts/<module>/<verb>.md`,
 * saves on exit, and seeds `shell.moduleOptions[<tool>][<KEY>_PROMPT]` with
 * the absolute path. `resolvePromptValue` in the module layer reads this at
 * tool-execution time.
 */
function handlePromptEditCommand(
  verbArg: string | undefined,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  if (!ctx.focusedModule) {
    return { output: "No focused module. Use /use <module> first." };
  }
  if (!ctx.dataDir) {
    return { output: "No data directory resolved for this shell." };
  }
  const verb = verbArg?.trim();
  if (!verb) {
    return { output: "Usage: /prompt edit <name>  (e.g. /prompt edit triage)" };
  }
  const targetResult = resolvePromptTarget(verb, core, opts, ctx, shellState);
  if (!targetResult.ok) return { output: targetResult.output };
  const target = targetResult.target;
  const resolved = core.registry.resolveTool(target.toolName);
  if (!resolved) {
    return { output: `Tool ${target.toolName} not found. Use /tools to list.` };
  }
  const dataDir = ctx.dataDir;
  const description = resolved.tool.description;
  return {
    output: `Opening ${target.promptKey} override in $EDITOR…`,
    asyncExecute: async () => {
      try {
        const outcome = await editPrompt({
          dataDir,
          moduleId: target.moduleId,
          verb: target.name,
          promptKey: target.promptKey,
          toolDescription: description,
        });
        if (!outcome.saved) {
          return "Prompt editor closed without saving.";
        }
        // Store the absolute path on the shell's in-memory option map so the
        // same path the tool reads at run-time matches what we just wrote.
        // Also record `promptsEditor.lastSaved{,At}` so the prompts editor
        // view can render its after-vim "Saved prompt override" card.
        if (ctx.uiStore) {
          const liveShell = ctx.uiStore.getState().shell;
          const nextModuleOptions = {
            ...(liveShell?.moduleOptions ?? {}),
            [target.toolName]: {
              ...(liveShell?.moduleOptions[target.toolName] ?? {}),
              [outcome.promptKey]: outcome.filePath,
            },
          };
          updateShell(ctx.uiStore, (shell) => ({
            ...shell,
            moduleOptions: nextModuleOptions,
            lastUsedTool: target.toolName,
            promptsEditor: {
              ...(shell.promptsEditor ?? {}),
              audit: buildPromptEditorAuditRows(core, opts, nextModuleOptions, target.moduleId),
              lastSavedAt: Date.now(),
              lastSaved: {
                name: target.name,
                path: outcome.filePath,
                size: outcome.byteLen,
              },
            },
          }));
        }
        return [
          `Saved ${outcome.byteLen} bytes to ${outcome.filePath}`,
          `Set ${promptOptionRef(target.toolName, outcome.promptKey)} = ${outcome.filePath}`,
        ].join("\n");
      } catch (err) {
        return `Prompt editor error: ${toErrorMessage(err)}`;
      }
    },
  };
}

/**
 * `/actor <n|fingerprint>` — drill into a per-actor transcript from
 * inside ModuleRunView. Numeric arguments resolve against the
 * sorted carlini-threat-hunt fingerprints in `state.agentActivity` (1-based);
 * non-numeric arguments are treated as a literal fingerprint.
 */
function handleActorCommand(
  args: string[],
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const arg = args[0]?.trim();
  if (!arg) return { output: "Usage: /actor <n|fingerprint>" };
  const live = ctx.uiStore?.getState();
  const activity = live?.agentActivity;
  if (!activity) return { output: "No live actor activity yet." };
  const fingerprints: string[] = [];
  for (const fp of activity.keys()) {
    if (fp.startsWith("carlini-threat-hunt:")) fingerprints.push(fp);
  }
  fingerprints.sort();
  let target: string | undefined;
  const asInt = Number.parseInt(arg, 10);
  if (Number.isFinite(asInt) && asInt >= 1) {
    target = fingerprints[asInt - 1];
  } else {
    target = fingerprints.find((fp) => fp === arg || fp.endsWith(arg));
  }
  if (!target) {
    if (fingerprints.length === 0) return { output: "No carlini-threat-hunt actors are active." };
    return {
      output: `No actor matched "${arg}". Active: ${fingerprints
        .map((fp, i) => `${i + 1}. ${fp}`)
        .join(" · ")}`,
    };
  }
  // Type-narrow: the fingerprints array is filtered down to a single
  // match above, so `target` is guaranteed defined here.
  const focused = target;
  void shellState;
  return {
    shellStateUpdater: (shell) => ({
      ...shell,
      shellView: "actor-detail",
      focusedActor: focused,
    }),
    output: `Drilling into ${focused}.`,
  };
}

/**
 * Bare verb `prompts` from inside `kuzushi/<module>>` — opens the per-module
 * prompts editor view. Pre-computes the audit table and stashes it on
 * `shell.promptsEditor.audit` so the renderer doesn't need a `CopilotCore`.
 */
function handlePromptsListCommand(
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  if (!ctx.focusedModule) {
    return { output: "No focused module. Use /use <module> first." };
  }
  const moduleId = ctx.focusedModule;
  const compact = buildPromptEditorAuditRows(core, opts, shellState.moduleOptions, moduleId);
  return {
    shellStateUpdater: (shell) => ({
      ...shell,
      shellView: "prompts-editor",
      promptsEditor: { ...(shell.promptsEditor ?? {}), audit: compact },
    }),
    output: `Prompts for ${moduleId} — ${compact.length} key${compact.length === 1 ? "" : "s"}.`,
  };
}

/**
 * `/prompt reset <verb>` — delete the override file (if any) and drop the
 * stored option entry. Idempotent: running on an already-default key
 * reports a no-op without erroring.
 */
function handlePromptResetCommand(
  verbArg: string | undefined,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  if (!ctx.focusedModule) {
    return { output: "No focused module. Use /use <module> first." };
  }
  if (!ctx.dataDir) {
    return { output: "No data directory resolved for this shell." };
  }
  const verb = verbArg?.trim();
  if (!verb) {
    return { output: "Usage: prompt reset <name>" };
  }
  const targetResult = resolvePromptTarget(verb, core, opts, ctx, shellState);
  if (!targetResult.ok) return { output: targetResult.output };
  const target = targetResult.target;
  const filePath = path.join(ctx.dataDir, "prompts", target.moduleId, `${target.name}.md`);
  const hadStoredOverride = Object.hasOwn(
    shellState.moduleOptions[target.toolName] ?? {},
    target.promptKey,
  );
  let removed = false;
  try {
    if (existsSync(filePath)) {
      unlinkSync(filePath);
      removed = true;
    }
  } catch (err) {
    return {
      output: `Failed to delete ${filePath}: ${toErrorMessage(err)}`,
    };
  }
  return {
    shellStateUpdater: (shell) => {
      const next = { ...(shell.moduleOptions[target.toolName] ?? {}) };
      delete next[target.promptKey];
      const moduleOptions = { ...shell.moduleOptions };
      if (Object.keys(next).length === 0) delete moduleOptions[target.toolName];
      else moduleOptions[target.toolName] = next;
      const promptsEditor = {
        ...(shell.promptsEditor ?? {}),
        audit: buildPromptEditorAuditRows(core, opts, moduleOptions, target.moduleId),
      };
      if (promptsEditor.lastSaved?.name === target.name) {
        delete promptsEditor.lastSaved;
        delete promptsEditor.lastSavedAt;
      }
      return {
        ...shell,
        moduleOptions,
        promptsEditor,
      };
    },
    output: removed
      ? `Removed override at ${filePath}; ${promptOptionRef(target.toolName, target.promptKey)} reset to default.`
      : hadStoredOverride
        ? `Reset ${promptOptionRef(target.toolName, target.promptKey)} to default (no override file at ${filePath}).`
        : `${promptOptionRef(target.toolName, target.promptKey)} already at default (no override file).`,
  };
}

/**
 * `/prompt diff <verb>` — unified diff between the local override and the
 * compiled-in default. Best-effort: if either side is missing we surface
 * a clear advisory instead of running `git diff`.
 */
function handlePromptDiffCommand(
  verbArg: string | undefined,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  if (!ctx.focusedModule) {
    return { output: "No focused module. Use /use <module> first." };
  }
  if (!ctx.dataDir) {
    return { output: "No data directory resolved for this shell." };
  }
  const verb = verbArg?.trim();
  if (!verb) return { output: "Usage: prompt diff <name>" };
  const targetResult = resolvePromptTarget(verb, core, opts, ctx, shellState);
  if (!targetResult.ok) return { output: targetResult.output };
  const target = targetResult.target;
  const filePath = path.join(ctx.dataDir, "prompts", target.moduleId, `${target.name}.md`);
  if (!existsSync(filePath)) {
    return { output: `No override file at ${filePath} — nothing to diff.` };
  }
  return {
    output: `Override on disk: ${filePath}.\nThe compiled-in default lives in src/modules/${target.moduleId}/. Use \`git diff\` against the upstream tree for a structured diff.`,
  };
}

/**
 * `/prompt show <verb>` — reports the currently effective prompt for the
 * focused tool: its source (file / inline / default), size, and path.
 */
function handlePromptShowCommand(
  verbArg: string | undefined,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  if (!ctx.focusedModule) {
    return { output: "No focused module. Use /use <module> first." };
  }
  const verb = verbArg?.trim();
  if (!verb) {
    return { output: "Usage: /prompt show <name>" };
  }
  const targetResult = resolvePromptTarget(verb, core, opts, ctx, shellState);
  if (!targetResult.ok) return { output: targetResult.output };
  const target = targetResult.target;
  const cwd = opts.target ? path.resolve(opts.target) : process.cwd();
  const stored = shellState.moduleOptions[target.toolName];
  const effective = readEffectivePrompt(target.toolName, target.promptKey, stored, cwd);
  const verbSuffix = promptKeyToVerb(target.promptKey);
  const header = `Prompt for ${target.toolName} (${verbSuffix})`;
  return { output: `${header}\n  ${formatEffectivePromptLine(effective)}` };
}

function handlePromptInlineSetCommand(
  input: string,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const rest = input
    .trim()
    .replace(/^set\s+/i, "")
    .trim();
  const match = /^(\S+)\s+([\s\S]+)$/.exec(rest);
  if (!match) {
    return { output: "Usage: set <name> <inline text or path>" };
  }
  const name = match[1]!;
  const value = stripWrappingQuotes(match[2]!);
  if (!value) {
    return { output: "Usage: set <name> <inline text or path>" };
  }
  const targetResult = resolvePromptTarget(name, core, opts, ctx, shellState);
  if (!targetResult.ok) return { output: targetResult.output };
  const target = targetResult.target;
  return {
    shellStateUpdater: (shell) => {
      const moduleOptions = {
        ...shell.moduleOptions,
        [target.toolName]: {
          ...(shell.moduleOptions[target.toolName] ?? {}),
          [target.promptKey]: value,
        },
      };
      const promptsEditor = {
        ...(shell.promptsEditor ?? {}),
        audit: buildPromptEditorAuditRows(core, opts, moduleOptions, target.moduleId),
      };
      if (promptsEditor.lastSaved?.name === target.name) {
        delete promptsEditor.lastSaved;
        delete promptsEditor.lastSavedAt;
      }
      return {
        ...shell,
        moduleOptions,
        lastUsedTool: target.toolName,
        promptsEditor,
      };
    },
    output: `Set ${target.toolName}.${target.promptKey} inline override (${Buffer.byteLength(value, "utf-8")} bytes).`,
  };
}

/**
 * Lazy DB handle for replay commands. Each call opens (or reuses) a
 * better-sqlite3 connection against `<dataDir>/findings.sqlite3`. The
 * handle is deliberately not cached on ShellContext so `/replay` stays
 * independent of the workspace/DB boot block (which may have been
 * skipped in degraded environments).
 */
async function openRunsDb(ctx: ShellContext, target?: string) {
  if (!ctx.dataDir) return undefined;
  const [dbPath] = await existingRunDbPaths(ctx.dataDir, target);
  if (!dbPath) return undefined;
  const { initDb } = await import("../store.js");
  return initDb(dbPath);
}

function handleShowAliasesCommand(
  args: string[],
  ctx: ShellContext,
  opts?: ShellOptions,
): LocalCommandResult {
  // Prefer live state.summary (post-scan); fall back to the persisted latest
  // run in the DB so `/show aliases` works even immediately after a shell
  // launch with no in-memory summary yet.
  const liveSummary = ctx.uiStore?.getState().summary;
  if (liveSummary) {
    const findingAliases = computeFindingAliases(liveSummary.actionableFindings ?? []);
    const chainAliases = computeChainAliases(liveSummary.exploitChains ?? []);
    const titles: Record<string, string | undefined> = {};
    for (const f of liveSummary.actionableFindings ?? []) {
      titles[f.fingerprint] = f.title ?? f.ruleId;
    }
    for (const c of liveSummary.exploitChains ?? []) {
      titles[c.id] = c.name;
    }
    return {
      output: formatAliasTable(findingAliases, chainAliases, args[0], titles),
    };
  }
  return {
    output: "Loading aliases from the latest persisted run…",
    asyncExecute: async () => {
      const db = await openRunsDb(ctx, opts?.target);
      if (!db) {
        return "No run summary in memory and no runs database found. Start a scan or use /replay <runId> to hydrate.";
      }
      try {
        const { listRuns } = await import("../store.js");
        const { buildSummaryData } = await import("../ui/summary-data.js");
        const run = listRuns(db, { limit: 1 })[0];
        if (!run) return "No persisted runs found. Start a scan first.";
        const repoRoot = opts?.target ? path.resolve(opts.target) : undefined;
        const summary = buildSummaryData(db, run.repo, {
          runId: run.runId,
          ...(repoRoot ? { repoRoot } : {}),
        });
        if (ctx.uiStore) ctx.uiStore.update({ summary });
        const findingAliases = computeFindingAliases(summary.actionableFindings ?? []);
        const chainAliases = computeChainAliases(summary.exploitChains ?? []);
        const titles: Record<string, string | undefined> = {};
        for (const f of summary.actionableFindings ?? []) {
          titles[f.fingerprint] = f.title ?? f.ruleId;
        }
        for (const c of summary.exploitChains ?? []) {
          titles[c.id] = c.name;
        }
        return formatAliasTable(findingAliases, chainAliases, args[0], titles);
      } finally {
        db.close();
      }
    },
  };
}

function handleShowRunsCommand(args: string[], ctx: ShellContext): LocalCommandResult {
  const limitFlagIdx = args.indexOf("--limit");
  const limit =
    limitFlagIdx >= 0 && args[limitFlagIdx + 1]
      ? Math.max(1, Math.min(250, Number.parseInt(args[limitFlagIdx + 1]!, 10) || 25))
      : 25;
  const repoFilter = args.find((a) => !a.startsWith("--") && a !== String(limit));
  return {
    output: "Listing runs…",
    asyncExecute: async () => {
      const db = await openRunsDb(ctx);
      if (!db) {
        return "No runs database found. .kuzushi/findings.sqlite3 is created on first scan.";
      }
      const { listRuns } = await import("../store.js");
      const runs = listRuns(db, { limit, ...(repoFilter ? { repo: repoFilter } : {}) });
      return formatRunsTable(runs, limit);
    },
  };
}

function handleReplayCommand(args: string[], ctx: ShellContext): LocalCommandResult {
  const runId = args[0];
  if (!runId) {
    return { output: "Usage: /replay <runId>  (find IDs with /show runs)" };
  }
  return {
    output: `Loading run ${runId}…`,
    asyncExecute: async () => {
      const db = await openRunsDb(ctx);
      if (!db) return "No runs database found.";
      const { getRun } = await import("../store.js");
      const run = getRun(db, runId);
      if (!run) {
        // Allow prefix match via listRuns so short IDs work.
        const { listRuns } = await import("../store.js");
        const matches = listRuns(db, { limit: 250 }).filter((r) => r.runId.startsWith(runId));
        if (matches.length === 0) return `Unknown runId: ${runId}`;
        if (matches.length > 1) {
          return `Ambiguous runId prefix "${runId}" — matches: ${matches.map((m) => m.runId).join(", ")}`;
        }
        return formatRunReplay(matches[0]!);
      }
      return formatRunReplay(run);
    },
  };
}

function handleTraceCommand(args: string[], ctx: ShellContext): LocalCommandResult {
  const runId = args[0];
  if (!runId) {
    return { output: "Usage: /trace <runId>  (find IDs with /show runs)" };
  }
  if (!ctx.dataDir) {
    return { output: "No data directory resolved for this shell." };
  }
  const dataDir = ctx.dataDir;
  return {
    output: `Reading trace for ${runId}…`,
    asyncExecute: async () => {
      // If the user passed a prefix, resolve it via the DB so trace and
      // replay share the same short-ID semantics.
      let fullRunId = runId;
      const db = await openRunsDb(ctx);
      if (db) {
        const { listRuns } = await import("../store.js");
        const matches = listRuns(db, { limit: 250 }).filter((r) => r.runId.startsWith(runId));
        if (matches.length === 1) fullRunId = matches[0]!.runId;
      }
      const events = readTraceEvents(dataDir, fullRunId);
      return formatRunTrace(fullRunId, events);
    },
  };
}

/**
 * Apply a NL-planner proposal against `shell.moduleOptions` using the same
 * coercion + validation helpers as `handleSetCommand`. Returns a summary
 * string plus a `ShellState` updater the caller merges into its result.
 */
function applyShellPlan(
  plan: ShellPlan,
  core: CopilotCore,
  shellState: ShellState,
): { output: string; updater: (shell: ShellState) => ShellState } {
  const resolved = core.registry.resolveTool(plan.toolName);
  if (!resolved) {
    return {
      output: `Plan references unknown tool: ${plan.toolName}`,
      updater: (shell) => shell,
    };
  }
  const properties = getToolProperties(resolved.tool);

  const applied: Array<{ option: string; value: unknown }> = [];
  const skipped: Array<{ option: string; reason: string }> = [];
  const nextOptions: Record<string, unknown> = {
    ...(shellState.moduleOptions[plan.toolName] ?? {}),
  };

  for (const change of plan.changes) {
    const schema = properties[change.option];
    if (!schema) {
      skipped.push({ option: change.option, reason: "unknown option" });
      continue;
    }
    // The planner returns JSON values directly; coerceOptionValue expects a
    // string. Stringify non-strings so enum/boolean/number paths stay in one
    // validation code path rather than forking by source.
    const rawValue =
      typeof change.proposed === "string" ? change.proposed : JSON.stringify(change.proposed);
    const coerced = coerceOptionValue(rawValue, schema);
    const typeError = validateOptionType(change.option, coerced, schema);
    if (typeError) {
      skipped.push({ option: change.option, reason: typeError });
      continue;
    }
    const enumError = validateOptionValue(change.option, coerced, schema);
    if (enumError) {
      skipped.push({ option: change.option, reason: enumError });
      continue;
    }
    nextOptions[change.option] = coerced;
    applied.push({ option: change.option, value: coerced });
  }

  const appliedLine = applied.length
    ? `Applied ${applied.length} change${applied.length === 1 ? "" : "s"} (source: ${plan.source}):\n` +
      applied.map((a) => `  ${plan.toolName}.${a.option} = ${formatValue(a.value)}`).join("\n")
    : "No changes applied.";
  const skippedLine = skipped.length
    ? `\nSkipped ${skipped.length}: ${skipped.map((s) => `${s.option} (${s.reason})`).join(", ")}`
    : "";

  return {
    output: `${appliedLine}${skippedLine}`,
    updater: (shell) => ({
      ...shell,
      moduleOptions: { ...shell.moduleOptions, [plan.toolName]: nextOptions },
      lastUsedTool: plan.toolName,
    }),
  };
}

function handleSetCommand(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  focusedModule: string | null,
  shellState: ShellState,
): LocalCommandResult {
  if (args.length === 0) {
    return { output: "Usage: /set <key> <value>" };
  }

  // Resolve the tool to apply the option to. Prefer the lastUsedTool when
  // it belongs to the focused module; otherwise fall back to the focused
  // module's default tool. The previous behavior errored with "Use /options
  // <tool> first" even when the operator was clearly inside a focused
  // module — operators never expect to set an option on something other
  // than the module they just entered.
  let activeToolName = shellState.lastUsedTool;
  if (!activeToolName || (focusedModule && !activeToolName.startsWith(`${focusedModule}:`))) {
    if (focusedModule) {
      const fallback = pickDefaultToolName(core, focusedModule);
      if (fallback) {
        activeToolName = fallback;
      }
    }
  }
  if (!activeToolName) {
    return { output: "No active tool selected. Use /options <tool> first." };
  }

  const resolved = core.registry.resolveTool(activeToolName);
  if (!resolved) {
    return { output: formatUnknownToolMessage(activeToolName) };
  }

  let optionKey = args[0] ?? "";
  let rawValue = "";
  const eqIndex = optionKey.indexOf("=");
  if (eqIndex >= 0) {
    rawValue = optionKey.slice(eqIndex + 1);
    optionKey = optionKey.slice(0, eqIndex);
  } else {
    rawValue = args.slice(1).join(" ").trim();
  }

  if (!optionKey || !rawValue) {
    return { output: "Usage: /set <key> <value>" };
  }

  const properties = getEffectiveToolProperties(resolved.tool, opts.config);
  const canonicalOptionKey = findOptionKey(properties, optionKey);
  const schema = canonicalOptionKey ? properties[canonicalOptionKey] : undefined;
  if (!canonicalOptionKey || !schema) {
    return {
      output: `Unknown option for ${activeToolName}: ${optionKey}\nAvailable options: ${formatChoices(Object.keys(properties).sort())}`,
    };
  }

  const coercedValue = coerceOptionValue(rawValue, schema);
  const typeError = validateOptionType(canonicalOptionKey, coercedValue, schema);
  if (typeError) {
    return { output: typeError };
  }
  const enumError = validateOptionValue(canonicalOptionKey, coercedValue, schema);
  if (enumError) {
    return { output: enumError };
  }
  const modelError = validateModelOptionValue(canonicalOptionKey, coercedValue, opts.config);
  if (modelError) {
    return { output: modelError };
  }

  return {
    output: `Set ${activeToolName}.${canonicalOptionKey} = ${formatValue(coercedValue)}`,
    shellStateUpdater: (shell) => {
      const nextModuleOptions = {
        ...shell.moduleOptions,
        [activeToolName]: {
          ...(shell.moduleOptions[activeToolName] ?? {}),
          [canonicalOptionKey]: coercedValue,
        },
      };
      const nextShell = {
        ...shell,
        moduleOptions: nextModuleOptions,
        lastUsedTool: activeToolName,
      };
      if (shell.shellView !== "options" || shell.optionsView?.toolName !== activeToolName) {
        return nextShell;
      }
      const built = buildOptionsViewSlice(core, activeToolName, opts, nextShell);
      return {
        ...nextShell,
        optionsView: built.ok ? built.view : shell.optionsView,
      };
    },
  };
}

const CONFIG_RESTART_KEYS = new Set([
  "agentRuntimeBackend",
  "agentRuntimeConfig",
  "agentModel",
  "busBackend",
  "dbPath",
]);

const CONFIG_SECRET_KEY_PATTERN = /(apiKey|token|secret|password)/i;

function redactConfigSecrets(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactConfigSecrets);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (CONFIG_SECRET_KEY_PATTERN.test(k) && typeof v === "string" && v.length > 0) {
        out[k] = `***redacted*** (len=${v.length})`;
      } else {
        out[k] = redactConfigSecrets(v);
      }
    }
    return out;
  }
  return value;
}

const CONFIG_USAGE = [
  "Usage:",
  "  /config                       Open the interactive config editor (TTY)",
  "  /config show                  Show overrides (grouped, defaults hidden)",
  "  /config show --all            Show full config including defaults",
  "  /config raw                   Print the full effective config as JSON",
  "  /config path                  Show config file paths",
  "  /config get <key>             Get a value (supports dotted paths)",
  "  /config set                   Open the editor focused on the key picker",
  "  /config set <key> <value>     Set a value in the global config",
  "  /config edit [key]            Alias for /config (optionally focused)",
].join("\n");

function maskApiKey(key: string | undefined): string {
  if (!key) return "(unset)";
  if (key.length <= 11) return `${key.slice(0, 3)}…`;
  return `${key.slice(0, 7)}…${key.slice(-4)}`;
}

function formatBackendSlots(
  cfg:
    | {
        claude?: { apiKey?: string; authToken?: string; baseUrl?: string };
        piAi?: { apiKey?: string; authToken?: string; baseUrl?: string };
        codex?: { apiKey?: string; authToken?: string; baseUrl?: string };
      }
    | undefined,
): string[] {
  const out: string[] = [];
  for (const slot of ["claude", "piAi", "codex"] as const) {
    const s = cfg?.[slot];
    if (s && (s.apiKey || s.authToken || s.baseUrl)) {
      out.push(
        `  ${slot.padEnd(6)} apiKey=${maskApiKey(s.apiKey)}  authToken=${maskApiKey(s.authToken)}  baseUrl=${s.baseUrl ?? "(default)"}`,
      );
      continue;
    }
    // No file-based creds — probe env vars before reporting "unset". The
    // claude runtime honors process.env.ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL
    // at subprocess launch, so reporting "unset" when env vars are set is a
    // lie that costs operators $0/0-finding wasted runs.
    const envCreds = probeEnvCredsForSlot(slot);
    if (envCreds) {
      out.push(
        `  ${slot.padEnd(6)} env-only (apiKey=${maskApiKey(envCreds.apiKey)}  authToken=${maskApiKey(envCreds.authToken)}  baseUrl=${envCreds.baseUrl ?? "(default)"})`,
      );
      continue;
    }
    out.push(
      `  ${slot.padEnd(6)} (unset — run /backend ${slot === "piAi" ? "pi-ai" : slot} then /auth)`,
    );
  }
  return out;
}

/**
 * Probe environment variables for backend credentials. Returns null when
 * no env-var credentials are present for the slot. Used by `/backend show`
 * so that operators who set ANTHROPIC_API_KEY in their parent shell don't
 * see a misleading "unset" status.
 */
function probeEnvCredsForSlot(
  slot: "claude" | "piAi" | "codex",
): { apiKey?: string; authToken?: string; baseUrl?: string } | null {
  if (slot === "claude") {
    const apiKey = process.env.ANTHROPIC_API_KEY || process.env.CLAUDE_API_KEY;
    const authToken = process.env.ANTHROPIC_AUTH_TOKEN || process.env.ANTHROPIC_OAUTH_TOKEN;
    const baseUrl = process.env.ANTHROPIC_BASE_URL;
    if (apiKey || authToken || baseUrl) return { apiKey, authToken, baseUrl };
    return null;
  }
  if (slot === "codex") {
    const apiKey = process.env.OPENAI_API_KEY;
    const baseUrl = process.env.OPENAI_BASE_URL;
    if (apiKey || baseUrl) return { apiKey, baseUrl };
    return null;
  }
  // pi-ai is multi-provider. Honor the most common provider env vars so
  // operators see a green light when ANY provider has env-only creds.
  const piAiVars: Array<[string, string?]> = [
    ["ANTHROPIC_API_KEY"],
    ["ANTHROPIC_AUTH_TOKEN"],
    ["ANTHROPIC_OAUTH_TOKEN"],
    ["OPENAI_API_KEY", "OPENAI_BASE_URL"],
    ["GOOGLE_API_KEY"],
    ["GROQ_API_KEY"],
    ["MISTRAL_API_KEY"],
    ["DEEPSEEK_API_KEY"],
  ];
  for (const [keyVar, baseVar] of piAiVars) {
    const apiKey = process.env[keyVar];
    if (apiKey) {
      const baseUrl = baseVar ? process.env[baseVar] : undefined;
      return keyVar === "ANTHROPIC_AUTH_TOKEN" || keyVar === "ANTHROPIC_OAUTH_TOKEN"
        ? { authToken: apiKey, baseUrl }
        : { apiKey, baseUrl };
    }
  }
  return null;
}

/**
 * Levenshtein edit distance — used by `/backend <name>` typo suggestion.
 */
function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  let curr = new Array<number>(b.length + 1);
  for (let i = 1; i <= a.length; i += 1) {
    curr[0] = i;
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(curr[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[b.length];
}

function closestBackend(input: string, candidates: readonly string[]): string | undefined {
  const needle = input.trim().toLowerCase();
  if (!needle) return undefined;
  let best: { name: string; distance: number } | undefined;
  for (const name of candidates) {
    const distance = levenshtein(needle, name.toLowerCase());
    if (!best || distance < best.distance) best = { name, distance };
  }
  if (!best) return undefined;
  // Only suggest when the typo is plausibly the same word: short edits relative
  // to the candidate length. "cluade" → "claude" is distance 2.
  const threshold = Math.max(1, Math.floor(best.name.length / 3));
  return best.distance <= threshold ? best.name : undefined;
}

/**
 * `/cost` — Reports session-to-date cost from the live moduleRun + the
 * persisted `~/.kuzushi/runs/<id>/cost.jsonl` (best-effort). Operators
 * previously had to grep the audit log to know what they'd spent during
 * a long shell session; this surfaces it inline.
 */
function handleCostCommand(opts: ShellOptions, shellState: ShellState): LocalCommandResult {
  return {
    asyncExecute: async () => {
      const lines: string[] = [];
      // Live cost from the current module run (if any)
      const liveCost = shellState.moduleRun?.costUsd ?? 0;
      const liveTool = shellState.moduleRun?.toolName ?? null;
      if (liveTool && (shellState.moduleRun?.status === "running" || liveCost > 0)) {
        const status = shellState.moduleRun?.status ?? "unknown";
        lines.push(`Active run:  ${liveTool}  $${liveCost.toFixed(4)}  (${status})`);
      } else {
        lines.push("Active run:  (none)");
      }

      // Aggregate from per-run summary.json files in the kuzushi runs dir.
      // Best-effort: missing dir / unreadable files are silently ignored.
      try {
        const fs = await import("node:fs/promises");
        const path = await import("node:path");
        const os = await import("node:os");
        const runsDir = path.join(os.homedir(), ".kuzushi", "runs");
        const entries = await fs.readdir(runsDir).catch(() => [] as string[]);
        let totalCost = 0;
        let runsCount = 0;
        const recent: Array<{ runId: string; cost: number; ts: number }> = [];
        for (const runId of entries) {
          try {
            const summaryPath = path.join(runsDir, runId, "summary.json");
            const stat = await fs.stat(summaryPath).catch(() => null);
            if (!stat) continue;
            const text = await fs.readFile(summaryPath, "utf-8");
            const summary = JSON.parse(text) as { totalCost?: number; costUsd?: number };
            const cost =
              typeof summary.totalCost === "number"
                ? summary.totalCost
                : typeof summary.costUsd === "number"
                  ? summary.costUsd
                  : 0;
            totalCost += cost;
            runsCount += 1;
            recent.push({ runId, cost, ts: stat.mtimeMs });
          } catch {
            /* per-run failure — skip */
          }
        }
        recent.sort((a, b) => b.ts - a.ts);
        lines.push(`All runs:    ${runsCount} runs · $${totalCost.toFixed(4)} cumulative`);
        if (recent.length > 0) {
          lines.push("");
          lines.push("Recent runs (last 5):");
          for (const r of recent.slice(0, 5)) {
            const when = new Date(r.ts).toISOString().slice(0, 16).replace("T", " ");
            lines.push(`  ${when}  ${r.runId.slice(0, 12).padEnd(14)} $${r.cost.toFixed(4)}`);
          }
        }
      } catch (error) {
        lines.push(
          `(could not read ~/.kuzushi/runs: ${error instanceof Error ? error.message : "unknown"})`,
        );
      }

      const ws = opts.workspaceName ?? opts.workspace;
      if (ws) lines.push("", `Workspace:   ${ws}`);
      return lines.join("\n");
    },
  };
}

function handleBackendCommand(args: string[], opts: ShellOptions): LocalCommandResult {
  const sub = (args[0] ?? "").toLowerCase();
  const current = opts.config.agentRuntimeBackend ?? "pi-ai";
  // `current` is what the live shell session uses, which may differ from the
  // persisted ~/.kuzushi/config.json value when ensureClaudeShellRuntime has
  // swapped a non-claude backend for the shell. /backend should always compare
  // against the persisted value so that the user can promote the swap.

  if (!sub || sub === "show" || sub === "list") {
    return {
      asyncExecute: async () => {
        const { loadConfig, configPath } = await import("../config.js");
        const persisted = loadConfig().agentRuntimeBackend ?? "pi-ai";
        const lines = [`Shell backend (live): ${current}`, `Persisted backend:    ${persisted}`];
        if (persisted !== current) {
          lines.push("(This shell is using a per-session backend override.)");
        }
        lines.push("", "Credentials (per backend):");
        lines.push(...formatBackendSlots(opts.config.agentRuntimeConfig));
        lines.push(
          "",
          "Available: pi-ai (default, 20+ providers), claude (legacy CC subprocess), codex (Codex SDK)",
          "Usage:",
          "  /backend show           Show current + persisted backend + credentials",
          "  /backend pi-ai          Use pi-ai — multi-provider, in-process (recommended)",
          "  /backend claude         Use Claude Code SDK — Anthropic only, subprocess-per-task",
          "  /backend codex          Use Codex SDK — OpenAI/Codex models",
          "",
          "For provider/model selection, use /provider instead.",
          `Persists to ${configPath()}.`,
        );
        return lines.join("\n");
      },
    };
  }

  if (sub !== "claude" && sub !== "pi-ai" && sub !== "codex") {
    const suggestion = closestBackend(sub, ["claude", "pi-ai", "codex"]);
    const hint = suggestion ? ` Did you mean "${suggestion}"?` : "";
    return {
      output: `Unknown backend "${sub}".${hint} Available: claude, pi-ai, codex. Run /backend show for help.`,
    };
  }

  return {
    asyncExecute: async () => {
      const { applyConfigPatch, configPath, loadConfig } = await import("../config.js");
      const persisted = loadConfig().agentRuntimeBackend ?? "pi-ai";
      if (persisted === sub) {
        return `Persisted backend in ${configPath()} is already "${sub}". No change.`;
      }
      try {
        applyConfigPatch([{ path: "agentRuntimeBackend", value: sub }]);
      } catch (error) {
        const detail = toErrorMessage(error);
        return `Failed to update backend: ${detail}`;
      }
      opts.config.agentRuntimeBackend = sub;
      const note =
        sub === "claude"
          ? "Shell sessions and future `kuzushi scan ...` runs will use claude. Restart the shell to pick up the change."
          : sub === "codex"
            ? "Shell sessions and future `kuzushi scan ...` runs will use codex. Restart the shell to pick up the change."
            : "Shell sessions and future `kuzushi scan ...` runs will use pi-ai. Restart the shell to pick up the change.";
      const lines = [`Backend persisted as "${sub}" in ${configPath()}.`, note];
      // Each backend has its own credential slot now, so switching can't leak
      // creds between backends. Just hint when the new slot is empty so the
      // operator knows to /auth.
      const slot = sub === "pi-ai" ? "piAi" : sub;
      const slotCreds = opts.config.agentRuntimeConfig?.[slot];
      if (!slotCreds || (!slotCreds.apiKey && !slotCreds.baseUrl)) {
        lines.push(
          `No ${slot} credentials configured yet — run /auth to paste an API key (and optional base URL).`,
        );
      }
      return lines.join("\n");
    },
  };
}

// /provider — show or set the default model (provider:model)

/** Common model presets surfaced by `/provider list` for fast switching. */
const PROVIDER_PRESETS = [
  { id: "anthropic:claude-sonnet-4-6", label: "Anthropic — Claude Sonnet (recommended)" },
  { id: "anthropic:claude-opus-4-6", label: "Anthropic — Claude Opus (accurate)" },
  { id: "anthropic:claude-haiku-4-5", label: "Anthropic — Claude Haiku (fast)" },
  { id: "openai:gpt-5-mini", label: "OpenAI — GPT-5 mini" },
  { id: "openai:gpt-5", label: "OpenAI — GPT-5" },
  { id: "google:gemini-2.5-pro", label: "Google — Gemini 2.5 Pro" },
  { id: "google:gemini-2.5-flash", label: "Google — Gemini 2.5 Flash" },
  { id: "groq:llama-3.3-70b-versatile", label: "Groq — Llama 3.3 70B" },
  { id: "openrouter:anthropic/claude-sonnet-4-6", label: "OpenRouter — Sonnet proxy" },
] as const;

function handleProviderCommand(args: string[], opts: ShellOptions): LocalCommandResult {
  const sub = (args[0] ?? "").toLowerCase();

  if (!sub || sub === "show") {
    return {
      output: [
        `Current model: ${opts.config.model ?? "(unset)"}`,
        "",
        "Usage:",
        "  /provider show             Show current model",
        "  /provider list             List preset provider:model combos",
        "  /provider <provider:model> Set model (persists to config.json)",
        "",
        "Credentials for the chosen provider must be set via /auth.",
      ].join("\n"),
    };
  }

  if (sub === "list") {
    const lines = ["Preset provider:model combos:"];
    for (const preset of PROVIDER_PRESETS) {
      const active = preset.id === opts.config.model ? " (active)" : "";
      lines.push(`  ${preset.id.padEnd(44)} ${preset.label}${active}`);
    }
    lines.push("", "Set one with: /provider <id>");
    lines.push("See pi-ai docs for the full list of supported models.");
    return { output: lines.join("\n") };
  }

  // Otherwise treat `sub` as a raw model id (e.g. `/provider openai:gpt-5`)
  const modelId = args.join(" ").trim();
  if (!modelId.includes(":")) {
    return {
      output: `Model id must be "<provider>:<model>" (e.g. "openai:gpt-5-mini"). Got: ${modelId}`,
    };
  }
  return {
    asyncExecute: async () => {
      const { applyConfigPatch, configPath } = await import("../config.js");
      try {
        applyConfigPatch([{ path: "model", value: modelId }]);
      } catch (error) {
        const detail = toErrorMessage(error);
        return `Failed to set model: ${detail}`;
      }
      opts.config.model = modelId;
      const providerId = modelId.split(":")[0];
      return [
        `Model set to "${modelId}" in ${configPath()}.`,
        `Ensure ${providerId} credentials are configured (run /auth if not).`,
      ].join("\n");
    },
  };
}

// /ask — explicit natural-language query, with screen context injected

/**
 * Build the "# Current shell context" block prepended to `/ask` queries so
 * the agent has a deterministic view of what the operator is looking at
 * (focused module, view, last tool, tail of history). Kept compact — it
 * rides on every turn, so bloat = caching churn + token waste.
 */
function buildAskContextPrefix(shellState: ShellState, opts: ShellOptions): string {
  const lines: string[] = ["# Current shell context"];
  if (shellState.focusedModule) lines.push(`- focused module: ${shellState.focusedModule}`);
  if (shellState.shellView) lines.push(`- shell view: ${shellState.shellView}`);
  if (opts.target) lines.push(`- target: ${opts.target}`);
  if (opts.workspace || opts.workspaceName) {
    lines.push(`- workspace: ${opts.workspaceName ?? opts.workspace}`);
  }
  if (shellState.openFindingId) lines.push(`- open finding: ${shellState.openFindingId}`);
  if (shellState.lastUsedTool) lines.push(`- last tool: ${shellState.lastUsedTool}`);

  const snapshot = shellState.contextSnapshot;
  if (snapshot) {
    const snapshotLines: string[] = [];
    if (snapshot.repoContext) snapshotLines.push("repoContext");
    if (snapshot.appModel) snapshotLines.push("appModel");
    if (snapshot.enrichedContext) snapshotLines.push("enrichedContext");
    if (snapshotLines.length > 0) {
      lines.push(`- context snapshot loaded: ${snapshotLines.join(", ")}`);
    }
  }

  const recent = (shellState.history ?? []).slice(-10);
  if (recent.length > 0) {
    lines.push("", "## Recent conversation (last 10 entries)");
    for (const entry of recent) {
      const label = entry.type === "input" ? "user" : entry.type;
      const text = (entry.text ?? "").replaceAll("\n", " ").slice(0, 500);
      lines.push(`- ${label}: ${text}`);
    }
  }

  const artifactRoot = opts.target ? path.resolve(opts.target) : process.cwd();
  const manifest = loadArtifactManifest(artifactRoot);
  lines.push("", "## Loaded artifacts (.kuzushi/)");
  if (manifest.length > 0) {
    for (const line of manifest) lines.push(`- ${line}`);
  } else {
    lines.push("- (none — this is a fresh directory)");
  }

  return lines.join("\n");
}

/**
 * Stat the `.kuzushi/` artifacts the agent might draw on. Pure disk read, no
 * opens — so a corrupt findings DB can't break `/ask`. Returned lines are
 * printed verbatim inside the context block.
 */
function loadArtifactManifest(repoRoot: string): string[] {
  const out: string[] = [];
  const kuzushiDir = path.join(repoRoot, ".kuzushi");
  if (!existsSync(kuzushiDir)) return out;
  const files: Array<{ rel: string; label: string }> = [
    { rel: "scan-context.json", label: "operator-authored scan context" },
    { rel: "threat-model.json", label: "persistent threat model" },
    // context-snapshot.json is what enables /use carlini-threat-hunt (etc.) to pass
    // the appModel prereq check without re-running context:build.
    // Surface it by name so operators understand what's carrying them.
    { rel: "context-snapshot.json", label: "context snapshot (repo + app model)" },
    { rel: "findings.sqlite3", label: "prior findings DB" },
  ];
  for (const { rel, label } of files) {
    const full = path.join(kuzushiDir, rel);
    if (!existsSync(full)) continue;
    try {
      const stat = statSync(full);
      const mtime = stat.mtime.toISOString().slice(0, 10);
      out.push(`${rel} - ${label}; modified ${mtime}`);
    } catch {
      out.push(`${rel} - ${label}`);
    }
  }
  return out;
}

/**
 * Dim trailer appended after each tool summary so operators can see which
 * `.kuzushi/` files were on disk while the tool ran — makes it impossible to
 * dress up cached findings as fresh scan output. Shell-local: no per-tool
 * provenance tracking, just "what was available at the time."
 */
function formatContextTrailer(repoRoot: string): string {
  const manifest = loadArtifactManifest(repoRoot);
  if (manifest.length === 0) return "";
  // Each manifest line starts with the filename followed by " (label, …)" —
  // strip the label for a compact trailer.
  const names = manifest.map((m) => m.split(" ")[0]).join(", ");
  return `  (context: ${names})`;
}

/**
 * Multi-line banner listing `.kuzushi/` artifacts the shell may reuse for
 * `/ask` and context-aware tools. Returned as a single string ready to feed
 * into `appendToHistory` or `console.error`; empty string for fresh dirs so
 * callers can skip rendering entirely.
 */
function formatArtifactBanner(repoRoot: string): string {
  const manifest = loadArtifactManifest(repoRoot);
  if (manifest.length === 0) return "";
  return [
    "Available .kuzushi context:",
    ...manifest.map((m) => `  - ${m}`),
    "Reused by /ask and context-aware modules. Run /context to refresh.",
  ].join("\n");
}

function handleAskCommand(
  args: string[],
  opts: ShellOptions,
  shellState: ShellState,
): LocalCommandResult {
  const question = args.join(" ").trim();
  if (!question) {
    return {
      output: "Usage: /ask <question>  (or prefix any input with ? to route to /ask)",
    };
  }
  const contextPrefix = buildAskContextPrefix(shellState, opts);
  return { askQuestion: `${contextPrefix}\n\n---\n${question}` };
}

/**
 * One-shot migration from project config.json (`agentRuntimeConfig` block,
 * which is silently stripped by UNSAFE_PROJECT_CONFIG_KEYS) to the supported
 * `.kuzushi/credentials.json` location. Reads project config.json (walking up
 * from cwd to the nearest ancestor with `.kuzushi/`), extracts the cred
 * blocks, writes via persistLocalCredentials, and reports.
 */
function handleAuthImportFromConfig(opts: ShellOptions): LocalCommandResult {
  return {
    asyncExecute: async () => {
      const { findProjectConfigRoot, projectConfigPath } = await import("../config/paths.js");
      const { persistLocalCredentials } = await import("../config.js");
      const root = findProjectConfigRoot(opts.target ?? process.cwd());
      if (!root) {
        return "No project config.json found in any ancestor — nothing to import.";
      }
      const cfgPath = projectConfigPath(root);
      let raw: Record<string, unknown>;
      try {
        const fs = await import("node:fs");
        const text = fs.readFileSync(cfgPath, "utf-8");
        raw = JSON.parse(text) as Record<string, unknown>;
      } catch (error) {
        return `Could not read ${cfgPath}: ${toErrorMessage(error)}`;
      }
      const arc = raw.agentRuntimeConfig;
      if (!arc || typeof arc !== "object") {
        return `${cfgPath} has no agentRuntimeConfig block — nothing to import.`;
      }
      const arcRec = arc as Record<string, unknown>;
      const credsToWrite: Record<
        string,
        { apiKey?: string; authToken?: string; baseUrl?: string }
      > = {};
      for (const slot of ["claude", "piAi", "codex"] as const) {
        const slotVal = arcRec[slot];
        if (slotVal && typeof slotVal === "object") {
          const sv = slotVal as Record<string, unknown>;
          const apiKey = typeof sv.apiKey === "string" ? sv.apiKey : undefined;
          const authToken = typeof sv.authToken === "string" ? sv.authToken : undefined;
          const baseUrl = typeof sv.baseUrl === "string" ? sv.baseUrl : undefined;
          if (apiKey || authToken || baseUrl) credsToWrite[slot] = { apiKey, authToken, baseUrl };
        }
      }
      if (
        Object.keys(credsToWrite).length === 0 &&
        (typeof arcRec.apiKey === "string" ||
          typeof arcRec.authToken === "string" ||
          typeof arcRec.baseUrl === "string")
      ) {
        const apiKey = typeof arcRec.apiKey === "string" ? arcRec.apiKey : undefined;
        const authToken = typeof arcRec.authToken === "string" ? arcRec.authToken : undefined;
        const baseUrl = typeof arcRec.baseUrl === "string" ? arcRec.baseUrl : undefined;
        credsToWrite.claude = { apiKey, authToken, baseUrl };
      }
      if (Object.keys(credsToWrite).length === 0) {
        return `${cfgPath} has agentRuntimeConfig but no apiKey/authToken/baseUrl to import.`;
      }
      const writtenTo = persistLocalCredentials(credsToWrite, root);
      const slots = Object.keys(credsToWrite).join(", ");
      return [
        `Imported ${slots} credentials from ${cfgPath}`,
        `→ ${writtenTo}`,
        ".gitignore updated to exclude credentials.json.",
        "",
        "You can now safely delete the agentRuntimeConfig block from project config.json.",
        "Restart the shell to pick up the new credentials.",
      ].join("\n");
    },
  };
}

function handleAuthCommand(
  args: string[],
  opts: ShellOptions,
  ctx: ShellContext,
): LocalCommandResult {
  // /auth import-from-config — migrate creds from project config.json (the
  // unsupported but natural location) to credentials.json (the supported one).
  // Saves operators from the silent-strip footgun documented in
  // sanitizeProjectConfigLayer + the C1 banner.
  const sub = (args[0] ?? "").toLowerCase();
  if (sub === "import-from-config") {
    return handleAuthImportFromConfig(opts);
  }

  // Ink shell: open the modal credential prompt and apply the outcome.
  if (ctx.uiStore) {
    return {
      output: "Opening credential prompt...",
      // Close any in-flight agent session before swapping creds. The next
      // ensureSession() call will rebuild against the new opts.runtime that
      // applyCredentialOutcome → rebuildShellRuntime swaps in.
      resetSession: true,
      asyncExecute: async () => {
        const { runCredentialPrompt } = await import("../ui/setup.js");
        const credentialOutcome = await runCredentialPrompt(ctx.uiStore, "shell");
        const result = await applyCredentialOutcome(credentialOutcome, opts);
        return (
          result.message ?? (result.enabled ? "Copilot enabled." : CREDENTIALS_CANCELLED_MESSAGE)
        );
      },
    };
  }

  // Readline / non-TTY shell: degraded path. The main loop owns stdin via its
  // own readline interface, so we can't safely launch a second one for an
  // interactive prompt mid-session. Point users at the env-var path instead.
  return {
    output: [
      "Run /auth from a TTY shell for the interactive credential prompt.",
      "From the readline shell, set credentials via the environment and restart:",
      "  export OPENAI_API_KEY=sk-...",
      "  export ANTHROPIC_API_KEY=sk-ant-...",
      "  export ANTHROPIC_OAUTH_TOKEN=...",
      "Or edit ~/.kuzushi/config.json / ./.kuzushi/credentials.json for the active backend slot.",
    ].join("\n"),
  };
}

function handleConfigCommand(args: string[], ctx: ShellContext): LocalCommandResult {
  const sub = (args[0] ?? "").toLowerCase();

  // Default + edit: open the interactive editor (or fall back to raw on no TTY).
  if (!sub || sub === "edit") {
    const focusKey = sub === "edit" ? args[1] : undefined;
    return openConfigEditor(ctx, focusKey);
  }

  if (sub === "list" || sub === "show" || sub === "summary" || sub === "--all" || sub === "-a") {
    const showDefaults =
      sub === "--all" || sub === "-a" || args.includes("--all") || args.includes("-a");
    return {
      asyncExecute: async () => {
        const [{ configPath, loadConfig }, { formatConfigText }] = await Promise.all([
          import("../config.js"),
          import("../config/render.js"),
        ]);
        return formatConfigText(loadConfig(), {
          showDefaults,
          configPath: configPath(),
        });
      },
    };
  }

  if (sub === "advanced") {
    return openConfigEditor(ctx, args[1] ?? "multiStrategyMode");
  }

  if (sub === "raw" || sub === "json") {
    return {
      asyncExecute: async () => {
        const { loadConfig, configPath } = await import("../config.js");
        const cfg = loadConfig();
        const redacted = redactConfigSecrets(cfg);
        return `Config: ${configPath()}\n${JSON.stringify(redacted, null, 2)}`;
      },
    };
  }

  if (sub === "path") {
    return {
      asyncExecute: async () => {
        const { configPath } = await import("../config.js");
        return `Global: ${configPath()}`;
      },
    };
  }

  if (sub === "get") {
    const key = args[1];
    if (!key) return { output: "Usage: /config get <key>" };
    return {
      asyncExecute: async () => {
        const { getConfigValue } = await import("../config.js");
        const value = getConfigValue(key);
        if (value === undefined) return `No value set for: ${key}`;
        const redacted = CONFIG_SECRET_KEY_PATTERN.test(key) ? "***redacted***" : value;
        return `${key} = ${JSON.stringify(redacted, null, 2)}`;
      },
    };
  }

  if (sub === "set") {
    const key = args[1];
    const raw = args.slice(2).join(" ").trim();
    // Bare "/config set" → guided picker via the editor.
    if (!key) return openConfigEditor(ctx);
    // "/config set <key>" with no value → focus the editor on that key.
    if (!raw) return openConfigEditor(ctx, key);
    return {
      asyncExecute: async () => {
        const { setConfigValue } = await import("../config.js");
        try {
          setConfigValue(key, raw);
        } catch (err) {
          return `Failed to set ${key}: ${toErrorMessage(err)}`;
        }
        const topLevel = key.split(".")[0] ?? key;
        const needsRestart = CONFIG_RESTART_KEYS.has(topLevel);
        const displayValue = CONFIG_SECRET_KEY_PATTERN.test(key) ? "***redacted***" : raw;
        const note = needsRestart
          ? "\n  Note: restart the shell for this change to take effect."
          : "";
        return `Set ${key} = ${displayValue}${note}`;
      },
    };
  }

  return { output: `Unknown /config subcommand: ${sub}\n${CONFIG_USAGE}` };
}

function openConfigEditor(ctx: ShellContext, focusKey?: string): LocalCommandResult {
  return {
    output: focusKey ? `Opening config editor (focus: ${focusKey})...` : "Opening config editor...",
    asyncExecute: async () => {
      const { runConfigEditor } = await import("../ui/setup.js");
      const outcome = await runConfigEditor(ctx.uiStore, focusKey);
      if (outcome.action === "skipped") {
        const { loadConfig, configPath } = await import("../config.js");
        const cfg = loadConfig();
        const redacted = redactConfigSecrets(cfg);
        return `Config editor needs an interactive TTY. Falling back to raw view.\nConfig: ${configPath()}\n${JSON.stringify(redacted, null, 2)}`;
      }
      if (outcome.action === "cancelled") {
        return "Config editor closed. No changes saved.";
      }
      if (outcome.changed === 0) {
        return "Config editor closed. No changes.";
      }
      const restartNote =
        outcome.restartKeys.length > 0
          ? `\n  Note: restart the shell for ${outcome.restartKeys.join(", ")} to take effect.`
          : "";
      return `Config updated (${outcome.changed} key${outcome.changed === 1 ? "" : "s"}).${restartNote}`;
    },
  };
}

function formatHelp(
  core: CopilotCore,
  opts: ShellOptions,
  options: { includeAdvanced?: boolean } = {},
): string {
  const modules = core.listModules();
  const toolCount = core.registry.allTools().length;

  // Bucket the catalog into ordered CLAUDE.md §12 sections. Entries without
  // a group fall into "session" so nothing silently disappears.
  const groupOrder: ShellCommandGroup[] = [
    "nav",
    "planner",
    "prompt",
    "replay",
    "aliases",
    "config",
    "scope",
    "threats",
    "kb",
    "session",
  ];
  const byGroup = new Map<ShellCommandGroup, ShellCommandEntry[]>();
  for (const entry of SHELL_COMMAND_CATALOG) {
    if (!options.includeAdvanced && !isCommandVisibleInDefaultHelp(entry)) continue;
    const g = entry.group ?? "session";
    const bucket = byGroup.get(g);
    if (bucket) bucket.push(entry);
    else byGroup.set(g, [entry]);
  }

  const groupSections = groupOrder
    .filter((g) => byGroup.has(g))
    .map((g): string[] => [
      `  ${SHELL_COMMAND_GROUP_TITLES[g]}`,
      ...formatCommandRows(
        (byGroup.get(g) ?? []).map(
          (entry) =>
            [
              entry.syntax,
              options.includeAdvanced && commandSurface(entry) !== "core"
                ? `[${commandSurface(entry)}] ${entry.description}`
                : entry.description,
            ] as [string, string],
        ),
      ),
    ]);

  return formatSections([
    [
      "  Kuzushi — security-native AI operating environment",
      options.includeAdvanced
        ? "  Showing core, advanced, and developer commands."
        : "  Showing core workflow commands. Use /help advanced for the full surface.",
      ...formatLabelValueRows([
        ["Modules:", modules.map((module) => module.id).join(", ") || "none"],
        ["Tools:", `${toolCount} available`],
        ["Target:", opts.target ?? null],
        ["Workspace:", opts.workspaceName ?? opts.workspace ?? null],
      ]),
    ],
    ...groupSections,
    [
      "  Tool Shortcuts",
      ...formatCommandRows([
        ["use sast", "Enter a module workflow"],
        ["set target .", "Set a module option"],
        ["run", "Run the focused module's primary tool"],
        ["scan .", "Top-level shortcut for sast:scan"],
      ]),
    ],
    [
      "  Ask The Agent",
      ...formatCommandRows([
        ["/ask What vulns are in this repo?", "Ask with current shell context"],
        ["?Hunt for SSRF chains", "Short form for /ask"],
        ["exit | quit | q", "Bare aliases that always exit"],
        ["/help <verb>", "Expand one command — e.g. /help open"],
      ]),
    ],
  ]);
}

function formatModuleList(
  core: CopilotCore,
  moduleCatalog?: ReadonlyArray<ShellModuleCard>,
): string {
  const modules = core.listModules();
  if (modules.length === 0) return "  No modules loaded.";
  const summaryByModule = new Map(
    (moduleCatalog ?? []).map((card) => [card.id, card.lastRunSummary ?? "never run"]),
  );

  return formatSections(
    modules.map((module) => {
      const tools = core.registry
        .moduleTools(module.id)
        .map((tool) => tool.name.split(":")[1])
        .join(", ");
      return [
        `  ${module.id} [${module.category}]`,
        `  ${formatModuleDescription(module.description)}`,
        ...formatLabelValueRows([
          ["Tools:", tools || "none"],
          ["Last run:", summaryByModule.get(module.id) ?? "never run"],
        ]),
      ];
    }),
  );
}

function formatModuleInfo(core: CopilotCore, id: string): string {
  if (!core.hasModule(id)) {
    const loaded = core.listModules().map((m) => m.id);
    return `  ${formatUnknownModule(id, loaded)}`;
  }

  const module = core.registry.get(id);
  const toolSections = module.tools.map((tool) => [
    `  ${tool.name} ${tool.headless ? "[headless]" : "[interactive]"}`,
    `  ${formatModuleDescription(tool.description)}`,
  ]);

  return formatSections([
    [
      `  ${module.displayName} v${module.version}`,
      ...formatLabelValueRows([
        ["Category:", module.category],
        ["Description:", module.description],
      ]),
    ],
    ...toolSections,
  ]);
}

function formatTools(
  core: CopilotCore,
  focusedModule: string | null,
  opts: { includeHidden?: boolean } = {},
): string {
  const includeHidden = opts.includeHidden === true;
  if (focusedModule) {
    const module = core.registry.get(focusedModule);
    if (module.tools.length === 0) {
      return `  No tools available for ${focusedModule}.`;
    }
    const visible = includeHidden ? module.tools : module.tools.filter((t) => t.hidden !== true);
    const hiddenCount = module.tools.length - visible.length;
    if (visible.length === 0 && hiddenCount > 0) {
      return `  All ${hiddenCount} tools on ${focusedModule} are advanced pipeline steps. Run \`/tools --all\` to list them.`;
    }

    const sections: string[][] = [
      [
        `  ${module.displayName}`,
        ...formatCommandRows(
          visible.map((tool) => [
            toolActionName(tool.name),
            formatModuleDescription(tool.description),
          ]),
        ),
      ],
    ];
    if (hiddenCount > 0) {
      sections.push([
        `  + ${hiddenCount} advanced pipeline step${hiddenCount === 1 ? "" : "s"} hidden (run \`/tools --all\` to list)`,
      ]);
    }
    return formatSections(sections);
  }

  const tools = core.registry.allTools();
  const visibleTools = includeHidden ? tools : tools.filter(({ tool }) => tool.hidden !== true);
  if (visibleTools.length === 0) {
    return tools.length === 0
      ? "  No tools available."
      : "  No default tools. Run `/tools --all` to list advanced pipeline steps.";
  }
  const hiddenCount = tools.length - visibleTools.length;

  const sections: string[][] = [
    [
      "  Available Tools",
      ...formatCommandRows(
        visibleTools.map(({ tool }) => [tool.name, formatModuleDescription(tool.description)]),
      ),
    ],
  ];
  if (hiddenCount > 0) {
    sections.push([
      `  + ${hiddenCount} advanced pipeline step${hiddenCount === 1 ? "" : "s"} hidden (run \`/tools --all\` to list)`,
    ]);
  }
  return formatSections(sections);
}

/**
 * Welcome message shown when the shell starts.
 */
export function formatWelcome(core: CopilotCore, opts: ShellOptions): string {
  const modules = core.listModules();
  const toolCount = core.registry.allTools().length;

  return formatSections([
    [
      "  Kuzushi",
      "  security-native AI operating environment",
      ...formatLabelValueRows([
        ["Modules:", modules.map((module) => module.id).join(", ") || "none"],
        ["Tools:", `${toolCount} available`],
        ["Target:", opts.target ?? null],
        ["Workspace:", opts.workspaceName ?? opts.workspace ?? null],
      ]),
      '  Type "modules" to choose a workflow, or "/ask <question>" for agent chat.',
    ],
  ]);
}

export const __shellInternals = {
  buildSeedMapFromSnapshot,
  buildShellPrompt,
  capShellHistory,
  classifyShellInput,
  createShellSession,
  extractAssistantText,
  extractHuntStats,
  extractToolUseActivities,
  extractToolUseHeaders,
  finalizeAssistantText,
  formatHuntSummaryLine,
  isHuntClassTool,
  looksLikeSubagentToolLine,
  looksLikeSubagentStartLine,
  summarizeInput,
  renderToolInputHint,
  patchHistoryEntry,
  pushLiveActivity,
  finalizeRunningToolCalls,
  pushToolActivity,
  pushToolPhase,
  formatHelp,
  formatModuleInfo,
  formatModuleList,
  formatOptions,
  formatTools,
  formatArtifactBanner,
  formatContextTrailer,
  formatWelcome,
  appendStoryEvent,
  appendProgressEvent,
  applyImplicitShellTarget,
  applyStoryEventToShell,
  applyCredentialOutcome,
  beginShellTurn,
  settleAbortedShellTurn,
  ensureClaudeShellRuntime,
  hasActiveShellCredentials,
  hydrateShellArtifacts,
  handleLocalCommand: routeInput,
  handleSlashCommand,
  handleStoryCommand,
  inferWorkspaceNameFromTarget,
  isTaskStoryNavigationInput,
  shouldRouteShellInputBeforeDispatcher,
  reconcileShellView,
  reconcileShellViewAfterFocusChange,
  reconcileShellViewAfterPlainOutput,
  loadArtifactManifest,
  loadShellCommandHistory,
  rebuildShellRuntime,
  resolveDirectToolDispatch,
  saveShellCommandHistory,
  shouldAppendSeparateBodyOutput,
  parseSeverityCounts,
};
