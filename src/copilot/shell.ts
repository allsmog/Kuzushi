/**
 * Interactive copilot shell — the default `kuzushi` experience.
 *
 * The shell is module-forward: operators choose a module, set options,
 * and run tools through the dispatcher. Agent chat is explicit via /ask
 * so command execution stays predictable.
 */

import {
  appendFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";
import { killAllClaudeSubprocesses } from "../agent-runtime/claude.js";
import { clampHint, summarizeInput } from "../agent-runtime/tool-summary.js";
import type { AgentQueryOptions, AgentRuntime, AgentSession } from "../agent-runtime/types.js";
import { createBus } from "../bus/index.js";
import type { MessageBus } from "../bus/types.js";
import { JobManager } from "../jobs/manager.js";
import { formatContextSummary } from "../modules/core-sast.js";
import type { ModuleInfo, ModuleTool } from "../modules/types.js";
import { SessionManager } from "../sessions/manager.js";
import type { KuzushiConfig } from "../types.js";
import { formatUnknownModule, formatUnknownTool, formatUnknownVerb } from "../ui/error-format.js";
import { formatDuration } from "../ui/format.js";
import type {
  ContextSnapshot,
  ShellHistoryEntry,
  ShellModuleCard,
  ShellState,
  ShellView,
  ToolActivityLine,
  TuneSnapshot,
  UIStore,
} from "../ui/state.js";
import { initContextBuildState } from "../ui/state.js";
import {
  appendCuratedStoryEvent,
  appendStoryTail,
  createShellStoryEvent,
  formatStoryEventPlain,
  type ShellStoryEvent,
  type ShellStoryEventDraft,
  shouldPersistStoryEvent,
} from "../ui/task-story.js";
import { CopilotCore } from "./core.js";
import { resolveTool } from "./dispatch/resolve-tool.js";
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
  promptKeyToVerb,
  readEffectivePrompt,
  readPromptAudit,
  verbToPromptKey,
} from "./prompt-edit.js";
import { listRecipes, resolveRecipePath } from "./recipes.js";
import { openRepl as openDevRepl } from "./repl.js";
import { formatRunReplay, formatRunsTable, formatRunTrace, readTraceEvents } from "./replay.js";
import { loadAndRunResource, saveResourceScript } from "./resource.js";
import { parseToolArgs } from "./run.js";
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
  "Copilot disabled — no Anthropic credentials. Run /auth to set them, export ANTHROPIC_API_KEY, or drop a key in ./.kuzushi/credentials.json.";
const CREDENTIALS_CANCELLED_MESSAGE =
  "Copilot disabled. Run /auth to enable it later, set ANTHROPIC_API_KEY, or save a key to ./.kuzushi/credentials.json.";
const CANCELLED_TOOL_MESSAGE = "Cancelled active operation.";
const CANCELLED_AGENT_MESSAGE = "Cancelled active request.";

/** Tools that require a ContextSnapshot before they can execute from the shell. */
const CONTEXT_REQUIRED_TOOLS = new Set([
  // Legacy sast:* names (resolved via registry alias).
  "sast:threat-hunt",
  "sast:taint-iris",
  // New sub-module names.
  "threat-hunt:run",
  "taint-iris:hunt",
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
 * downstream consumers (`extractActorsWithThreats` in threat-hunt,
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
 * `findings: []` for threat-model-randori is safe — threat-hunt only
 * reads `.document`, and no other task reads the findings array from
 * the threat-model output (those findings flow separately via
 * `taskOutputs["threat-model-randori"].findings` into the report
 * phase, which isn't reconstructed from the snapshot).
 */
function buildSeedMapFromSnapshot(snapshot: ContextSnapshot): Map<string, unknown> {
  const seed = new Map<string, unknown>();
  if (snapshot.repoContext || snapshot.fileIndex) {
    seed.set("context-gatherer", {
      repoContext: snapshot.repoContext,
      fileIndex: snapshot.fileIndex,
    });
  }
  if (snapshot.enrichedContext) seed.set("context-enricher", snapshot.enrichedContext);
  if (snapshot.appModel) seed.set("app-model-build", snapshot.appModel);
  if (snapshot.threatModel)
    seed.set("threat-model-randori", { document: snapshot.threatModel, findings: [] });
  if (snapshot.scenarios) seed.set("threat-scenario-build", { scenarios: snapshot.scenarios });
  return seed;
}

export interface ShellOptions {
  config: KuzushiConfig;
  runtime: AgentRuntime;
  workspace?: string;
  modules?: string[];
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
}

interface AsyncExecutionResult {
  output: string;
  ok?: boolean;
  costUsd?: number;
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
): { shellView: ShellView; label: string } | undefined {
  switch (sub) {
    case "dfd":
    case "1":
      return { shellView: "threat-dfd", label: "data flow diagram" };
    case "stride":
    case "2":
      return { shellView: "threat-stride", label: "STRIDE matrix" };
    case "stories":
    case "3":
      return { shellView: "threat-stories", label: "attacker stories" };
    case "scope":
    case "4":
      return { shellView: "threat-scope", label: "scope & criticality" };
    case "summary":
    case "5":
      return { shellView: "threat-summary", label: "threat summary" };
    default:
      return undefined;
  }
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
    `${moduleId}:exploit`,
    `${moduleId}:audit`,
  ];
  for (const name of preferred) {
    const t = mod.tools.find((x) => x.name === name);
    if (t) return t.name;
  }
  const headless = mod.tools.find((t) => t.headless);
  return (headless ?? mod.tools[0])?.name;
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

/**
 * Transform `core.listModules()` into the flat struct the v2 ModuleCatalog /
 * ModuleHome screens render from. Keeping this here (rather than inside the
 * UI layer) so the UI never has to import anything from `src/modules/`.
 */
export function buildModuleCatalog(
  modules: ReadonlyArray<ModuleInfo>,
  core: CopilotCore,
): ShellModuleCard[] {
  return modules.map((mod) => {
    const instance = core.registry.has(mod.id) ? core.registry.get(mod.id) : undefined;
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
        }))
      : undefined;
    return {
      id: mod.id,
      displayName: mod.displayName,
      category: mod.category,
      description: mod.description,
      rank: mod.rank,
      toolCount: mod.toolCount,
      // External packages surface later via a loader flag; default false here.
      external: false,
      toolSummaries,
    };
  });
}

function normalizeAsyncExecutionResult(value: string | AsyncExecutionResult): AsyncExecutionResult {
  return typeof value === "string" ? { output: value } : value;
}

function moduleIdFromToolName(toolName: string): string | null {
  const [moduleId] = toolName.split(":");
  return moduleId && moduleId.length > 0 ? moduleId : null;
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
  try {
    const { ClaudeAgentRuntime } = await import("../agent-runtime/claude.js");
    const { LoggingAgentRuntime } = await import("../agent-runtime/logging-runtime.js");
    // Mark the live config so subsequent calls (and other code that checks the
    // backend) treat the shell as running on claude. The user's persisted
    // global config is untouched — switch is per-process unless they /backend.
    opts.config.agentRuntimeBackend = "claude";
    const { resolveActiveCredentials } = await import("../config.js");
    const active = resolveActiveCredentials(opts.config);
    const creds = Object.keys(active).length > 0 ? active : undefined;
    opts.runtime = new LoggingAgentRuntime(new ClaudeAgentRuntime(creds));
    const base = `Note: agent backend "${backend}" does not support interactive sessions. Using "claude" for this shell (your scan backend is unchanged). Run /backend claude to make this the default.`;
    const hint = !creds
      ? "\nNo claude credentials configured yet — run /auth to paste an Anthropic key."
      : "";
    const message = base + hint;
    if (store) {
      appendToHistory(store, { type: "output", text: message, timestamp: Date.now() });
    } else {
      process.stderr.write(`${message}\n`);
    }
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    const message = `Failed to swap in claude runtime for shell: ${detail}`;
    if (store) {
      appendToHistory(store, { type: "error", text: message, timestamp: Date.now() });
    } else {
      process.stderr.write(`${message}\n`);
    }
  }
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
 * Rebuild `opts.runtime` so it picks up the latest config + env. The Anthropic
 * SDK client is constructed once in ClaudeAgentRuntime's constructor with the
 * apiKey/baseURL captured at that moment — without this rebuild, credentials
 * supplied later via /auth never reach the SDK.
 */
async function rebuildShellRuntime(opts: ShellOptions): Promise<void> {
  const { ClaudeAgentRuntime } = await import("../agent-runtime/claude.js");
  const { LoggingAgentRuntime } = await import("../agent-runtime/logging-runtime.js");
  const { resolveActiveCredentials } = await import("../config.js");
  const active = resolveActiveCredentials(opts.config);
  const creds = Object.keys(active).length > 0 ? active : undefined;
  opts.runtime = new LoggingAgentRuntime(new ClaudeAgentRuntime(creds));
}

/** Merge `patch` into the active backend's slot in agentRuntimeConfig. */
function mergeIntoActiveSlot(
  opts: ShellOptions,
  patch: { apiKey?: string; baseUrl?: string },
): void {
  const backend = opts.config.agentRuntimeBackend ?? "pi-ai";
  const slot = backend === "pi-ai" ? "piAi" : "claude";
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
      const detail = error instanceof Error ? error.message : String(error);
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
    const detail = error instanceof Error ? error.message : String(error);
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

function parseCommand(input: string): { cmd: string; args: string[] } {
  const [cmd = "", ...args] = input.trim().split(/\s+/);
  return { cmd, args };
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

interface StoryAppendOptions {
  persistHistory?: boolean;
  liveOnly?: boolean;
}

function applyStoryEventToShell(
  shell: ShellState,
  event: ShellStoryEvent,
  options: StoryAppendOptions = {},
): ShellState {
  const activeRunIds =
    event.runId && !shell.taskStory?.activeRunIds.includes(event.runId)
      ? [...(shell.taskStory?.activeRunIds ?? []), event.runId]
      : (shell.taskStory?.activeRunIds ?? []);
  const nextStory = {
    activeTurnId: event.turnId ?? shell.taskStory?.activeTurnId,
    activeRunIds,
    startedAt: shell.taskStory?.startedAt ?? event.timestamp,
    endedAt:
      event.status === "ok" || event.status === "fail" || event.status === "aborted"
        ? event.timestamp
        : shell.taskStory?.endedAt,
    abortStatus:
      event.status === "aborted"
        ? ("aborted" as const)
        : (shell.taskStory?.abortStatus ?? ("idle" as const)),
    abortReason: shell.taskStory?.abortReason,
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
      };
    });
    return mutated ? { ...shell, history: next } : shell;
  });
}

/**
 * Push a short activity line onto a running tool-call's `liveActivities`
 * tail (newest at index 0, max 5). Silently no-ops when the id isn't a
 * running tool-call.
 *
 * Cap bumped from 3 → 5 in Phase 15 so subprocess stdout preview (via
 * `ctx.reportOutput`) has room to show several streaming lines without
 * starving `task:activity` labels.
 */
const LIVE_ACTIVITY_CAP = 5;
const LIVE_ACTIVITY_TEXT_CAP = 80;
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
    const nextActivities = [
      { id: `la-${Date.now()}-${liveActivitySeq++}`, text: trimmed },
      ...prev,
    ].slice(0, LIVE_ACTIVITY_CAP);
    const next = shell.history.slice();
    next[idx] = { ...entry, liveActivities: nextActivities };
    return { ...shell, history: next };
  });
}

/**
 * Tool names whose completion drains `state.lastHuntSnapshot` into a
 * `hunt-post-mortem` scrollback block. Currently just threat-hunt:run;
 * add other hunt-class tools here when they adopt the per-actor
 * `reportAgentActivity` + `done:true` pattern.
 */
const HUNT_CLASS_TOOLS = new Set(["threat-hunt:run"]);

function isHuntClassTool(toolName: string): boolean {
  return HUNT_CLASS_TOOLS.has(toolName);
}

interface HuntStats {
  findingsCount: number;
  costUsd: number;
}

/**
 * Read `totalFindings` + `totalCostUsd` off a hunt tool's `ToolResult.data`.
 * `runSingleTaskPipeline` populates these under `data.stats`; the unknown
 * cast is guarded by runtime shape checks so a shape drift produces zeros
 * rather than a crash.
 */
function extractHuntStats(result: { data?: unknown }): HuntStats {
  const stats = (result.data as { stats?: { totalFindings?: unknown; totalCostUsd?: unknown } })
    ?.stats;
  const findingsCount =
    typeof stats?.totalFindings === "number" && Number.isFinite(stats.totalFindings)
      ? stats.totalFindings
      : 0;
  const costUsd =
    typeof stats?.totalCostUsd === "number" && Number.isFinite(stats.totalCostUsd)
      ? stats.totalCostUsd
      : 0;
  return { findingsCount, costUsd };
}

function formatHuntSummaryLine(actorCount: number, findingsCount: number, costUsd: number): string {
  const actorsLabel = `${actorCount} actor${actorCount === 1 ? "" : "s"}`;
  const findingsLabel = `${findingsCount} finding${findingsCount === 1 ? "" : "s"}`;
  const costLabel = `$${costUsd.toFixed(2)}`;
  return `${actorsLabel} · ${findingsLabel} · ${costLabel}`;
}

function beginShellTurn(
  store: UIStore,
  input: string,
  focusedModule: string | null,
  turnId: string,
  options: { preserveTaskStory?: boolean } = {},
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
    processing: true,
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

function setAbortHandler(store: UIStore, onAbort?: () => void): void {
  updateShell(store, (shell) => ({
    ...shell,
    onAbort,
  }));
}

function markAbortRequested(store: UIStore, reason: string): void {
  const now = Date.now();
  updateShell(store, (shell) => ({
    ...shell,
    taskStory: {
      activeTurnId: shell.taskStory?.activeTurnId,
      activeRunIds: shell.taskStory?.activeRunIds ?? [],
      startedAt: shell.taskStory?.startedAt ?? now,
      events: shell.taskStory?.events ?? [],
      abortStatus: "aborting",
      abortReason: reason,
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
  appendStoryEvent(store, {
    kind: "result",
    status: "aborted",
    importance: "primary",
    message: "Interrupted by operator",
    detail: reason,
    durable: true,
  });
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
 * driver.handle / agent query) closes the window. Stock Ink doesn't do
 * this; Claude Code's custom Ink does (see
 * yasasbanukaofficial/claude-code/src/ink/components/App.tsx rawModeEnabledCount).
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
  if (stdin.isRaw) return;
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
    (currentView === "module" ||
      currentView === "findings" ||
      currentView === "finding" ||
      currentView === "tune")
  ) {
    return "catalog";
  }
  return currentView;
}

function syncShellState(store: UIStore, opts: ShellOptions, focusedModule: string | null): void {
  updateShell(store, (shell) => ({
    ...shell,
    focusedModule,
    shellView: reconcileShellView(shell.shellView, focusedModule),
    target: opts.target ?? null,
    workspace: opts.workspace ?? null,
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
      },
    };
  });
}

const PHASE_COUNT_RE = /\((\d+)\s*\/\s*(\d+)\)/;

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

function appendProgressEvent(
  store: UIStore,
  event: {
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
  },
): void {
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
            const nextActivities = [
              { id: `la-${now}-${liveActivitySeq++}`, text: trimmedLiveActivity },
              ...prev,
            ].slice(0, LIVE_ACTIVITY_CAP);
            const nextHistory = nextShell.history.slice();
            nextHistory[idx] = { ...entry, liveActivities: nextActivities };
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

function clearTransientShellState(store: UIStore): void {
  updateShell(store, (shell) => ({
    ...shell,
    currentTool: undefined,
    pendingAssistantText: undefined,
    onAbort: undefined,
    llmHeartbeat: undefined,
  }));
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

    // If `-D` has persisted a default workspace from a prior shell and the
    // current launch didn't pass `--workspace`, honor it.
    if (!opts.workspace) {
      const defaultFile = path.join(homedir(), ".kuzushi", "default-workspace");
      if (existsSync(defaultFile)) {
        const name = readFileSync(defaultFile, "utf8").trim();
        if (name) opts.workspace = name;
      }
    }

    if (opts.workspace) {
      const ws = workspaceManager.getOrCreate(opts.workspace, opts.target ? [opts.target] : []);
      workspaceManager.touchAccessed(ws.id);
      opts.workspace = ws.id;
      if (opts.target) workspaceManager.addTarget(ws.id, opts.target);
      loadedSnapshot = workspaceManager.loadLatestSnapshot(ws.id);
    }
  } catch {
    // Workspace persistence is optional — degrade gracefully
  }

  // No-workspace fallback: if the target repo has a prior on-disk
  // `<target>/.kuzushi/context-snapshot.json` from an earlier
  // `context:build` run, auto-load it so dependent modules
  // (threat-hunt, agentic-sast, taint-iris) find their appModel /
  // threatModel prerequisites without the operator having to re-run
  // context:build on every session.
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
  });

  await core.init();

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

// ---------------------------------------------------------------------------
// Ink-powered shell (TTY) — conversation stream rendered through React
// ---------------------------------------------------------------------------

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
   * Epoch ms the most recent tool/agent abort fired. The SIGINT fallback
   * consults this to distinguish a "real" idle-prompt Ctrl+C (operator
   * intent: exit) from a "duplicate" SIGINT forwarded milliseconds after an
   * abort completed (pnpm/tsx / terminal-driver double-delivery). Without
   * this, the second SIGINT takes the idle branch and exits the shell with
   * code 130 even though the operator only pressed Ctrl+C once.
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
  // task runIds (fresh UUIDs from `buildTaskContext`), so legitimate
  // progress still flows. Cap the blacklist FIFO to bound memory over
  // a long shell session.
  const seenRunIdsThisTurn = new Set<string>();
  const abortedRunIds = new Set<string>();
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

  // ---------------------------------------------------------------------------
  // msfconsole-style CommandDispatcher — first-pass router for help / use /
  // set / setg / unset / show / info / search / history / resource / makerc /
  // banner / exit. Unknown commands fall through to routeInput (second pass)
  // and ultimately the LLM agent (third pass).
  // ---------------------------------------------------------------------------
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

  const runToolFromDispatcher = async (
    tool: ModuleTool,
    input: Record<string, unknown>,
    signal?: AbortSignal,
    datastore?: Datastore,
  ) => {
    const snapshot = store.getState().shell?.contextSnapshot ?? null;
    const seedTaskOutputs = snapshot ? buildSeedMapFromSnapshot(snapshot) : undefined;
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
    // Emit the cc-repo-style `⏺ tool(hint)` header once, up front. The
    // scrollback is now the primary progress surface; `⎿  …` progress lines
    // will accumulate beneath it as `task:activity` / `task:phase-progress`
    // events arrive (see bus subscriptions near `startShell`). The entry
    // has a stable `id` so the finally-block can flip its status on
    // resolution (cyan `⏺` → green / red / dim) without appending a
    // duplicate completion line.
    const inputDisplay = renderToolInputHint(tool, input);
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
    appendToHistory(store, {
      type: "tool-call",
      id: historyEntryId,
      tool: tool.name,
      ...(displayName ? { displayName } : {}),
      ...(inputDisplay ? { inputHint: inputDisplay } : {}),
      status: "running",
      text: headerText,
      timestamp: Date.now(),
      storyEvent: startStory,
    });
    updateShell(store, (shell) =>
      applyStoryEventToShell(shell, startStory, { persistHistory: false }),
    );
    // Seed `currentTool` so ToolRunningStatus has something to render the
    // moment the dispatcher kicks off a direct `run` — otherwise the
    // `task:activity` events that fire during the tool would hit an empty
    // slot and be dropped.
    const startedAt = Date.now();
    updateShell(store, (shell) => ({
      ...shell,
      currentTool: {
        name: tool.name,
        startedAt,
        lastEventAt: startedAt,
        historyEntryId,
        ...(displayName ? { displayName } : {}),
        ...(turnId ? { turnId } : {}),
        storyTail: [startStory],
      },
    }));
    let ok = false;
    let aborted = false;
    let finalResult: Awaited<ReturnType<CopilotCore["executeTool"]>> | undefined;
    try {
      const result = await core.executeTool(tool.name, input, execOpts);
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
      });
      updateShell(store, (shell) => ({
        ...shell,
        currentTool: undefined,
        lastUsedTool: tool.name,
        moduleCatalog: applyModuleRunTelemetry(
          shell.moduleCatalog,
          tool.name,
          status,
          status === "ok" ? finalResult?.costUsd : undefined,
        ),
      }));
      // Hunt post-mortem — after threat-hunt (and future hunt-class tools
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
            text: formatHuntSummaryLine(perActor.length, stats.findingsCount, stats.costUsd),
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
      if (abortedRunIds.has(runId)) return;
      if (activeAbortRequested || store.getState().shell?.processing !== true) return;
      seenRunIdsThisTurn.add(runId);
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
    if (abortedRunIds.has(runId)) return;
    if (activeAbortRequested || store.getState().shell?.processing !== true) return;
    seenRunIdsThisTurn.add(runId);
    const description = event.payload.description;
    const isSubagentTool = looksLikeSubagentToolLine(description);
    // All sub-agent tool-echo lines (bare tool-call-start "Read", assistant
    // `tool_use` hint "Read · path", AND the eventual tool-summary
    // "Read path (42 lines)") are kept out of permanent scrollback — the
    // summary now attaches to the parent `⏺` entry as its `resultOutput`
    // (see the `case "tool-summary"` handler below), and the running
    // `liveActivities` tail still ticks on every sub-step via the
    // appendProgressEvent calls this subscriber makes regardless of
    // `skipHistory`. Result: one row per tool call instead of three.
    const skipHistory = isSubagentTool;
    appendProgressEvent(store, {
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
    if (abortedRunIds.has(runId)) return;
    if (activeAbortRequested || store.getState().shell?.processing !== true) return;
    seenRunIdsThisTurn.add(runId);
    const entryId = store.getState().shell?.currentTool?.historyEntryId;
    if (entryId) pushLiveActivity(store, entryId, event.payload.line);
    appendStoryEvent(
      store,
      {
        kind: "activity",
        status: "running",
        importance: "debug",
        message: event.payload.line,
        source: "task:output",
        runId,
        ...(activeTurnId ? { turnId: activeTurnId } : {}),
      },
      { persistHistory: false, liveOnly: true },
    );
  });

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
      return shell ? { contextSnapshot: shell.contextSnapshot } : undefined;
    },
    // Workspace-DB finding count for triage/verify/patch requires. Optional —
    // when no workspace is active the count defaults to 0 and the preflight
    // fires the expected "run a scanner first" hint.
    getFindingCount: () => {
      const wsId = opts.workspace;
      if (!wsId || !workspaceManager) return 0;
      return workspaceManager.vulns.listForWorkspace(wsId).length;
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
    syncShellState(store, opts, shellCtx.focusedModule);
  };

  const closeSession = async (): Promise<void> => {
    const currentSession = session;
    session = undefined;
    sessionCwd = undefined;
    await closeShellSession(currentSession);
  };

  const lazyPromptForCredentials = async (): Promise<boolean> => {
    const isClaudeBackend = (opts.config.agentRuntimeBackend ?? "pi-ai") === "claude";
    if (!isClaudeBackend) return false;
    const { hasAnthropicCredentials, runCredentialPrompt } = await import("../ui/setup.js");
    const { resolveActiveCredentials } = await import("../config.js");
    if (hasAnthropicCredentials(resolveActiveCredentials(opts.config).apiKey)) {
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
      finalizeRunningToolCalls(store, "abort", CANCELLED_TOOL_MESSAGE);
      markAbortSettled(store, "tool execution");
      clearTransientShellState(store);
      setProcessing(store, false);
      // Restore raw mode in case a Claude SDK subprocess disabled it. Must
      // happen before the next keystroke or the terminal echoes chars
      // below Ink's frame and Ctrl+C keeps missing `useInput`.
      ensureRawMode();
      // Stamp the abort time so a duplicate SIGINT arriving milliseconds
      // later (e.g. from pnpm/tsx signal forwarding) doesn't fall through
      // the idle branch of `shellSigintHandler` and exit the shell.
      lastAbortFiredAt = Date.now();
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
      finalizeRunningToolCalls(store, "abort", CANCELLED_AGENT_MESSAGE);
      markAbortSettled(store, "agent request");
      clearTransientShellState(store);
      setProcessing(store, false);
      // Restore raw mode — the session's subprocess almost certainly
      // disabled it. Without this the next keystroke echoes below Ink.
      ensureRawMode();
      // Stamp the abort time (see tool-abort path above) so the next
      // spurious SIGINT — commonly a duplicate forwarded by pnpm/tsx —
      // doesn't exit the shell by falling through the idle branch.
      lastAbortFiredAt = Date.now();
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
    beginShellTurn(store, input, shellCtx.focusedModule, activeTurnId, { preserveTaskStory });
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

    // First pass: msfconsole-style dispatcher. If a registered command matches,
    // we render its output and skip the legacy router + LLM agent.
    const controller = new AbortController();
    setToolAbort(controller);
    let dispatched: Awaited<ReturnType<typeof driver.handle>>;
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
        text: err instanceof Error ? err.message : String(err),
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
    if (dispatched.matched) {
      if (dispatched.push || dispatched.pop) syncFocusFromDispatcher();
      if (dispatched.output) {
        appendToHistory(store, {
          type: "output",
          text: dispatched.output,
          timestamp: Date.now(),
        });
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
    finishActiveAction();

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
    if (localResult.shellStateUpdater) {
      updateShell(store, localResult.shellStateUpdater);
    }
    syncShellState(store, opts, shellCtx.focusedModule);

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
        if (execResult.output) {
          appendToHistory(store, {
            type: "output",
            text: execResult.output,
            timestamp: Date.now(),
          });
        }
      } catch (error) {
        const wasAborted = controller.signal.aborted;
        finishActiveAction();
        if (localResult.executedToolName) {
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
            detail: error instanceof Error ? error.message : String(error),
            source: localResult.executedToolName,
            ...(activeTurnId ? { turnId: activeTurnId } : {}),
            durable: true,
          });
        }
        appendToHistory(store, {
          type: "error",
          text: error instanceof Error ? error.message : String(error),
          timestamp: Date.now(),
        });
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
      clearTransientShellState(store);
      setProcessing(store, false);
      return;
    }

    const agentInput = localResult.askQuestion;
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
      const message = error instanceof Error ? error.message : String(error);
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

  store.update({
    mode: "shell",
    shell: {
      modules: modules.map((module) => module.id),
      moduleCatalog: buildModuleCatalog(modules, core),
      tools: tools.map(({ tool }) => tool.name),
      focusedModule: null,
      shellView: "catalog",
      openFindingId: null,
      target: opts.target ?? null,
      workspace: opts.workspace ?? null,
      tuneSnapshot: buildTuneSnapshot(opts.config, dataDir, null),
      history: [],
      commandHistory,
      moduleOptions: {},
      contextSnapshot: loadedSnapshot ?? undefined,
      processing: false,
      onInput: handleInput,
      onExit: handleExit,
      onAbort: abortActiveAction,
    },
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
  const shellSigintHandler = (): void => {
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
    // Guard: a SIGINT within 2s of a tool/agent abort is almost certainly
    // a duplicate — pnpm/tsx and some terminal drivers forward the same
    // Ctrl+C twice (once as 0x03 byte, once as SIGINT) across the
    // raw-mode flip. Without this, the shell exits with code 130 right
    // after a successful abort even though the operator only pressed
    // Ctrl+C once.
    if (lastAbortFiredAt > 0 && Date.now() - lastAbortFiredAt < 2000) {
      abortDebug("SIGINT at idle — within 2s of abort, swallowing duplicate");
      return;
    }
    abortDebug("SIGINT at idle — forwarding to prior listeners");
    for (const listener of priorSigintListeners) {
      try {
        (listener as NodeJS.SignalsListener)("SIGINT");
      } catch {
        /* best-effort */
      }
    }
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
    if (!activeActionKind) return;
    // 0x03 is the byte terminal raw mode sends for Ctrl+C. 0x04 is Ctrl+D;
    // both count as an abort trigger.
    if (!(chunk.includes(0x03) || chunk.includes(0x04))) return;
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
  // biome-ignore lint/correctness/noUnusedVariables: teardown is registered for completeness; the OS reclaims /dev/tty fd on shell exit, so an explicit invocation isn't required today
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
        if (!activeActionKind) return;
        if (!(chunk.includes(0x03) || chunk.includes(0x04))) return;
        abortDebug(
          `dev-tty: 0x03/0x04 detected on /dev/tty fd, activeActionKind=${activeActionKind}`,
        );
        const killed = killAllClaudeSubprocesses();
        abortDebug(`dev-tty: killed=${killed} subprocesses`);
        abortActiveAction();
      };
      ttyStream.on("data", devTtyListener);
      ttyStream.on("error", (err) => {
        abortDebug(`dev-tty: stream error ${err instanceof Error ? err.message : String(err)}`);
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
      abortDebug(
        `dev-tty: could not open /dev/tty: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  // Surface prior .kuzushi/ artifacts so operators see the cache surface
  // before they run anything. Silent on fresh dirs.
  {
    const banner = formatArtifactBanner(opts.target ? path.resolve(opts.target) : process.cwd());
    if (banner) {
      appendToHistory(store, { type: "output", text: banner, timestamp: Date.now() });
    }
  }

  // The interactive shell always uses the Claude Agent SDK for sessions —
  // other backends (e.g. pi-ai) are designed for batch scans and don't expose
  // `createSession`. We always need Anthropic credentials here regardless of
  // the configured agentRuntimeBackend, so the prompt is no longer gated on it.
  await ensureClaudeShellRuntime(opts, store);
  {
    const { hasAnthropicCredentials, runCredentialPrompt } = await import("../ui/setup.js");
    const { resolveActiveCredentials } = await import("../config.js");
    if (!hasAnthropicCredentials(resolveActiveCredentials(opts.config).apiKey)) {
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
      // Anthropic creds were just provided — re-check the runtime can create
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

// ---------------------------------------------------------------------------
// Readline fallback (non-TTY) — for piped input and CI
// ---------------------------------------------------------------------------

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
  const rlCtx: ShellContext = { focusedModule: null, workspaceManager, dataDir };
  let rlState: ShellState = {
    modules: modules.map((module) => module.id),
    moduleCatalog: buildModuleCatalog(modules, core),
    tools: tools.map(({ tool }) => tool.name),
    focusedModule: null,
    shellView: "catalog",
    openFindingId: null,
    target: opts.target ?? null,
    workspace: opts.workspace ?? null,
    tuneSnapshot: buildTuneSnapshot(opts.config, dataDir, null),
    history: [],
    commandHistory,
    moduleOptions: {},
    contextSnapshot: loadedSnapshot ?? undefined,
    processing: false,
  };

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

  // Surface prior .kuzushi/ artifacts so operators see the cache surface
  // before they run anything. Silent on fresh dirs.
  {
    const banner = formatArtifactBanner(opts.target ? path.resolve(opts.target) : process.cwd());
    if (banner) console.error(`\n${banner}\n`);
  }

  // Startup credential prompt for the readline shell. Only runs when stderr is
  // a TTY (so users in CI/piped contexts aren't blocked) and when the Claude
  // backend has no credentials available yet. Done BEFORE creating the main
  // `rl` so the prompt's own readline interface owns stdin uncontested.
  // Safety-net: swap in Claude only if the configured runtime doesn't expose
  // createSession(). Built-in backends (claude, pi-ai) both support sessions,
  // so this is a no-op for them. Done before the credential prompt so the
  // prompt can guide the user to enable whichever backend is active.
  await ensureClaudeShellRuntime(opts);
  if (process.stderr.isTTY) {
    const { hasAnthropicCredentials, runReadlineCredentialPrompt } = await import("../ui/setup.js");
    const { resolveActiveCredentials } = await import("../config.js");
    if (!hasAnthropicCredentials(resolveActiveCredentials(opts.config).apiKey)) {
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
        workspace: opts.workspace ?? null,
      };
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
            process.stdout.write(`${execResult.output}\n`);
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
          const message = activeAbortRequested
            ? CANCELLED_TOOL_MESSAGE
            : error instanceof Error
              ? error.message
              : String(error);
          process.stdout.write(`${message}\n`);
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
          process.stdout.write(`${localResult.output}\n`);
        }
        rl.prompt();
        continue;
      }

      const agentInput = localResult.askQuestion;
      const currentSession = await ensureSession();
      if (!currentSession) {
        process.stdout.write(
          `${assistantDisabledReason ?? sessionError ?? DEFAULT_NO_SESSION_MESSAGE}\n`,
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
        const message = activeAbortRequested
          ? CANCELLED_AGENT_MESSAGE
          : error instanceof Error
            ? error.message
            : String(error);
        if (pendingAssistantText) {
          process.stdout.write(`${pendingAssistantText}\n`);
        }
        process.stdout.write(`${message}\n`);
        activeActionKind = null;
        activeAbortRequested = false;
        rl.prompt();
        continue;
      }

      if (pendingAssistantText || fallbackResultText) {
        process.stdout.write(
          `${finalizeAssistantText(pendingAssistantText, fallbackResultText)}\n`,
        );
      }
      if (pendingErrorText) {
        process.stdout.write(`${pendingErrorText}\n`);
      } else if (activeAbortRequested && !pendingAssistantText && !fallbackResultText) {
        process.stdout.write(`${CANCELLED_AGENT_MESSAGE}\n`);
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

// ---------------------------------------------------------------------------
// Local commands — handled without the LLM
// ---------------------------------------------------------------------------

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

function routeInput(
  input: string,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const trimmed = input.trim();
  const lower = trimmed.toLowerCase();

  if (trimmed.startsWith("?")) {
    recordCommandUsage(ctx, shellState, "/ask");
    return handleAskCommand([trimmed.slice(1).trim()], opts, shellState);
  }

  if (trimmed.startsWith("/")) {
    recordCommandUsage(ctx, shellState, trimmed);
    return handleSlashCommand(trimmed, core, opts, ctx, shellState);
  }

  if (lower === "exit" || lower === "quit" || lower === "q") {
    return { exit: true };
  }

  if (lower === "help") {
    recordCommandUsage(ctx, shellState, "/help");
    return { output: formatHelp(core, opts) };
  }
  if (lower === "help advanced") {
    recordCommandUsage(ctx, shellState, "/help");
    return { output: formatHelp(core, opts, { includeAdvanced: true }) };
  }
  if (lower === "modules" || lower === "m") {
    return { output: formatModuleList(core, shellState.moduleCatalog) };
  }
  if (lower === "tools") {
    return { output: formatTools(core, ctx.focusedModule) };
  }
  if (lower.startsWith("use ")) {
    return handleUseCommand(trimmed.split(/\s+/).slice(1), core, opts, ctx);
  }
  if (lower === "back" || lower === "b") {
    return handleBackCommand(opts, ctx, shellState);
  }
  if (lower === "findings" || lower === "f") {
    return {
      shellStateUpdater: (shell) => ({ ...shell, shellView: "findings", openFindingId: null }),
      output: "Showing current findings.",
    };
  }
  if (lower === "tune" || lower === "t") {
    if (!ctx.focusedModule) return { output: "Use a module first: use <module>" };
    return {
      shellStateUpdater: (shell) => ({ ...shell, shellView: "tune" }),
      output: `Tuning ${ctx.focusedModule}. Use prompt edit <verb> for prompt overrides.`,
    };
  }
  if (lower === "story") {
    recordCommandUsage(ctx, shellState, "/story");
    return handleStoryCommand(shellState);
  }
  if (lower.startsWith("open ")) {
    return handleOpenCommand(trimmed.split(/\s+/).slice(1));
  }
  if (lower === "scan" || lower.startsWith("scan ")) {
    return resolveToolExecution(
      "sast:scan",
      trimmed.split(/\s+/).slice(1),
      core,
      opts,
      ctx,
      shellState,
    );
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

  const preview = trimmed.length > 60 ? `${trimmed.slice(0, 60)}…` : trimmed;
  const base = `Unknown command: "${preview}". Try /help, or /ask <question> to ask Claude with current shell context.`;
  const hint = firstBareSentenceHintShown
    ? ""
    : "\n(hint: natural-language chat moved to /ask — type /ask <question> or prefix with ?)";
  firstBareSentenceHintShown = true;
  return { output: base + hint };
}

function handleSlashCommand(
  input: string,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult {
  const { cmd, args } = parseCommand(input.slice(1));
  const command = cmd.toLowerCase();

  switch (command) {
    case "help":
      // `/help <verb>` prints the one-line row from the commands table plus a
      // short expanded description; bare `/help` falls through to the grouped
      // top-level help. Both surfaces render from SHELL_COMMAND_CATALOG so
      // drift is impossible.
      if (args[0]?.toLowerCase() === "advanced") {
        return { output: formatHelp(core, opts, { includeAdvanced: true }) };
      }
      if (args[0]) return { output: formatHelpForVerb(args[0]) };
      return { output: formatHelp(core, opts) };

    case "modules":
    case "m":
      return { output: formatModuleList(core, shellState.moduleCatalog) };

    case "tools":
      return {
        output: formatTools(core, ctx.focusedModule, { includeHidden: args.includes("--all") }),
      };

    case "scan":
      return resolveToolExecution("sast:scan", args, core, opts, ctx, shellState);

    case "use":
      return handleUseCommand(args, core, opts, ctx);

    case "back":
    case "b":
      return handleBackCommand(opts, ctx, shellState);

    case "findings":
    case "f":
      return {
        shellStateUpdater: (shell) => ({
          ...shell,
          shellView: "findings",
          openFindingId: null,
          diffSince: undefined,
        }),
        output: "Showing all current findings.",
      };

    case "tune":
    case "t":
      if (!ctx.focusedModule) {
        return { output: "Usage: /use <module> first, then /tune." };
      }
      return {
        shellStateUpdater: (shell) => ({ ...shell, shellView: "tune" }),
        output: `Tuning ${ctx.focusedModule}. Use prompt edit <verb> for prompt overrides.`,
      };

    case "open":
      return handleOpenCommand(args);

    case "plan":
      return handlePlanCommand(args, core, opts, ctx, shellState);

    case "yes":
    case "apply-plan":
      return handleApplyPlanCommand(core, shellState);

    case "no":
    case "discard-plan":
      return handleDiscardPlanCommand(shellState);

    case "prompt": {
      const sub = args[0]?.toLowerCase();
      const verb = args[1];
      if (sub === "edit") {
        return handlePromptEditCommand(verb, core, opts, ctx, shellState);
      }
      if (sub === "show") {
        return handlePromptShowCommand(verb, core, opts, ctx, shellState);
      }
      return {
        output: [
          "Usage:",
          "  /prompt edit <verb>    open the operator override in $EDITOR",
          "  /prompt show <verb>    print the current effective prompt + source",
          "  /show prompts          cross-module audit of all *_PROMPT keys",
        ].join("\n"),
      };
    }

    case "show":
      return handleShowCommand(args, core, opts, ctx, shellState);

    case "runs":
      return handleShowRunsCommand(args, ctx);

    case "replay":
      return handleReplayCommand(args, ctx);

    case "trace":
      return handleTraceCommand(args, ctx);

    case "options":
      return handleOptionsCommand(args, core, opts, ctx, shellState);

    case "set":
      return handleSetCommand(args, core, ctx.focusedModule, shellState);

    case "config":
      return handleConfigCommand(args, ctx);

    case "auth":
      return handleAuthCommand(opts, ctx);

    case "ask":
      return handleAskCommand(args, opts, shellState);

    case "backend":
      return handleBackendCommand(args, opts);

    case "provider":
      return handleProviderCommand(args, opts);

    case "context":
      return handleContextCommand(args, core, opts, ctx, shellState);

    case "since":
      return handleSinceCommand(args, opts, ctx);

    case "threats":
      return handleThreatsCommand(args, opts, ctx);

    case "target":
      return handleTargetCommand(args, opts, shellState);

    case "workspace":
      return handleWorkspaceCommand(args, opts, ctx);

    case "clear":
      return {
        clearHistory: true,
        resetSession: true,
        output: "Conversation cleared.",
      };

    case "history":
      return { output: formatHistory(shellState.commandHistory) };

    case "load":
      return handleLoadCommand(args, core);

    case "exit":
      return { exit: true };

    default:
      return { output: formatUnknownVerb(command, collectKnownVerbs()) };
  }
}

function handleUseCommand(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
): LocalCommandResult {
  const moduleId = args[0];
  if (!moduleId) {
    return { output: "Usage: /use <module>" };
  }
  if (!core.hasModule(moduleId)) {
    const loaded = core.listModules().map((m) => m.id);
    return { output: formatUnknownModule(moduleId, loaded) };
  }
  const mod = core.registry.get(moduleId);
  const tuneSnapshot = ctx.dataDir
    ? buildTuneSnapshot(opts.config, ctx.dataDir, moduleId)
    : undefined;
  return {
    setFocus: moduleId,
    shellStateUpdater: (shell) => ({
      ...shell,
      shellView: "module",
      openFindingId: null,
      tuneSnapshot: tuneSnapshot ?? shell.tuneSnapshot,
    }),
    output: `Focused on ${mod.displayName}. ${mod.tools.length} tools available.`,
  };
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
    currentView === "tune" ||
    currentView === "diff-since" ||
    currentView?.startsWith("threat-")
  ) {
    return {
      shellStateUpdater: (shell) => ({ ...shell, shellView: "module" }),
      output: "Back to module home.",
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

function handleOpenCommand(args: string[]): LocalCommandResult {
  const findingId = args[0];
  if (!findingId) {
    return { output: "Usage: /open <F-NNNN|fingerprint>" };
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
    return { output: "No focused module. Use /use <module> first." };
  }
  const activeToolName = shellState.lastUsedTool;
  const fallbackToolName = activeToolName?.startsWith(`${ctx.focusedModule}:`)
    ? activeToolName
    : pickDefaultToolName(core, ctx.focusedModule);
  if (!fallbackToolName) {
    return { output: `No tool resolved for ${ctx.focusedModule}. Use /options <tool> first.` };
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
        errorMsg = err instanceof Error ? err.message : String(err);
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
    return { output: formatPromptAuditTable(rows) };
  }
  if (sub === "runs") {
    return handleShowRunsCommand(args.slice(1), ctx);
  }
  if (sub === "aliases") {
    return handleShowAliasesCommand(args.slice(1), ctx);
  }
  return { output: "Usage: /show prompts  |  /show runs  |  /show aliases [prefix]" };
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
  return {
    output: formatOptions(core, resolved.toolName, opts, shellState),
    shellStateUpdater: (shell) => ({
      ...shell,
      lastUsedTool: resolved.toolName,
    }),
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

  // /context build — Live Build screen. Runs the deterministic
  // `gatherContextForRoot` pipeline with a phase observer that streams
  // into `shell.contextBuild`, writes `.kuzushi/scan-context.json` on
  // completion, and returns to the prompt with a one-line summary.
  if (sub === "build") {
    if (!opts.target) return { output: "No target set. Use /target <path> first." };
    const repoRoot = path.resolve(opts.target);
    return {
      output: "Building operator scan context…",
      shellStateUpdater: (shell) => ({
        ...shell,
        shellView: "context-build",
        contextBuild: initContextBuildState(repoRoot),
      }),
      asyncExecute: async (signal) => {
        const { runContextBuildLive } = await import("./context-build-runner.js");
        return runContextBuildLive(ctx.uiStore, repoRoot, signal);
      },
    };
  }

  // /context edit — open the operator context intake editor
  if (sub === "edit") {
    if (!opts.target) return { output: "No target set. Use /target <path> first." };
    const repoRoot = path.resolve(opts.target);
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
    if (!opts.target) return { output: "No target set. Use /target <path> first." };
    return resolveToolExecution("context:build", args.slice(1), core, opts, ctx, shellState);
  }

  // /context <module-path> — drill into monorepo module
  if (sub && shellState.contextSnapshot?.modules?.[sub]) {
    return { output: formatContextSummary(shellState.contextSnapshot, sub) };
  }

  // /context — show current snapshot if valid for current target
  if (
    shellState.contextSnapshot &&
    opts.target &&
    shellState.contextSnapshot.target === path.resolve(opts.target)
  ) {
    return { output: formatContextSummary(shellState.contextSnapshot) };
  }

  // No valid snapshot — trigger generation
  if (!opts.target) return { output: "No target set. Use /target <path> first." };
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
    shellStateUpdater: (shell) => ({ ...shell, shellView: "findings", openFindingId: null }),
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

function handleThreatsCommand(
  args: string[],
  opts: ShellOptions,
  ctx: ShellContext,
): LocalCommandResult {
  const sub = args[0]?.toLowerCase() ?? "summary";

  // /threats dfd|stride|stories|scope|summary (and 1..5) — Phase C views.
  // Each routes to a shellView; the component reads shell.threatModel which
  // this handler populates below.
  const viewRoute = resolveThreatView(sub);
  if (viewRoute) {
    if (!opts.target) return { output: "No target set. Use /target <path> first." };
    const repoRoot = path.resolve(opts.target);
    return {
      output: `Loading threat model for ${viewRoute.label}…`,
      shellStateUpdater: (shell) => ({ ...shell, shellView: viewRoute.shellView }),
      asyncExecute: async () => {
        const { loadShellThreatModel } = await import("./threat-model-loader.js");
        const loaded = loadShellThreatModel(repoRoot);
        if (!loaded) {
          return "No threat model found. Run a scan with threat modeling enabled first.";
        }
        if (ctx.uiStore) {
          updateShell(ctx.uiStore, (shell) => ({
            ...shell,
            threatModel: loaded.document,
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
    if (!opts.target) return { output: "No target set. Use /target <path> first." };
    const repoRoot = path.resolve(opts.target);
    return {
      output: "Opening threat model editor...",
      asyncExecute: async () => {
        const { loadPersistentThreatModel } = await import("../threat-model-renderer.js");
        const { runThreatModelEditor } = await import("../ui/setup.js");
        const tm = loadPersistentThreatModel(repoRoot);
        if (!tm) return "No threat model found. Run a scan with threat modeling enabled first.";
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
        return "Threat model editing skipped.";
      },
    };
  }

  return {
    output: "Usage: /threats [dfd|stride|stories|scope|summary|edit]  (1..5 also switches views)",
  };
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
      };
    }
    return { output: `Target set to: ${newTarget}` };
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
    return { output: `[+] Workspace created: ${name} (${ws.id.slice(0, 8)})` };
  }
  if (sub === "-d" && args[1] && mgr) {
    const target = args.slice(1).join(" ");
    const existing = mgr.getByName(target);
    if (!existing) return { output: `[-] No workspace named '${target}'.` };
    mgr.delete(existing.id);
    if (opts.workspace === existing.id) opts.workspace = undefined;
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
    return { output: `Workspace created: ${name} (${ws.id.slice(0, 8)})` };
  }

  // /workspace switch <name> or /workspace <name> (backward compat)
  const name = sub === "switch" ? args.slice(1).join(" ").trim() : args.join(" ").trim();
  if (name) {
    if (mgr) {
      const ws = mgr.getOrCreate(name, opts.target ? [opts.target] : []);
      mgr.touchAccessed(ws.id);
      opts.workspace = ws.id;
      return {
        output: `Workspace: ${ws.name} (${ws.targets.length} targets, last accessed ${ws.lastAccessedAt.slice(0, 10)})`,
      };
    }
    opts.workspace = name;
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
      ? `Current workspace: ${opts.workspace}`
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
        return `Failed to load module: ${err instanceof Error ? err.message : String(err)}`;
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
  // (e.g. `threat-hunt:run`), typing `run .` is parsed as "dispatch tool `.`"
  // instead of "dispatch threat-hunt:run with positional `.`".
  if (ctx.focusedModule) {
    const qualifiedName = `${ctx.focusedModule}:${cmd}`;
    if (core.registry.resolveTool(qualifiedName)) {
      return resolveToolExecution(qualifiedName, args, core, opts, ctx, shellState);
    }
  }

  // `run <tool> [args]` explicit escape. Kept after focused-module resolution
  // so that a focused module whose tool is named `run` wins; still available
  // at top level and for explicit cross-module dispatch like `run sast:scan .`.
  if (cmd.toLowerCase() === "run" && args.length > 0) {
    return resolveToolExecution(args[0]!, args.slice(1), core, opts, ctx, shellState);
  }

  const resolvedToolName = resolveToolName(cmd, core, null);
  if (resolvedToolName) {
    return resolveToolExecution(resolvedToolName, args, core, opts, ctx, shellState);
  }

  return undefined;
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

  // Context gating — block tools that require context when none exists
  if (CONTEXT_REQUIRED_TOOLS.has(finalToolName) && !shellState.contextSnapshot) {
    return { output: `Context required for ${finalToolName}. Run context (or /context) first.` };
  }

  return {
    executedToolName: finalToolName,
    asyncExecute: async (signal?: AbortSignal) => {
      const storedArgs = shellState.moduleOptions[finalToolName] ?? {};
      const parsedArgs = parseToolArgs(toolArgs);
      const mergedArgs: Record<string, unknown> = { ...storedArgs, ...parsedArgs };
      if (!("target" in mergedArgs) && opts.target) {
        mergedArgs.target = opts.target;
      }

      const seedTaskOutputs = shellState.contextSnapshot
        ? buildSeedMapFromSnapshot(shellState.contextSnapshot)
        : undefined;

      const result = await core.executeTool(finalToolName, mergedArgs, {
        cwd: opts.target ? path.resolve(opts.target) : process.cwd(),
        target: (mergedArgs.target as string) ?? opts.target,
        workspaceId: opts.workspace,
        uiStore: ctx.uiStore,
        signal,
        seedTaskOutputs,
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
    return { ok: false, output: "Usage: /options <tool>" };
  }

  if (focusedModule && !lastUsedTool.startsWith(`${focusedModule}:`)) {
    return {
      ok: false,
      output: `No active tool selected for ${focusedModule}. Use /options <tool> first.`,
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
  const resolved = core.registry.resolveTool(toolName);
  if (!resolved) {
    return formatUnknownToolMessage(toolName, core);
  }

  const properties = getToolProperties(resolved.tool);
  const optionNames = Object.keys(properties);
  if (optionNames.length === 0) {
    return `  ${toolName} has no configurable options.`;
  }

  const storedValues = shellState.moduleOptions[toolName] ?? {};
  const rows = optionNames.map((optionName) => {
    const schema = properties[optionName]!;
    const hasStoredValue = Object.hasOwn(storedValues, optionName);
    const value = hasStoredValue
      ? storedValues[optionName]
      : optionName === "target" && opts.target
        ? opts.target
        : undefined;
    return {
      optionName,
      valueLabel: hasStoredValue ? `* ${formatValue(value)}` : formatValue(value),
      defaultLabel: formatValue(schema.default),
      description: formatOptionDescription(schema),
    };
  });

  const optionWidth = Math.max("Option".length, ...rows.map((row) => row.optionName.length));
  const valueWidth = Math.max("Value".length, ...rows.map((row) => row.valueLabel.length));
  const defaultWidth = Math.max("Default".length, ...rows.map((row) => row.defaultLabel.length));

  return formatSections([
    [
      `  ${toolName} options                              * = set`,
      "",
      `  ${"Option".padEnd(optionWidth)}  ${"Value".padEnd(valueWidth)}  ${"Default".padEnd(defaultWidth)}  Description`,
      `  ${"-".repeat(optionWidth)}  ${"-".repeat(valueWidth)}  ${"-".repeat(defaultWidth)}  -----------`,
      ...rows.map(
        (row) =>
          `  ${row.optionName.padEnd(optionWidth)}  ${row.valueLabel.padEnd(valueWidth)}  ${row.defaultLabel.padEnd(defaultWidth)}  ${row.description}`,
      ),
    ],
  ]);
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
    return { output: "Usage: /prompt edit <verb>  (e.g. /prompt edit triage)" };
  }
  const promptKey = verbToPromptKey(verb);
  if (!promptKey) {
    return { output: `No prompt override for verb "${verb}".` };
  }
  const toolName = `${ctx.focusedModule}:${verb}`;
  const resolved = core.registry.resolveTool(toolName);
  if (!resolved) {
    return { output: `Tool ${toolName} not found. Use /tools to list.` };
  }
  const dataDir = ctx.dataDir;
  const focusedModule = ctx.focusedModule;
  const description = resolved.tool.description;
  return {
    output: `Opening ${promptKey} override in $EDITOR…`,
    asyncExecute: async () => {
      try {
        const outcome = await editPrompt({
          dataDir,
          moduleId: focusedModule,
          verb,
          toolDescription: description,
        });
        if (!outcome.saved) {
          return "Prompt editor closed without saving.";
        }
        // Store the absolute path on the shell's in-memory option map so the
        // same path the tool reads at run-time matches what we just wrote.
        if (ctx.uiStore) {
          updateShell(ctx.uiStore, (shell) => ({
            ...shell,
            moduleOptions: {
              ...shell.moduleOptions,
              [toolName]: {
                ...(shell.moduleOptions[toolName] ?? {}),
                [outcome.promptKey]: outcome.filePath,
              },
            },
            lastUsedTool: toolName,
          }));
        }
        return [
          `Saved ${outcome.byteLen} bytes to ${outcome.filePath}`,
          `Set ${toolName}.${outcome.promptKey} = ${outcome.filePath}`,
        ].join("\n");
      } catch (err) {
        return `Prompt editor error: ${err instanceof Error ? err.message : String(err)}`;
      }
    },
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
    return { output: "Usage: /prompt show <verb>" };
  }
  const promptKey = verbToPromptKey(verb);
  if (!promptKey) {
    return { output: `No prompt override for verb "${verb}".` };
  }
  const toolName = `${ctx.focusedModule}:${verb}`;
  if (!core.registry.resolveTool(toolName)) {
    return { output: `Tool ${toolName} not found.` };
  }
  const cwd = opts.target ? path.resolve(opts.target) : process.cwd();
  const stored = shellState.moduleOptions[toolName];
  const effective = readEffectivePrompt(toolName, promptKey, stored, cwd);
  const verbSuffix = promptKeyToVerb(promptKey);
  const header = `Prompt for ${toolName} (${verbSuffix})`;
  return { output: `${header}\n  ${formatEffectivePromptLine(effective)}` };
}

/**
 * Lazy DB handle for replay commands. Each call opens (or reuses) a
 * better-sqlite3 connection against `<dataDir>/findings.sqlite3`. The
 * handle is deliberately not cached on ShellContext so `/replay` stays
 * independent of the workspace/DB boot block (which may have been
 * skipped in degraded environments).
 */
async function openRunsDb(ctx: ShellContext) {
  if (!ctx.dataDir) return undefined;
  const dbPath = path.join(ctx.dataDir, "findings.sqlite3");
  if (!existsSync(dbPath)) return undefined;
  const { initDb } = await import("../store.js");
  return initDb(dbPath);
}

function handleShowAliasesCommand(args: string[], ctx: ShellContext): LocalCommandResult {
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
    output: "No run summary in memory. Start a scan or use /replay <runId> to hydrate.",
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
  focusedModule: string | null,
  shellState: ShellState,
): LocalCommandResult {
  if (args.length === 0) {
    return { output: "Usage: /set <key> <value>" };
  }

  const activeToolName = shellState.lastUsedTool;
  if (!activeToolName || (focusedModule && !activeToolName.startsWith(`${focusedModule}:`))) {
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

  const properties = getToolProperties(resolved.tool);
  const schema = properties[optionKey];
  if (!schema) {
    return { output: `Unknown option for ${activeToolName}: ${optionKey}` };
  }

  const coercedValue = coerceOptionValue(rawValue, schema);
  const typeError = validateOptionType(optionKey, coercedValue, schema);
  if (typeError) {
    return { output: typeError };
  }
  const enumError = validateOptionValue(optionKey, coercedValue, schema);
  if (enumError) {
    return { output: enumError };
  }

  return {
    output: `Set ${activeToolName}.${optionKey} = ${formatValue(coercedValue)}`,
    shellStateUpdater: (shell) => ({
      ...shell,
      moduleOptions: {
        ...shell.moduleOptions,
        [activeToolName]: {
          ...(shell.moduleOptions[activeToolName] ?? {}),
          [optionKey]: coercedValue,
        },
      },
      lastUsedTool: activeToolName,
    }),
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
        claude?: { apiKey?: string; baseUrl?: string };
        piAi?: { apiKey?: string; baseUrl?: string };
      }
    | undefined,
): string[] {
  const out: string[] = [];
  for (const slot of ["claude", "piAi"] as const) {
    const s = cfg?.[slot];
    if (!s || (!s.apiKey && !s.baseUrl)) {
      out.push(
        `  ${slot.padEnd(6)} (unset — run /backend ${slot === "piAi" ? "pi-ai" : "claude"} then /auth)`,
      );
      continue;
    }
    out.push(
      `  ${slot.padEnd(6)} apiKey=${maskApiKey(s.apiKey)}  baseUrl=${s.baseUrl ?? "(default)"}`,
    );
  }
  return out;
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
          lines.push(
            `(Swapped for this session because "${persisted}" doesn't support interactive shell.)`,
          );
        }
        lines.push("", "Credentials (per backend):");
        lines.push(...formatBackendSlots(opts.config.agentRuntimeConfig));
        lines.push(
          "",
          "Available: pi-ai (default, 20+ providers), claude (legacy CC subprocess)",
          "Usage:",
          "  /backend show           Show current + persisted backend + credentials",
          "  /backend pi-ai          Use pi-ai — multi-provider, in-process (recommended)",
          "  /backend claude         Use Claude Code SDK — Anthropic only, subprocess-per-task",
          "",
          "For provider/model selection, use /provider instead.",
          `Persists to ${configPath()}.`,
        );
        return lines.join("\n");
      },
    };
  }

  if (sub !== "claude" && sub !== "pi-ai") {
    const suggestion = closestBackend(sub, ["claude", "pi-ai"]);
    const hint = suggestion ? ` Did you mean "${suggestion}"?` : "";
    return {
      output: `Unknown backend "${sub}".${hint} Available: claude, pi-ai. Run /backend show for help.`,
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
        const detail = error instanceof Error ? error.message : String(error);
        return `Failed to update backend: ${detail}`;
      }
      opts.config.agentRuntimeBackend = sub;
      const note =
        sub === "claude"
          ? "Shell sessions and future `kuzushi scan ...` runs will use claude. Restart the shell to pick up the change."
          : "Shell sessions and future `kuzushi scan ...` runs will use pi-ai. Restart the shell to pick up the change.";
      const lines = [`Backend persisted as "${sub}" in ${configPath()}.`, note];
      // Each backend has its own credential slot now, so switching can't leak
      // creds between backends. Just hint when the new slot is empty so the
      // operator knows to /auth.
      const slot = sub === "pi-ai" ? "piAi" : "claude";
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

// ---------------------------------------------------------------------------
// /provider — show or set the default model (provider:model)
// ---------------------------------------------------------------------------

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
        const detail = error instanceof Error ? error.message : String(error);
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

// ---------------------------------------------------------------------------
// /ask — explicit natural-language query, with screen context injected
// ---------------------------------------------------------------------------

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
  if (opts.workspace) lines.push(`- workspace: ${opts.workspace}`);
  if (shellState.openFindingId) lines.push(`- open finding: ${shellState.openFindingId}`);
  if (shellState.lastUsedTool) lines.push(`- last tool: ${shellState.lastUsedTool}`);

  const snapshot = shellState.contextSnapshot;
  if (snapshot) {
    const snapshotLines: string[] = [];
    if (snapshot.repoContext) snapshotLines.push("repoContext");
    if (snapshot.appModel) snapshotLines.push("appModel");
    if (snapshot.threatModel) snapshotLines.push("threatModel");
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
    // context-snapshot.json is what enables /use threat-hunt (etc.) to pass
    // the appModel/threatModel prereq check without re-running context:build.
    // Surface it by name so operators understand what's carrying them.
    { rel: "context-snapshot.json", label: "context snapshot (appModel + threatModel)" },
    { rel: "findings.sqlite3", label: "prior findings DB" },
  ];
  for (const { rel, label } of files) {
    const full = path.join(kuzushiDir, rel);
    if (!existsSync(full)) continue;
    try {
      const stat = statSync(full);
      const mtime = stat.mtime.toISOString().slice(0, 10);
      out.push(`${rel} (${label}, modified ${mtime})`);
    } catch {
      out.push(`${rel} (${label})`);
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
 * Multi-line banner listing prior `.kuzushi/` artifacts the shell will carry
 * into `/ask` and tool runs. Returned as a single string ready to feed into
 * `appendToHistory` or `console.error`; empty string for fresh dirs so callers
 * can skip rendering entirely.
 */
function formatArtifactBanner(repoRoot: string): string {
  const manifest = loadArtifactManifest(repoRoot);
  if (manifest.length === 0) return "";
  return [
    "Prior artifacts in .kuzushi/:",
    ...manifest.map((m) => `  - ${m}`),
    "/ask uses these as context.",
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

function handleAuthCommand(opts: ShellOptions, ctx: ShellContext): LocalCommandResult {
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
      "  export ANTHROPIC_API_KEY=sk-ant-...",
      "  export ANTHROPIC_OAUTH_TOKEN=...",
      "Or edit ~/.kuzushi/config.json (agentRuntimeConfig.apiKey).",
    ].join("\n"),
  };
}

function handleConfigCommand(args: string[], ctx: ShellContext): LocalCommandResult {
  const sub = (args[0] ?? "").toLowerCase();

  // Default + edit: open the interactive editor (or fall back to raw on no TTY).
  if (!sub || sub === "list" || sub === "show" || sub === "edit") {
    const focusKey = sub === "edit" ? args[1] : undefined;
    return openConfigEditor(ctx, focusKey);
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
          return `Failed to set ${key}: ${err instanceof Error ? err.message : String(err)}`;
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
        ["Workspace:", opts.workspace ?? null],
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
      return `  All ${hiddenCount} tools on ${focusedModule} are DAG-internal. Run \`/tools --all\` to list them.`;
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
      : "  No user-facing tools. Run `/tools --all` to list DAG-internal nodes.";
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
        ["Workspace:", opts.workspace ?? null],
      ]),
      '  Type "modules" to choose a workflow, or "/ask <question>" for agent chat.',
    ],
  ]);
}

export const __shellInternals = {
  buildSeedMapFromSnapshot,
  buildShellPrompt,
  capShellHistory,
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
  handleLocalCommand: routeInput,
  handleSlashCommand,
  reconcileShellView,
  loadArtifactManifest,
  loadShellCommandHistory,
  resolveDirectToolDispatch,
  saveShellCommandHistory,
};
