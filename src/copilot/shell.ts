/**
 * Interactive copilot shell — the default `kuzushi` experience.
 *
 * The LLM is the router. User input goes to an AgentSession, which
 * decides what tools to call. The Ink UI streams the conversation.
 *
 * This is the Claude Code model: you type naturally, the agent
 * handles dispatch, tool progress renders inline, results appear
 * as the conversation flows.
 */

import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
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
import { SpoolController } from "./spool.js";

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

/** Build a seed map from a ContextSnapshot to inject into pipelines. */
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
  if (snapshot.threatModel) seed.set("threat-model-randori", snapshot.threatModel);
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
  asyncExecute?: (signal?: AbortSignal) => Promise<string>;
  /**
   * When set, the shell should stream this string through `currentSession.query()`
   * — this is the `/ask` pathway. Replaces the old silent fallback that
   * forwarded any unknown input to the agent and invited hallucinated answers.
   */
  askQuestion?: string;
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

export function buildShellPrompt(focusedModule: string | null): string {
  return focusedModule ? `kuzushi/${focusedModule}> ` : "kuzushi> ";
}

/**
 * Map the sub-verb of `/threats <sub>` to a threat-model shellView. Accepts
 * both named (`dfd`, `stride`, `stories`, `scope`, `summary`) and numeric
 * (`1..5`) shortcuts so operators can cycle through the Phase C views with
 * the same keys shown in the footer.
 */
function resolveThreatView(
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

function formatUnknownToolMessage(toolName: string): string {
  return `Unknown tool: "${toolName}". Type /tools to list available.`;
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
    if (prev[0] === trimmed) return shell;
    const nextActivities = [trimmed, ...prev].slice(0, LIVE_ACTIVITY_CAP);
    const next = shell.history.slice();
    next[idx] = { ...entry, liveActivities: nextActivities };
    return { ...shell, history: next };
  });
}

function beginShellTurn(store: UIStore, input: string, focusedModule: string | null): void {
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

function syncShellState(store: UIStore, opts: ShellOptions, focusedModule: string | null): void {
  updateShell(store, (shell) => ({
    ...shell,
    focusedModule,
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

function updateToolSummary(store: UIStore, summary: string): void {
  updateShell(store, (shell) => ({
    ...shell,
    history: [...shell.history, { type: "output", text: `  ${summary}`, timestamp: Date.now() }],
    currentTool: undefined,
  }));
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
    appendToHistory(store, {
      type: "tool-call",
      id: historyEntryId,
      tool: tool.name,
      ...(displayName ? { displayName } : {}),
      ...(inputDisplay ? { inputHint: inputDisplay } : {}),
      status: "running",
      text: headerText,
      timestamp: Date.now(),
    });
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
      const elapsed = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
      const status: "ok" | "fail" | "abort" = aborted ? "abort" : ok ? "ok" : "fail";
      // Per-tool renderResult() may return a concise summary like
      // "Read 559 lines". Fall back to the generic verb when omitted.
      const customResult =
        status === "ok" && finalResult ? tool.renderResult?.(finalResult) : undefined;
      const verb = aborted ? "aborted" : ok ? "done" : "failed";
      const resultOutput =
        customResult && customResult.length > 0 ? customResult : `${verb} in ${elapsed}s`;
      patchHistoryEntry(store, historyEntryId, {
        status,
        elapsedSeconds: elapsed,
        resultOutput,
        // Clear the live tail — the tool is done, scrollback already has
        // the per-activity entries for the audit trail.
        liveActivities: undefined,
      });
      updateShell(store, (shell) => ({ ...shell, currentTool: undefined }));
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
      pushToolPhase(store, event.payload.phase);
      // Also feed the running tool-call's live tail so operators see the
      // latest phase inline under the `⏺` header while the tool runs.
      const entryId = store.getState().shell?.currentTool?.historyEntryId;
      if (entryId) pushLiveActivity(store, entryId, event.payload.phase);
      appendToHistory(store, {
        type: "tool-progress",
        text: event.payload.phase,
        timestamp: Date.now(),
      });
    },
  );
  bus.subscribe<import("../bus/events.js").TaskActivityEvent>("task:activity", (event) => {
    const runId = event.meta.runId;
    if (abortedRunIds.has(runId)) return;
    if (activeAbortRequested || store.getState().shell?.processing !== true) return;
    seenRunIdsThisTurn.add(runId);
    if (event.payload.phase) pushToolPhase(store, event.payload.phase);
    pushToolActivity(store, event.payload.description);
    const entryId = store.getState().shell?.currentTool?.historyEntryId;
    if (entryId) pushLiveActivity(store, entryId, event.payload.description);
    const isSubagentTool = looksLikeSubagentToolLine(event.payload.description);
    appendToHistory(store, {
      type: "tool-progress",
      text: event.payload.description,
      timestamp: Date.now(),
      ...(isSubagentTool ? { progressKind: "invocation" as const } : {}),
    });
  });
  // Ephemeral subprocess stdout / tool-use preview — shows in the running
  // `⏺` entry's live tail but never lands in scrollback. cc-repo's
  // `ShellProgressMessage` analogue: operators see live Bash output during
  // execution, then it's gone once the tool resolves.
  bus.subscribe<import("../bus/events.js").TaskOutputEvent>("task:output", (event) => {
    const entryId = store.getState().shell?.currentTool?.historyEntryId;
    if (entryId) pushLiveActivity(store, entryId, event.payload.line);
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
      controller.abort(new Error("Shell tool execution aborted"));
      // Immediately return the operator to the prompt instead of waiting
      // for the tool to notice the signal. A tool that ignores the signal
      // will still finish in the background; its cleanup path is idempotent
      // with what we do here. This is the core "Ctrl+C once goes back"
      // behavior — the alternative (waiting for the tool to unwind) felt
      // like the shell was hung even though the abort had fired.
      blacklistCurrentTurnRunIds();
      appendToHistory(store, {
        type: "output",
        text: "[aborted]",
        timestamp: Date.now(),
      });
      clearTransientShellState(store);
      setProcessing(store, false);
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
      appendToHistory(store, {
        type: "output",
        text: CANCELLED_AGENT_MESSAGE,
        timestamp: Date.now(),
      });
      clearTransientShellState(store);
      setProcessing(store, false);
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
    beginShellTurn(store, input, shellCtx.focusedModule);

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
      try {
        const output = await localResult.asyncExecute(controller.signal);
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
          }));
        }
        if (output) {
          appendToHistory(store, { type: "output", text: output, timestamp: Date.now() });
        }
      } catch (error) {
        const wasAborted = controller.signal.aborted;
        finishActiveAction();
        if (wasAborted) {
          // Abort handler already rendered `[aborted]` — no need to also
          // append CANCELLED_TOOL_MESSAGE.
          return;
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
            // batch's `precedingToolUseIds` from "running" → "ok". The
            // Anthropic SDK doesn't expose per-tool success/failure at
            // the summary level — it bundles multiple uses together —
            // so we mark everything in the batch as successful and rely
            // on follow-up assistant text to surface errors explicitly.
            const precedingIds = message.precedingToolUseIds ?? [];
            for (const toolUseId of precedingIds) {
              const history = store.getState().shell?.history ?? [];
              const entry = history.find(
                (e) => e.type === "tool-call" && e.toolUseId === toolUseId,
              );
              if (entry?.id) {
                patchHistoryEntry(store, entry.id, {
                  status: "ok",
                  liveActivities: undefined,
                });
              }
            }
            updateToolSummary(store, message.summary);
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
          const output = await localResult.asyncExecute(controller.signal);
          if (localResult.executedToolName) {
            rlState = {
              ...rlState,
              lastUsedTool: localResult.executedToolName,
            };
          }
          if (output) {
            process.stdout.write(`${output}\n`);
          }
        } catch (error) {
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
    return handleAskCommand([trimmed.slice(1).trim()], opts, shellState);
  }

  if (trimmed.startsWith("/")) {
    return handleSlashCommand(trimmed, core, opts, ctx, shellState);
  }

  if (lower === "exit" || lower === "quit" || lower === "q") {
    return { exit: true };
  }

  const toolResult = resolveDirectToolDispatch(trimmed, core, opts, ctx, shellState);
  if (toolResult !== undefined) {
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
      return { output: formatHelp(core, opts) };

    case "modules":
      return { output: formatModuleList(core) };

    case "tools":
      return { output: formatTools(core, ctx.focusedModule) };

    case "use": {
      const moduleId = args[0];
      if (!moduleId) {
        return { output: "Usage: /use <module>" };
      }
      if (!core.hasModule(moduleId)) {
        return { output: `Unknown module: "${moduleId}". Type /modules to list available.` };
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

    case "back": {
      // Step up through the shellView stack before falling back to top-level.
      const currentView = shellState.shellView;
      if (currentView === "finding") {
        return {
          shellStateUpdater: (shell) => ({ ...shell, shellView: "findings", openFindingId: null }),
          output: "Back to findings.",
        };
      }
      if (currentView === "findings" || currentView === "tune") {
        return {
          shellStateUpdater: (shell) => ({ ...shell, shellView: "module" }),
          output: "Back to module home.",
        };
      }
      if (ctx.focusedModule) {
        const clearedTune = ctx.dataDir
          ? buildTuneSnapshot(opts.config, ctx.dataDir, null)
          : undefined;
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

    case "findings":
    case "f":
      return {
        shellStateUpdater: (shell) => ({ ...shell, shellView: "findings", openFindingId: null }),
        output: ctx.focusedModule
          ? `Showing findings for ${ctx.focusedModule}.`
          : "Showing all findings across modules.",
      };

    case "tune":
    case "t":
      if (!ctx.focusedModule) {
        return { output: "Usage: /use <module> first, then /tune." };
      }
      return {
        shellStateUpdater: (shell) => ({ ...shell, shellView: "tune" }),
        output: `Tuning ${ctx.focusedModule}. Press p for expert prompt editor.`,
      };

    case "open": {
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

    case "plan": {
      // Natural-language → option-diff planner. Joins all args into the
      // request text so quoting is optional: `/plan run harder, focus on auth`.
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
        return { output: `Unknown tool: ${fallbackToolName}` };
      }
      const currentOptions = { ...(shellState.moduleOptions[fallbackToolName] ?? {}) };
      const runtime = opts.runtime;
      return {
        output: `Planning: "${text.slice(0, 80)}${text.length > 80 ? "\u2026" : ""}"`,
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

    case "yes":
    case "apply-plan": {
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

    case "no":
    case "discard-plan": {
      if (!shellState.pendingPlan) {
        return { output: "No pending plan." };
      }
      return {
        output: "Plan discarded.",
        shellStateUpdater: (shell) => ({ ...shell, pendingPlan: null }),
      };
    }

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

    case "show": {
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

    case "runs":
      return handleShowRunsCommand(args, ctx);

    case "replay":
      return handleReplayCommand(args, ctx);

    case "trace":
      return handleTraceCommand(args, ctx);

    case "options": {
      const resolved = resolveOptionsTool(
        core,
        args[0],
        ctx.focusedModule,
        shellState.lastUsedTool,
      );
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

    case "context": {
      const sub = args[0]?.toLowerCase();

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
        return resolveToolExecution("sast:context", args.slice(1), core, opts, ctx, shellState);
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
      return resolveToolExecution("sast:context", [], core, opts, ctx, shellState);
    }

    case "since": {
      // `/since <ref>` — diff-aware view. Computes the changed-file set
      // between HEAD and `<ref>` via git, stores it on shell.diffSince,
      // and pivots to the diff-since shellView. Works on any git ref
      // including tags and commit SHAs.
      const ref = args[0];
      if (!ref) {
        return { output: "Usage: /since <git-ref>  e.g.  /since main" };
      }
      if (!opts.target) {
        return { output: "No target set. Use /target <path> first." };
      }
      const repoRoot = path.resolve(opts.target);
      return {
        output: `Diffing HEAD against ${ref}\u2026`,
        shellStateUpdater: (shell) => ({ ...shell, shellView: "diff-since" }),
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
          return `Found ${scope.changedFiles.length} changed file${
            scope.changedFiles.length === 1 ? "" : "s"
          } since ${ref}.`;
        },
      };
    }

    case "threats": {
      const sub = args[0]?.toLowerCase();

      // /threats dfd|stride|stories|scope|summary (and 1..5) — Phase C
      // visualization views. Each routes to a shellView; the component
      // reads shell.threatModel which this handler populates below.
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

      // /threats — show summary
      if (!opts.target) return { output: "No target set. Use /target <path> first." };
      return {
        output: "Loading threat model...",
        asyncExecute: async () => {
          try {
            const { loadPersistentThreatModel } = await import("../threat-model-renderer.js");
            const repoRoot = path.resolve(opts.target!);
            const tm = loadPersistentThreatModel(repoRoot);
            if (!tm) return "No threat model found. Run a scan with threat modeling enabled first.";
            const dismissed = tm.dismissedThreats?.length ?? 0;
            const total = tm.threats.length;
            const mitigations = tm.confirmedMitigations?.length ?? 0;
            return `Threat model: ${total} threats (${dismissed} dismissed, ${mitigations} confirmed mitigations)\nUse /threats edit to review and edit.`;
          } catch {
            return "Failed to load threat model.";
          }
        },
      };
    }

    case "target": {
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
        output: opts.target
          ? `Current target: ${opts.target}`
          : "No target set. Usage: /target <path>",
      };
    }

    case "workspace": {
      const sub = args[0]?.toLowerCase();
      const mgr = ctx.workspaceManager;

      // -a / -d / -r / -D / -v / -S — msfconsole-style flags. These live
      // alongside the positional subcommands (list / create / switch) so
      // muscle memory from either side keeps working.
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
      // -D (capital): set default workspace for next shell launch. We check
      // the raw arg to distinguish from -d (delete). parseCommand splits on
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

    case "clear":
      return {
        clearHistory: true,
        resetSession: true,
        output: "Conversation cleared.",
      };

    case "history":
      return { output: formatHistory(shellState.commandHistory) };

    case "load": {
      const specifier = args.join(" ").trim();
      if (!specifier)
        return {
          output:
            "Usage: /load <module-specifier>\n  Examples: /load file:///path/to/module, /load package:@kuzushi/blackbox",
        };
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

    case "exit":
      return { exit: true };

    default:
      return { output: `Unknown command: /${command}. Type /help for available commands.` };
  }
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
    return { output: formatUnknownToolMessage(toolName) };
  }

  const finalToolName = resolvedToolName;

  // Context gating — block tools that require context when none exists
  if (CONTEXT_REQUIRED_TOOLS.has(finalToolName) && !shellState.contextSnapshot) {
    return { output: `Context required for ${finalToolName}. Run /context first.` };
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

      return result.output;
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
      return { ok: false, output: formatUnknownToolMessage(toolName) };
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
    return formatUnknownToolMessage(toolName);
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

function formatHelp(core: CopilotCore, opts: ShellOptions): string {
  const modules = core.listModules();
  const toolCount = core.registry.allTools().length;

  return formatSections([
    [
      "  Kuzushi — security-native AI operating environment",
      ...formatLabelValueRows([
        ["Modules:", modules.map((module) => module.id).join(", ") || "none"],
        ["Tools:", `${toolCount} available`],
        ["Target:", opts.target ?? null],
        ["Workspace:", opts.workspace ?? null],
      ]),
    ],
    [
      "  Commands",
      ...formatCommandRows([
        ["/help", "Show this help"],
        ["/modules", "List loaded modules"],
        ["/tools", "List available tools"],
        ["/use <module>", "Focus on a module"],
        ["/back", "Step back one level (finding → findings → module → catalog)"],
        ["/findings", "Show the findings list for the current module"],
        ["/open <F-NNNN>", "Open a finding in the linear deep page"],
        ["/tune", "Open the tune view for the focused module"],
        ["/plan <english>", "Propose option changes from a plain-English request"],
        ["/yes | /no", "Apply or discard the pending planner proposal"],
        ["/prompt edit <verb>", "Open the operator system-prompt override in $EDITOR"],
        ["/prompt show <verb>", "Show the effective prompt + source for a tool"],
        ["/show prompts", "Cross-module audit of every *_PROMPT override"],
        ["/show runs [repo]", "List recent pipeline runs (id · status · cost)"],
        ["/show aliases [pfx]", "List short-ID aliases (F-0001, C-01) for the current run"],
        ["/replay <runId>", "Re-render the summary of a past run from stored state"],
        ["/trace <runId>", "Stream the per-event JSONL audit log of a past run"],
        ["/options [tool]", "Show tool options"],
        ["/set <key> <value>", "Set a tool option"],
        ["/config", "Open the interactive config editor"],
        ["/config raw|get|set|path", "Inspect/update ~/.kuzushi/config.json"],
        ["/auth", "Set or change credentials for any supported provider"],
        ["/provider", "Show or set the default <provider>:<model> (e.g. openai:gpt-5-mini)"],
        ["/ask <question>", "Ask the agent with current shell context (? prefix also works)"],
        ["/backend [claude|pi-ai]", "Show or change the agent runtime backend (advanced)"],
        ["/target <path>", "Set or show the active target"],
        ["/context", "Generate or show application context map"],
        ["/context edit", "Review/edit operator scan context"],
        ["/context regenerate", "Re-generate context for current target"],
        ["/threats", "Show threat model summary"],
        ["/threats edit", "Review/edit threat model interactively"],
        ["/load <specifier>", "Load an external module at runtime"],
        ["/workspace <id>", "Set or show the active workspace"],
        ["/clear", "Clear conversation history"],
        ["/history", "Show command history"],
        ["/exit", "Exit the shell"],
      ]),
    ],
    [
      "  Tool Shortcuts",
      ...formatCommandRows([
        ["sast:scan .", "Direct tool invocation"],
        ["semgrep .", "Global shorthand when unambiguous"],
        ["scan .", "Focused module shorthand"],
        ["run sast:scan .", "Explicit run prefix"],
      ]),
    ],
    [
      "  Natural Language",
      ...formatCommandRows([
        ["What vulns are in this repo?", "Ask the copilot anything"],
        ["Hunt for SSRF chains", "Targeted code investigation"],
        ["exit | quit | q", "Bare aliases that always exit"],
      ]),
    ],
  ]);
}

function formatModuleList(core: CopilotCore): string {
  const modules = core.listModules();
  if (modules.length === 0) return "  No modules loaded.";

  return formatSections(
    modules.map((module) => {
      const tools = core.registry
        .moduleTools(module.id)
        .map((tool) => tool.name.split(":")[1])
        .join(", ");
      return [
        `  ${module.id} [${module.category}]`,
        `  ${formatModuleDescription(module.description)}`,
        ...formatLabelValueRows([["Tools:", tools || "none"]]),
      ];
    }),
  );
}

function formatModuleInfo(core: CopilotCore, id: string): string {
  if (!core.hasModule(id)) return `  Unknown module: "${id}"`;

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

function formatTools(core: CopilotCore, focusedModule: string | null): string {
  if (focusedModule) {
    const module = core.registry.get(focusedModule);
    if (module.tools.length === 0) {
      return `  No tools available for ${focusedModule}.`;
    }

    return formatSections([
      [
        `  ${module.displayName}`,
        ...formatCommandRows(
          module.tools.map((tool) => [
            toolActionName(tool.name),
            formatModuleDescription(tool.description),
          ]),
        ),
      ],
    ]);
  }

  const tools = core.registry.allTools();
  if (tools.length === 0) return "  No tools available.";

  return formatSections([
    [
      "  Available Tools",
      ...formatCommandRows(
        tools.map(({ tool }) => [tool.name, formatModuleDescription(tool.description)]),
      ),
    ],
  ]);
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
      '  Type "/help" for commands, or just describe what you need.',
    ],
  ]);
}

export const __shellInternals = {
  buildShellPrompt,
  capShellHistory,
  createShellSession,
  extractAssistantText,
  extractToolUseActivities,
  extractToolUseHeaders,
  finalizeAssistantText,
  looksLikeSubagentToolLine,
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
  loadArtifactManifest,
  loadShellCommandHistory,
  resolveDirectToolDispatch,
  saveShellCommandHistory,
};
