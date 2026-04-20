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

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { AgentQueryOptions, AgentRuntime, AgentSession } from "../agent-runtime/types.js";
import { createBus } from "../bus/index.js";
import type { MessageBus } from "../bus/types.js";
import { formatContextSummary } from "../modules/core-sast.js";
import type { ModuleTool } from "../modules/types.js";
import type { KuzushiConfig } from "../types.js";
import type { ContextSnapshot, ShellHistoryEntry, ShellState, UIStore } from "../ui/state.js";
import { CopilotCore } from "./core.js";
import { CoreDispatcher, DispatcherDriver } from "./dispatcher/index.js";
import { ModuleDispatcher } from "./dispatcher/module-dispatcher.js";
import { Datastore } from "./options.js";
import { createPrintSink, type PrintLevel, type PrintSink } from "./print.js";
import { listRecipes, resolveRecipePath } from "./recipes.js";
import { loadAndRunResource, saveResourceScript } from "./resource.js";
import { parseToolArgs } from "./run.js";

const SHELL_ALLOWED_TOOLS = ["Read", "Glob", "Grep", "Bash", "LS"];
const SHELL_HISTORY_FILENAME = "shell-history.json";
const MAX_SHELL_HISTORY = 1000;
const DEFAULT_NO_SESSION_MESSAGE =
  "No agent session available.\nSet ANTHROPIC_API_KEY or use Claude Code OAuth to enable the copilot.";
const CREDENTIALS_CANCELLED_MESSAGE =
  "Copilot assistant remains disabled without credentials. Local shell commands still work.";
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

export function finalizeAssistantText(
  pendingAssistantText: string | undefined,
  resultText: string,
): string {
  return pendingAssistantText && pendingAssistantText.length > 0
    ? pendingAssistantText
    : resultText;
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
  if (!toolName) {
    return undefined;
  }

  if (toolName.includes(":")) {
    return core.registry.resolveTool(toolName)?.tool.name;
  }

  if (focusedModule) {
    const focusedName = `${focusedModule}:${toolName}`;
    if (core.registry.resolveTool(focusedName)) {
      return focusedName;
    }
  }

  const matches = core.registry.allTools().filter(({ tool }) => {
    return toolActionName(tool.name).toLowerCase() === toolName.toLowerCase();
  });
  return matches.length === 1 ? matches[0]!.tool.name : undefined;
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
  updateShell(store, (shell) => ({
    ...shell,
    currentTool: { name: toolName, elapsedSeconds },
  }));
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
  let activeActionKind: "tool" | "agent" | null = null;
  let activeAbortRequested = false;

  const currentCwd = (): string => (opts.target ? path.resolve(opts.target) : process.cwd());
  const shellCtx: ShellContext = { focusedModule: null, uiStore: store, workspaceManager };

  // ---------------------------------------------------------------------------
  // msfconsole-style CommandDispatcher — first-pass router for help / use /
  // set / setg / unset / show / info / search / history / resource / makerc /
  // banner / exit. Unknown commands fall through to routeInput (second pass)
  // and ultimately the LLM agent (third pass).
  // ---------------------------------------------------------------------------
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
    },
  });

  const globals = new Datastore();

  const runToolFromDispatcher = async (
    tool: ModuleTool,
    input: Record<string, unknown>,
    signal?: AbortSignal,
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
    return core.executeTool(tool.name, input, execOpts);
  };

  let driver: DispatcherDriver;

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
  });

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
      store.getState().shell?.onAbort?.();
      return;
    }

    void closeSession();
  };

  const setToolAbort = (controller: AbortController): void => {
    activeActionKind = "tool";
    activeAbortRequested = false;
    setAbortHandler(store, () => {
      activeAbortRequested = true;
      controller.abort(new Error("Shell tool execution aborted"));
    });
  };

  const setAgentAbort = (): void => {
    activeActionKind = "agent";
    activeAbortRequested = false;
    setAbortHandler(store, () => {
      activeAbortRequested = true;
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

    beginShellTurn(store, input, shellCtx.focusedModule);

    // First pass: msfconsole-style dispatcher. If a registered command matches,
    // we render its output and skip the legacy router + LLM agent.
    const controller = new AbortController();
    setToolAbort(controller);
    const dispatched = await driver.handle(input, controller.signal);
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
    const localResult = shellState
      ? routeInput(input, core, opts, shellCtx, shellState)
      : undefined;
    if (localResult !== undefined) {
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
          if (finishActiveAction()) {
            appendToHistory(store, {
              type: "output",
              text: CANCELLED_TOOL_MESSAGE,
              timestamp: Date.now(),
            });
          } else {
            appendToHistory(store, {
              type: "error",
              text: error instanceof Error ? error.message : String(error),
              timestamp: Date.now(),
            });
          }
          clearTransientShellState(store);
          setProcessing(store, false);
          return;
        }

        finishActiveAction();
        clearTransientShellState(store);
        setProcessing(store, false);
        return;
      }

      if (localResult.output) {
        appendToHistory(store, { type: "output", text: localResult.output, timestamp: Date.now() });
      }
      clearTransientShellState(store);
      setProcessing(store, false);
      return;
    }

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
      for await (const message of currentSession.query(input)) {
        if (!alive) break;

        switch (message.type) {
          case "assistant": {
            const text = extractAssistantText(message.content);
            if (text) {
              appendPendingAssistantText(store, text);
            }
            break;
          }

          case "tool-progress": {
            updateToolActivity(store, message.toolName, message.elapsedSeconds);
            break;
          }

          case "tool-summary": {
            updateToolSummary(store, message.summary);
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
      const message = wasAborted
        ? CANCELLED_AGENT_MESSAGE
        : error instanceof Error
          ? error.message
          : String(error);
      const pendingAssistantText = store.getState().shell?.pendingAssistantText;
      if (pendingAssistantText) {
        appendToHistory(store, {
          type: "output",
          text: pendingAssistantText,
          timestamp: Date.now(),
        });
      }
      setPendingAssistantText(store, undefined);
      appendToHistory(store, {
        type: wasAborted ? "output" : "error",
        text: message,
        timestamp: Date.now(),
      });
      clearTransientShellState(store);
      setProcessing(store, false);
      return;
    }

    const wasAborted = finishActiveAction();
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
        type: pendingErrorText === CANCELLED_AGENT_MESSAGE || wasAborted ? "output" : "error",
        text: pendingErrorText,
        timestamp: Date.now(),
      });
    } else if (wasAborted && !pendingAssistantText && !fallbackResultText) {
      appendToHistory(store, {
        type: "output",
        text: CANCELLED_AGENT_MESSAGE,
        timestamp: Date.now(),
      });
    }

    clearTransientShellState(store);
    setProcessing(store, false);
  }

  store.update({
    mode: "shell",
    shell: {
      modules: modules.map((module) => module.id),
      tools: tools.map(({ tool }) => tool.name),
      focusedModule: null,
      target: opts.target ?? null,
      workspace: opts.workspace ?? null,
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

  const isClaudeBackend = (opts.config.agentRuntimeBackend ?? "claude") === "claude";
  if (isClaudeBackend) {
    const { hasAnthropicCredentials, runCredentialPrompt } = await import("../ui/setup.js");
    if (!hasAnthropicCredentials(opts.config.agentRuntimeConfig?.apiKey)) {
      const credentialOutcome = await runCredentialPrompt(store, "shell");
      if (credentialOutcome.action === "cancel") {
        assistantDisabledReason = CREDENTIALS_CANCELLED_MESSAGE;
        appendToHistory(store, {
          type: "output",
          text: assistantDisabledReason,
          timestamp: Date.now(),
        });
      } else if (credentialOutcome.choice.kind === "api-key") {
        opts.config.agentRuntimeConfig = {
          ...opts.config.agentRuntimeConfig,
          apiKey: credentialOutcome.choice.value,
        };
        process.env["ANTHROPIC_API_KEY"] = credentialOutcome.choice.value;
      } else if (credentialOutcome.choice.kind === "oauth-token") {
        process.env["ANTHROPIC_OAUTH_TOKEN"] = credentialOutcome.choice.value;
      }
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
  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const rlCtx: ShellContext = { focusedModule: null, workspaceManager };
  let rlState: ShellState = {
    modules: modules.map((module) => module.id),
    tools: tools.map(({ tool }) => tool.name),
    focusedModule: null,
    target: opts.target ?? null,
    workspace: opts.workspace ?? null,
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

  const updatePrompt = (): void => {
    rl.setPrompt(buildShellPrompt(rlCtx.focusedModule));
  };

  console.error(formatWelcome(core, opts));
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
      if (localResult !== undefined) {
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
        if (localResult.output) {
          process.stdout.write(`${localResult.output}\n`);
        }
        rl.prompt();
        continue;
      }

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
        for await (const message of currentSession.query(input)) {
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
 * Three-layer input router:
 *   1. Slash commands (/help, /use, /options, /set, ...) — local only
 *   2. Direct tool dispatch (sast:scan ., semgrep ., scan .) — local only
 *   3. Natural language — undefined falls through to AgentSession
 */
function routeInput(
  input: string,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
  shellState: ShellState,
): LocalCommandResult | undefined {
  const trimmed = input.trim();
  const lower = trimmed.toLowerCase();

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

  return undefined;
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
      return {
        setFocus: moduleId,
        output: `Focused on ${mod.displayName}. ${mod.tools.length} tools available.`,
      };
    }

    case "back":
      if (ctx.focusedModule) {
        return { setFocus: null, output: "Returned to top level." };
      }
      return { output: "Already at top level." };

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
      return handleConfigCommand(args);

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

    case "threats": {
      const sub = args[0]?.toLowerCase();

      // /threats edit — open the threat model editor
      if (sub === "edit") {
        if (!opts.target) return { output: "No target set. Use /target <path> first." };
        const repoRoot = path.resolve(opts.target);
        return {
          output: "Opening threat model editor...",
          asyncExecute: async () => {
            const { loadPersistentThreatModel, savePersistentThreatModel } = await import(
              "../threat-model-renderer.js"
            );
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

  if (cmd.toLowerCase() === "run" && args.length > 0) {
    return resolveToolExecution(args[0]!, args.slice(1), core, opts, ctx, shellState);
  }

  if (cmd.includes(":")) {
    return resolveToolExecution(cmd, args, core, opts, ctx, shellState);
  }

  if (ctx.focusedModule) {
    const qualifiedName = `${ctx.focusedModule}:${cmd}`;
    if (core.registry.resolveTool(qualifiedName)) {
      return resolveToolExecution(qualifiedName, args, core, opts, ctx, shellState);
    }
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
  "  /config              Show effective config (secrets redacted)",
  "  /config path         Show config file paths",
  "  /config get <key>    Get a value (supports dotted paths)",
  "  /config set <key> <value>   Set a value in the global config",
].join("\n");

function handleConfigCommand(args: string[]): LocalCommandResult {
  const sub = (args[0] ?? "").toLowerCase();

  if (!sub || sub === "list" || sub === "show") {
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
    if (!key || !raw) return { output: "Usage: /config set <key> <value>" };
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
        ["/back", "Return to top level"],
        ["/options [tool]", "Show tool options"],
        ["/set <key> <value>", "Set a tool option"],
        ["/config", "Show global config (secrets redacted)"],
        ["/config get|set|path", "Read/update ~/.kuzushi/config.json"],
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
  finalizeAssistantText,
  formatHelp,
  formatModuleInfo,
  formatModuleList,
  formatOptions,
  formatTools,
  formatWelcome,
  handleLocalCommand: routeInput,
  handleSlashCommand,
  loadShellCommandHistory,
  resolveDirectToolDispatch,
  saveShellCommandHistory,
};
