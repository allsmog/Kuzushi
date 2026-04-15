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

import path from "node:path";
import { existsSync, mkdirSync } from "node:fs";
import { CopilotCore } from "./core.js";
import type { AgentRuntime, AgentMessage } from "../agent-runtime/types.js";
import type { KuzushiConfig } from "../types.js";
import type { ShellHistoryEntry } from "../ui/state.js";
import { createBus } from "../bus/index.js";

export interface ShellOptions {
  config: KuzushiConfig;
  runtime: AgentRuntime;
  workspace?: string;
  modules?: string[];
  target?: string;
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
    await startInkShell(core, opts, bus, systemPrompt);
  } else {
    await startReadlineShell(core, opts, bus, systemPrompt);
  }
}

// ---------------------------------------------------------------------------
// Ink-powered shell (TTY) — conversation stream rendered through React
// ---------------------------------------------------------------------------

async function startInkShell(
  core: CopilotCore,
  opts: ShellOptions,
  bus: import("../bus/types.js").MessageBus,
  systemPrompt: string,
): Promise<void> {
  const { createUIRenderer } = await import("../ui/render.js");
  const renderer = await createUIRenderer();
  const { store, cleanup: cleanupUI } = renderer;

  // Create a persistent agent session — this is the copilot brain.
  // The session subprocess stays alive across prompts.
  const session = opts.runtime.createSession?.({
    cwd: opts.target ? path.resolve(opts.target) : process.cwd(),
    model: opts.config.model,
    allowedTools: ["Read", "Glob", "Grep", "Bash", "LS"],
    permissionMode: "default",
    systemPromptPrefix: systemPrompt,
    effort: "high",
  });

  const modules = core.listModules();
  const tools = core.registry.allTools();

  let alive = true;
  const shellCtx: ShellContext = { focusedModule: null };
  const exitPromise = new Promise<void>((resolve) => {

    function handleExit(): void {
      alive = false;
      resolve();
    }

    async function handleInput(input: string): Promise<void> {
      if (!alive) return;

      // Local commands — handled without the LLM
      const localResult = handleLocalCommand(input, core, opts, shellCtx);
      if (localResult !== undefined) {
        if (localResult.exit) {
          handleExit();
          return;
        }
        if (localResult.setFocus !== undefined) {
          shellCtx.focusedModule = localResult.setFocus;
          // Update ShellState so the Ink component can show focused prompt
          const currentShell = store.getState().shell;
          if (currentShell) {
            store.update({ shell: { ...currentShell, focusedModule: localResult.setFocus } });
          }
        }
        if (localResult.asyncExecute) {
          // Tool execution — run async, append result when done
          localResult.asyncExecute().then((output) => {
            appendToHistory(store, { type: "output", text: output, timestamp: Date.now() });
            setProcessing(store, false);
          }).catch((err) => {
            appendToHistory(store, { type: "error", text: err instanceof Error ? err.message : String(err), timestamp: Date.now() });
            setProcessing(store, false);
          });
          return;
        }
        if (localResult.output) {
          appendToHistory(store, { type: "output", text: localResult.output, timestamp: Date.now() });
        }
        setProcessing(store, false);
        return;
      }

      // Everything else goes to the AgentSession
      if (!session) {
        appendToHistory(store, {
          type: "error",
          text: "No agent session available.\nSet ANTHROPIC_API_KEY or use Claude Code OAuth to enable the copilot.",
          timestamp: Date.now(),
        });
        setProcessing(store, false);
        return;
      }

      // Stream the agent response
      try {
        let resultText = "";
        let costUsd: number | undefined;

        for await (const message of session.query(input)) {
          if (!alive) break;

          switch (message.type) {
            case "assistant": {
              // Extract text blocks from assistant content
              for (const block of message.content) {
                if ((block as { type: string }).type === "text" && (block as { text: string }).text) {
                  // Don't append yet — wait for the result to get the full response
                }
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
              if (message.subtype === "success") {
                resultText = (message as { result: string }).result;
                costUsd = (message as { totalCostUsd?: number }).totalCostUsd;
              } else {
                const errors = (message as { errors: string[] }).errors;
                resultText = `Error: ${errors.join("; ")}`;
              }
              break;
            }
          }
        }

        // Append the final response to history
        if (resultText) {
          appendToHistory(store, {
            type: "output",
            text: resultText,
            timestamp: Date.now(),
          });
        }
      } catch (err) {
        appendToHistory(store, {
          type: "error",
          text: err instanceof Error ? err.message : String(err),
          timestamp: Date.now(),
        });
      }

      clearToolActivity(store);
      setProcessing(store, false);
    }

    // Initialize shell mode — must be after function definitions
    store.update({
      mode: "shell",
      shell: {
        modules: modules.map((m) => m.id),
        tools: tools.map(({ tool }) => tool.name),
        focusedModule: null,
        target: opts.target ?? null,
        workspace: opts.workspace ?? null,
        history: [{ type: "output" as const, text: formatWelcome(core, opts), timestamp: Date.now() }],
        processing: false,
        onInput: handleInput,
        onExit: handleExit,
      },
    });
  });

  await exitPromise;
  await session?.close();
  await core.dispose();
  await bus.close();
  cleanupUI();
}

// ---------------------------------------------------------------------------
// Readline fallback (non-TTY) — for piped input and CI
// ---------------------------------------------------------------------------

async function startReadlineShell(
  core: CopilotCore,
  opts: ShellOptions,
  bus: import("../bus/types.js").MessageBus,
  systemPrompt: string,
): Promise<void> {
  const { createInterface } = await import("node:readline");

  const session = opts.runtime.createSession?.({
    cwd: opts.target ? path.resolve(opts.target) : process.cwd(),
    model: opts.config.model,
    allowedTools: ["Read", "Glob", "Grep", "Bash", "LS"],
    permissionMode: "default",
    systemPromptPrefix: systemPrompt,
    effort: "high",
  });

  const modules = core.listModules();
  console.error(`kuzushi shell (non-TTY mode)`);
  console.error(`modules: ${modules.map((m) => m.id).join(", ")}  tools: ${core.registry.allTools().length}`);
  if (opts.target) console.error(`target: ${opts.target}`);

  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const rlCtx: ShellContext = { focusedModule: null };

  const updatePrompt = () => {
    const prefix = rlCtx.focusedModule ? `kuzushi/${rlCtx.focusedModule}> ` : "kuzushi> ";
    rl.setPrompt(prefix);
  };
  updatePrompt();
  rl.prompt();

  for await (const line of rl) {
    const input = line.trim();
    if (!input) { rl.prompt(); continue; }

    // Local commands first
    const localResult = handleLocalCommand(input, core, opts, rlCtx);
    if (localResult?.exit) break;
    if (localResult !== undefined) {
      if (localResult.setFocus !== undefined) {
        rlCtx.focusedModule = localResult.setFocus;
        updatePrompt();
      }
      if (localResult.asyncExecute) {
        try {
          const output = await localResult.asyncExecute();
          console.log(output);
        } catch (err) {
          console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
        }
        rl.prompt();
        continue;
      }
      if (localResult.output) console.log(localResult.output);
      rl.prompt();
      continue;
    }

    // Natural language → AgentSession
    if (!session) {
      console.log("No agent session available. Set ANTHROPIC_API_KEY or use Claude Code OAuth.");
      rl.prompt();
      continue;
    }

    try {
      for await (const message of session.query(input)) {
        if (message.type === "tool-progress") {
          process.stderr.write(`  [${message.toolName}] ${message.elapsedSeconds}s\r`);
        }
        if (message.type === "result") {
          if (message.subtype === "success") {
            console.log((message as { result: string }).result);
          } else {
            console.error(`Error: ${(message as { errors: string[] }).errors.join("; ")}`);
          }
        }
      }
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    }

    rl.prompt();
  }

  rl.close();
  await session?.close();
  await core.dispose();
  await bus.close();
}

// ---------------------------------------------------------------------------
// Store helpers — update shell state without re-creating the whole object
// ---------------------------------------------------------------------------

function appendToHistory(
  store: import("../ui/state.js").UIStore,
  entry: ShellHistoryEntry,
): void {
  const shell = store.getState().shell;
  if (!shell) return;
  store.update({
    shell: {
      ...shell,
      history: [...shell.history, entry],
    },
  });
}

function setProcessing(
  store: import("../ui/state.js").UIStore,
  processing: boolean,
): void {
  const shell = store.getState().shell;
  if (!shell) return;
  store.update({
    shell: { ...shell, processing },
  });
}

function updateToolActivity(
  store: import("../ui/state.js").UIStore,
  toolName: string,
  elapsedSeconds: number,
): void {
  const shell = store.getState().shell;
  if (!shell) return;
  store.update({
    shell: {
      ...shell,
      currentTool: { name: toolName, elapsedSeconds },
    },
  });
}

function updateToolSummary(
  store: import("../ui/state.js").UIStore,
  summary: string,
): void {
  const shell = store.getState().shell;
  if (!shell) return;
  // Append tool summary as a history entry for context
  store.update({
    shell: {
      ...shell,
      history: [...shell.history, { type: "output" as const, text: `  ${summary}`, timestamp: Date.now() }],
      currentTool: undefined,
    },
  });
}

function clearToolActivity(
  store: import("../ui/state.js").UIStore,
): void {
  const shell = store.getState().shell;
  if (!shell) return;
  store.update({
    shell: { ...shell, currentTool: undefined },
  });
}

// ---------------------------------------------------------------------------
// Local commands — handled without the LLM
// ---------------------------------------------------------------------------

interface ShellContext {
  focusedModule: string | null;
}

interface LocalCommandResult {
  output?: string;
  exit?: boolean;
  /** Update focusedModule. */
  setFocus?: string | null;
  /** Async tool execution needed — returns a promise of output. */
  asyncExecute?: () => Promise<string>;
}

/**
 * Handle local commands. Returns:
 *   - a LocalCommandResult if handled
 *   - undefined if the input is NOT a local command (should go to AgentSession)
 */
function handleLocalCommand(
  input: string,
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
): LocalCommandResult | undefined {
  const trimmed = input.trim();
  const lower = trimmed.toLowerCase();
  const [cmd, ...args] = trimmed.split(/\s+/);

  // Exit
  if (lower === "exit" || lower === "quit" || lower === "q") {
    return { exit: true };
  }

  // Help
  if (lower === "help" || lower === "/help" || lower === "?") {
    return { output: formatHelp(core, opts) };
  }

  // Modules
  if (lower === "modules" || lower === "/modules" ||
      (cmd.toLowerCase() === "module" && (!args[0] || args[0] === "list"))) {
    return { output: formatModuleList(core) };
  }

  // Module info
  if (cmd.toLowerCase() === "module" && args[0] === "info" && args[1]) {
    return { output: formatModuleInfo(core, args[1]) };
  }

  // Tools
  if (lower === "tools" || lower === "/tools") {
    return { output: formatTools(core) };
  }

  // Target
  if (cmd.toLowerCase() === "target" || cmd.toLowerCase() === "/target") {
    const newTarget = args[0];
    if (newTarget) {
      opts.target = newTarget;
      return { output: `Target set to: ${newTarget}` };
    }
    return { output: opts.target ? `Current target: ${opts.target}` : "No target set. Usage: target <path>" };
  }

  // Use — focus on a module
  if (cmd.toLowerCase() === "use") {
    const moduleId = args[0];
    if (!moduleId) return { output: "Usage: use <module>" };
    if (!core.hasModule(moduleId)) {
      return { output: `Unknown module: "${moduleId}". Type "modules" to list available.` };
    }
    const mod = core.registry.get(moduleId);
    const toolNames = mod.tools.map((t) => t.name).join(", ");
    return { setFocus: moduleId, output: `Focused on ${mod.displayName}. Tools: ${toolNames}` };
  }

  // Back — unfocus module
  if (lower === "back") {
    if (ctx.focusedModule) {
      return { setFocus: null, output: "Returned to top level." };
    }
    return { output: "Already at top level." };
  }

  // Run — explicit tool execution: "run sast:scan ." or "run scan ." (when focused)
  if (cmd.toLowerCase() === "run" && args.length > 0) {
    return resolveToolExecution(args[0], args.slice(1), core, opts, ctx);
  }

  // Direct tool invocation — "sast:scan ." (qualified name with colon)
  if (cmd.includes(":")) {
    return resolveToolExecution(cmd, args, core, opts, ctx);
  }

  // Focused shorthand — "scan ." when focused on sast → "sast:scan ."
  if (ctx.focusedModule) {
    const qualifiedName = `${ctx.focusedModule}:${cmd}`;
    const resolved = core.registry.resolveTool(qualifiedName);
    if (resolved) {
      return resolveToolExecution(qualifiedName, args, core, opts, ctx);
    }
  }

  // Global shorthand — "scan ." at top level, search all modules for a
  // tool ending in ":scan". If exactly one match, run it.
  const allTools = core.registry.allTools();
  const actionName = cmd.toLowerCase();
  const matches = allTools.filter(({ tool }) => {
    const action = tool.name.split(":")[1];
    return action?.toLowerCase() === actionName;
  });
  if (matches.length === 1) {
    return resolveToolExecution(matches[0].tool.name, args, core, opts, ctx);
  }

  // Not a local command — pass to AgentSession
  return undefined;
}

/**
 * Build a tool execution result — runs the tool via executeRun().
 */
function resolveToolExecution(
  toolName: string,
  toolArgs: string[],
  core: CopilotCore,
  opts: ShellOptions,
  ctx: ShellContext,
): LocalCommandResult {
  // Resolve shorthand when focused
  if (!toolName.includes(":") && ctx.focusedModule) {
    toolName = `${ctx.focusedModule}:${toolName}`;
  }

  // Check tool exists
  const resolved = core.registry.resolveTool(toolName);
  if (!resolved) {
    return { output: `Unknown tool: "${toolName}". Type "tools" to list available.` };
  }

  return {
    asyncExecute: async () => {
      const { executeRun, formatRunOutput, parseToolArgs } = await import("./run.js");
      const parsedArgs = parseToolArgs(toolArgs);
      if (opts.target && !parsedArgs.target) {
        parsedArgs.target = opts.target;
      }

      const bus = createBus(opts.config);
      const dataDir = path.resolve(process.cwd(), ".kuzushi");

      const result = await executeRun({
        toolName,
        input: parsedArgs,
        format: "text",
        cwd: process.cwd(),
        target: parsedArgs.target as string | undefined,
        workspaceId: opts.workspace,
        runtime: opts.runtime,
        bus,
        config: opts.config,
        dataDir,
        modules: opts.modules,
      });

      await bus.close();
      const output = formatRunOutput(result, "text");
      return output || (result.ok ? "Done." : `Tool failed (exit code ${result.exitCode}).`);
    },
  };
}

function formatHelp(core: CopilotCore, opts: ShellOptions): string {
  const modules = core.listModules();
  const toolCount = core.registry.allTools().length;

  const lines = [
    "",
    "  Kuzushi — security-native AI operating environment",
    "",
    `  Modules: ${modules.map((m) => m.id).join(", ") || "none"}`,
    `  Tools:   ${toolCount} available`,
    opts.target ? `  Target:  ${opts.target}` : "",
    "",
    "  Commands:",
    "    help                Show this help",
    "    modules             List loaded modules",
    "    module info <id>    Detailed module info",
    "    tools               List all available tools",
    "    use <module>        Focus on a module (shorthand commands)",
    "    back                Return to top level",
    "    run <tool> [args]   Execute a tool (e.g. run sast:scan .)",
    "    target <path>       Set/show the active target",
    "    exit                Exit the shell",
    "",
    "  Tool shortcuts:",
    "    sast:scan .         Direct tool invocation",
    "    use sast; scan .    Shorthand when focused",
    "",
    "  Or just type naturally — the agent handles the rest.",
    "  Examples:",
    "    > What's the attack surface of this repo?",
    "    > Hunt for SSRF chains in ./src",
    "    > Are we PCI DSS compliant?",
    "",
  ].filter(Boolean);

  return lines.join("\n");
}

function formatModuleList(core: CopilotCore): string {
  const modules = core.listModules();
  if (modules.length === 0) return "  No modules loaded.";

  const lines = [""];
  for (const mod of modules) {
    const tools = core.registry.moduleTools(mod.id).map((t) => t.name.split(":")[1]).join(", ");
    lines.push(`  ${mod.id} [${mod.category}] — ${mod.description.split(".")[0]}`);
    if (tools) lines.push(`    tools: ${tools}`);
  }
  lines.push("");
  return lines.join("\n");
}

function formatModuleInfo(core: CopilotCore, id: string): string {
  if (!core.hasModule(id)) return `  Unknown module: "${id}"`;

  const mod = core.registry.get(id);
  const lines = [
    "",
    `  ${mod.displayName} v${mod.version} [${mod.category}]`,
    `  ${mod.description}`,
    "",
  ];
  for (const tool of mod.tools) {
    const mode = tool.headless ? "[headless]" : "[interactive]";
    lines.push(`  ${tool.name} ${mode}`);
    lines.push(`    ${tool.description.split(".")[0]}.`);
  }
  lines.push("");
  return lines.join("\n");
}

function formatTools(core: CopilotCore): string {
  const tools = core.registry.allTools();
  if (tools.length === 0) return "  No tools available.";

  const lines = [""];
  for (const { tool } of tools) {
    const mode = tool.headless ? "[h]" : "[i]";
    lines.push(`  ${tool.name} ${mode} — ${tool.description.split(".")[0]}`);
  }
  lines.push("");
  return lines.join("\n");
}

/**
 * Welcome message shown when the shell starts.
 */
export function formatWelcome(core: CopilotCore, opts: ShellOptions): string {
  const modules = core.listModules();
  const toolCount = core.registry.allTools().length;

  const lines = [
    `  modules: ${modules.map((m) => m.id).join(", ") || "none"}  tools: ${toolCount}`,
  ];
  if (opts.target) lines.push(`  target:  ${opts.target}`);
  if (opts.workspace) lines.push(`  workspace: ${opts.workspace}`);
  lines.push("");
  lines.push('  Type "help" for commands, or just describe what you need.');
  return lines.join("\n");
}
