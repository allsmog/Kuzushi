/**
 * Interactive copilot shell — the default `kuzushi` experience.
 *
 * In TTY mode: renders through the Ink terminal UI (same infrastructure as
 * `kuzushi scan`). Sets the UIStore to "shell" mode and lets the CopilotShell
 * Ink component handle rendering, input, and display.
 *
 * In non-TTY mode (piped, CI): falls back to readline for basic interactivity.
 *
 * Command dispatch lives here (not in the component) to keep React pure.
 */

import path from "node:path";
import { existsSync, mkdirSync } from "node:fs";
import { CopilotCore } from "./core.js";
import { executeRun, formatRunOutput, parseToolArgs } from "./run.js";
import type { AgentRuntime } from "../agent-runtime/types.js";
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
 * TTY → Ink UI (CopilotShell component).
 * Non-TTY → readline fallback for piped/CI usage.
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

  if (process.stdout.isTTY && process.stdin.isTTY) {
    await startInkShell(core, opts, bus);
  } else {
    await startReadlineShell(core, opts, bus);
  }
}

/**
 * Ink-powered shell (TTY mode) — full rich rendering.
 */
async function startInkShell(
  core: CopilotCore,
  opts: ShellOptions,
  bus: import("../bus/types.js").MessageBus,
): Promise<void> {
  const { createUIRenderer } = await import("../ui/render.js");
  const renderer = await createUIRenderer();
  const { store, cleanup: cleanupUI } = renderer;

  let focusedModule: string | null = null;
  let target = opts.target ?? null;

  const exitPromise = new Promise<void>((resolveExit) => {

    function updateShellState(overrides: Partial<{
      history: ShellHistoryEntry[];
      processing: boolean;
      focusedModule: string | null;
      target: string | null;
    }> = {}): void {
      const modules = core.listModules();
      const tools = core.registry.allTools();
      const currentShell = store.getState().shell;

      store.update({
        shell: {
          modules: modules.map((m) => m.id),
          tools: tools.map(({ tool }) => tool.name),
          focusedModule: overrides.focusedModule ?? focusedModule,
          target: overrides.target ?? target,
          workspace: opts.workspace ?? null,
          history: overrides.history ?? currentShell?.history ?? [],
          processing: overrides.processing ?? false,
          onInput: handleInput,
          onExit: handleExit,
        },
      });
    }

    function appendOutput(text: string, type: "output" | "error" = "output"): void {
      const currentShell = store.getState().shell;
      const history = [...(currentShell?.history ?? [])];
      history.push({ type, text, timestamp: Date.now() });
      updateShellState({ history, processing: false });
    }

    async function handleInput(input: string): Promise<void> {
      try {
        const result = await handleCommand(input, core, { ...opts, target: target ?? undefined }, focusedModule);

        if (result.exit) {
          handleExit();
          return;
        }

        if (result.setFocus !== undefined) {
          focusedModule = result.setFocus;
        }
        if (result.setTarget !== undefined) {
          target = result.setTarget;
        }

        if (result.output) {
          appendOutput(result.output);
        } else {
          updateShellState({ processing: false });
        }
      } catch (err) {
        appendOutput(err instanceof Error ? err.message : String(err), "error");
      }
    }

    function handleExit(): void {
      resolveExit();
    }

    // Initialize shell mode
    store.update({ mode: "shell" });
    updateShellState();
  });

  await exitPromise;
  await core.dispose();
  await bus.close();
  cleanupUI();
}

/**
 * Readline-based shell (non-TTY fallback) — for piped input and CI.
 */
async function startReadlineShell(
  core: CopilotCore,
  opts: ShellOptions,
  bus: import("../bus/types.js").MessageBus,
): Promise<void> {
  const { createInterface } = await import("node:readline");

  let focusedModule: string | null = null;

  // Print banner to stderr so it doesn't pollute piped stdout
  const modules = core.listModules();
  const toolCount = core.registry.allTools().length;
  console.error(`kuzushi shell (non-TTY mode)`);
  console.error(`modules: ${modules.map((m) => m.id).join(", ")}  tools: ${toolCount}`);
  if (opts.target) console.error(`target: ${opts.target}`);

  const rl = createInterface({ input: process.stdin, output: process.stderr });
  const prompt = () => {
    const prefix = focusedModule ? `kuzushi/${focusedModule}> ` : "kuzushi> ";
    rl.setPrompt(prefix);
    rl.prompt();
  };

  prompt();

  for await (const line of rl) {
    const input = line.trim();
    if (!input) { prompt(); continue; }

    try {
      const result = await handleCommand(input, core, opts, focusedModule);

      if (result.exit) break;
      if (result.setFocus !== undefined) focusedModule = result.setFocus;
      if (result.output) console.log(result.output);
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    }

    prompt();
  }

  rl.close();
  await core.dispose();
  await bus.close();
}

// ---------------------------------------------------------------------------
// Command handling (pure logic, no UI)
// ---------------------------------------------------------------------------

interface CommandResult {
  output?: string;
  exit?: boolean;
  setFocus?: string | null;
  setTarget?: string | null;
}

async function handleCommand(
  input: string,
  core: CopilotCore,
  opts: ShellOptions,
  focusedModule: string | null,
): Promise<CommandResult> {
  const [cmd, ...args] = input.split(/\s+/);
  const lower = cmd.toLowerCase();

  // Exit
  if (lower === "exit" || lower === "quit" || lower === "q") {
    return { exit: true };
  }

  // Help
  if (lower === "help" || lower === "?") {
    return { output: formatHelp() };
  }

  // Module list
  if (lower === "modules" || (lower === "module" && (!args[0] || args[0] === "list"))) {
    return { output: formatModuleList(core) };
  }

  // Module info
  if (lower === "module" && args[0] === "info" && args[1]) {
    return { output: formatModuleInfo(core, args[1]) };
  }

  // Module tools
  if (lower === "tools" || (lower === "module" && args[0] === "tools")) {
    return { output: formatTools(core) };
  }

  // Use — focus on a module
  if (lower === "use") {
    const moduleId = args[0];
    if (!moduleId) return { output: "Usage: use <module-id>" };
    if (!core.hasModule(moduleId)) {
      return { output: `Unknown module: "${moduleId}". Type "modules" to see available modules.` };
    }
    const mod = core.registry.get(moduleId);
    return {
      setFocus: moduleId,
      output: `Focused on ${mod.displayName}. Tools: ${mod.tools.map((t) => t.name).join(", ")}`,
    };
  }

  // Back — unfocus
  if (lower === "back") {
    return focusedModule
      ? { setFocus: null, output: "Returned to top level." }
      : {};
  }

  // Target
  if (lower === "target") {
    const newTarget = args[0];
    if (newTarget) {
      return { setTarget: newTarget, output: `Target set to: ${newTarget}` };
    }
    return { output: opts.target ? `Current target: ${opts.target}` : "No target set. Usage: target <path>" };
  }

  // Run — execute a tool
  if (lower === "run") {
    return runToolCommand(args, core, opts, focusedModule);
  }

  // Direct tool invocation: "sast:scan ./repo" or "scan ./repo" when focused
  if (input.includes(":") || focusedModule) {
    let toolName = cmd;
    if (focusedModule && !toolName.includes(":")) {
      toolName = `${focusedModule}:${toolName}`;
    }
    const resolved = core.registry.resolveTool(toolName);
    if (resolved) {
      return runToolCommand([toolName, ...args], core, opts, focusedModule);
    }
  }

  return { output: `Unknown command: "${cmd}". Type "help" for available commands.` };
}

async function runToolCommand(
  args: string[],
  core: CopilotCore,
  opts: ShellOptions,
  focusedModule: string | null,
): Promise<CommandResult> {
  let toolName = args[0];
  if (!toolName) return { output: "Usage: run <module:action> [args...]" };

  if (focusedModule && !toolName.includes(":")) {
    toolName = `${focusedModule}:${toolName}`;
  }

  const toolArgs = parseToolArgs(args.slice(1));
  if (opts.target && !toolArgs.target) {
    toolArgs.target = opts.target;
  }

  const bus = createBus(opts.config);
  const dataDir = path.resolve(process.cwd(), ".kuzushi");

  const result = await executeRun({
    toolName,
    input: toolArgs,
    format: "text",
    cwd: process.cwd(),
    target: toolArgs.target as string | undefined,
    workspaceId: opts.workspace,
    runtime: opts.runtime,
    bus,
    config: opts.config,
    dataDir,
    modules: opts.modules,
  });

  await bus.close();

  const output = formatRunOutput(result, "text");
  return { output: output || (result.ok ? "Done." : `Tool returned error (exit code ${result.exitCode}).`) };
}

// ---------------------------------------------------------------------------
// Formatters (plain text — the Ink component renders them)
// ---------------------------------------------------------------------------

function formatHelp(): string {
  return [
    "",
    "Commands:",
    "",
    "  modules              List loaded modules",
    "  module info <id>     Detailed module info",
    "  tools                List all available tools",
    "  use <module>         Focus on a module (enables shorthand)",
    "  back                 Return to top level",
    "  run <tool> [args]    Execute a tool (e.g. run sast:scan ./repo)",
    "  target <path>        Set/show the active target",
    "  help                 Show this help",
    "  exit                 Exit the shell",
    "",
    "  When focused on a module, tool names can be shortened:",
    "    kuzushi/sast> run scan ./repo  =>  runs sast:scan",
    "",
  ].join("\n");
}

function formatModuleList(core: CopilotCore): string {
  const modules = core.listModules();
  if (modules.length === 0) return "No modules loaded.";

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
  if (!core.hasModule(id)) return `Unknown module: "${id}"`;

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
  if (tools.length === 0) return "No tools available.";

  const lines = [""];
  for (const { tool } of tools) {
    const mode = tool.headless ? "[h]" : "[i]";
    lines.push(`  ${tool.name} ${mode} — ${tool.description.split(".")[0]}`);
  }
  lines.push("");
  return lines.join("\n");
}
