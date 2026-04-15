/**
 * Headless run executor — executes a single module tool invocation
 * without any interactive UI. Used by `kuzushi run <module:action>`.
 *
 * Output modes:
 *   --json   → structured JSON to stdout
 *   --quiet  → no output, just exit code
 *   (default) → human-readable text output
 *
 * Exit codes:
 *   0 — tool executed successfully (ok: true)
 *   1 — tool execution failed (ok: false) or tool not found
 *   2 — usage error (bad arguments, unknown module/tool)
 */

import { CopilotCore } from "./core.js";
import type { ToolResult, ToolExecutionContext } from "../modules/types.js";
import type { AgentRuntime } from "../agent-runtime/types.js";
import type { MessageBus } from "../bus/types.js";
import type { KuzushiConfig } from "../types.js";

export interface RunOptions {
  /** Fully-qualified tool name: "module:action" */
  toolName: string;
  /** Tool input (parsed from CLI args or --input JSON) */
  input: Record<string, unknown>;
  /** Output format */
  format: "text" | "json" | "quiet";
  /** Current working directory (for target resolution) */
  cwd: string;
  /** Target override (repo path, host, etc.) */
  target?: string;
  /** Workspace ID to write results to */
  workspaceId?: string;
  /** Agent runtime */
  runtime: AgentRuntime;
  /** Message bus */
  bus: MessageBus;
  /** Config */
  config: KuzushiConfig;
  /** Data directory for module persistence */
  dataDir: string;
  /** Additional modules to load beyond core */
  modules?: string[];
}

export interface RunResult {
  ok: boolean;
  toolResult: ToolResult;
  exitCode: number;
}

/**
 * Execute a module tool headlessly and return the result.
 *
 * This is the core function behind `kuzushi run`. It:
 * 1. Initializes CopilotCore with the core SAST module
 * 2. Loads any additional requested modules
 * 3. Resolves the tool by qualified name
 * 4. Executes the tool
 * 5. Returns the result with appropriate exit code
 */
export async function executeRun(opts: RunOptions): Promise<RunResult> {
  const core = new CopilotCore({
    runtime: opts.runtime,
    bus: opts.bus,
    config: opts.config,
    dataDir: opts.dataDir,
    modules: opts.modules,
  });

  try {
    await core.init();

    // Check tool exists before executing
    const resolved = core.registry.resolveTool(opts.toolName);
    if (!resolved) {
      return {
        ok: false,
        toolResult: {
          ok: false,
          output: `Unknown tool: "${opts.toolName}"\n\nAvailable tools:\n${formatAvailableTools(core)}`,
        },
        exitCode: 2,
      };
    }

    // Check headless compatibility
    if (!resolved.tool.headless) {
      return {
        ok: false,
        toolResult: {
          ok: false,
          output:
            `Tool "${opts.toolName}" requires interactive confirmation and cannot run in headless mode.\n` +
            `Use "kuzushi shell" for interactive operations.`,
        },
        exitCode: 2,
      };
    }

    const ctxOverrides: Partial<ToolExecutionContext> = {
      cwd: opts.cwd,
      target: opts.target,
      workspaceId: opts.workspaceId,
    };

    const toolResult = await core.executeTool(opts.toolName, opts.input, ctxOverrides);

    return {
      ok: toolResult.ok,
      toolResult,
      exitCode: toolResult.ok ? 0 : 1,
    };
  } finally {
    await core.dispose();
  }
}

/**
 * Format the run result for output to stdout.
 */
export function formatRunOutput(result: RunResult, format: "text" | "json" | "quiet"): string {
  switch (format) {
    case "json":
      return JSON.stringify(
        {
          ok: result.toolResult.ok,
          output: result.toolResult.output,
          data: result.toolResult.data ?? null,
          costUsd: result.toolResult.costUsd ?? null,
        },
        null,
        2,
      );

    case "quiet":
      return "";

    case "text":
    default:
      return result.toolResult.output;
  }
}

/**
 * Format available tools for help text.
 */
function formatAvailableTools(core: CopilotCore): string {
  const tools = core.registry.allTools({ headlessOnly: true });
  if (tools.length === 0) return "  (no tools available)";

  return tools
    .map(({ tool }) => `  ${tool.name} — ${tool.description.split(".")[0]}`)
    .join("\n");
}

/**
 * Parse a "key=value" style positional argument into the input object.
 * Supports:
 *   target=./repo          → { target: "./repo" }
 *   severity=critical,high → { severity: ["critical", "high"] }
 *   verify=true            → { verify: true }
 *   preset=deep            → { preset: "deep" }
 */
export function parseToolArgs(args: string[]): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const arg of args) {
    const eqIdx = arg.indexOf("=");
    if (eqIdx === -1) {
      // Bare positional arg — treat as "target"
      if (!result.target) {
        result.target = arg;
      }
      continue;
    }

    const key = arg.slice(0, eqIdx);
    const rawValue = arg.slice(eqIdx + 1);

    // Parse value types
    if (rawValue === "true") {
      result[key] = true;
    } else if (rawValue === "false") {
      result[key] = false;
    } else if (rawValue.includes(",")) {
      result[key] = rawValue.split(",").map((v) => v.trim());
    } else if (/^\d+$/.test(rawValue)) {
      result[key] = parseInt(rawValue, 10);
    } else if (/^\d+\.\d+$/.test(rawValue)) {
      result[key] = parseFloat(rawValue);
    } else {
      result[key] = rawValue;
    }
  }

  return result;
}
