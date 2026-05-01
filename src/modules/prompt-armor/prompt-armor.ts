/**
 * PromptArmor — LLM red-team CopilotModule.
 *
 * Thin wrapper that exposes the `promptarmor-plugin` Claude Code plugin as
 * module:action tools callable from shell and run modes. The plugin ships
 * 6 slash commands (`scan`, `analyze`, `attack`, `diff`, `report`, `config`)
 * plus an MCP server; each wrapper tool drives the corresponding command
 * by handing the target to a Claude Code subprocess with the plugin loaded.
 *
 * Safety: `prompt-armor:scan` and `prompt-armor:attack` can generate real
 * traffic against live endpoints. Both require an explicit
 * `authorized: true` input flag before they'll run — otherwise they refuse
 * with a CLI-safe error. `analyze`, `diff`, `report`, and `config` are
 * read-only/descriptive and have no such gate.
 */

import { existsSync } from "node:fs";
import path from "node:path";
import { resolveDefaultReadOnlyTools } from "../../agent-runtime/execution.js";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { forwardSubAgentMessage } from "../../agents/tasks/forward-subagent-output.js";
import { resolvePromptArmorPluginPath } from "../../agents/tasks/prompt-armor/resolve-promptarmor-plugin.js";
import { resolveRepo } from "../../cli/shared.js";
import { createLogger } from "../../logger.js";
import { toErrorMessage } from "../../utils.js";
import type { CopilotModule, ExecutionContext, ModuleTool, ToolResult } from "../types.js";

const log = createLogger({ stage: "prompt-armor" });

type Command = "scan" | "analyze" | "attack" | "diff" | "report" | "config";

const NETWORK_COMMANDS: ReadonlySet<Command> = new Set(["scan", "attack"]);

interface PromptArmorRunParams {
  runtime: AgentRuntime;
  repoRoot: string;
  pluginPath: string;
  command: Command;
  promptAugment: string;
  model: string;
  allowedTools: string[];
  signal?: AbortSignal;
  /** Live-output sink for the `⎿` tail — see ctx.reportOutput. */
  onOutput?: (line: string) => void;
}

interface PromptArmorRunResult {
  costUsd: number;
  outputDir: string;
}

function resolveModel(ctx: ExecutionContext, override?: string): string {
  if (override) return override;
  const cfg = ctx.config.taskConfig?.["prompt-armor"] as Record<string, unknown> | undefined;
  if (cfg && typeof cfg.model === "string" && cfg.model.trim()) return cfg.model.trim();
  return ctx.config.model;
}

function resolveTargetPaths(ctx: ExecutionContext, input?: string): { root: string; name: string } {
  return resolveRepo(input ?? ctx.target ?? ctx.cwd);
}

function buildPromptArmorPrompt(command: Command, augment: string): string {
  const header = (() => {
    switch (command) {
      case "scan":
        return "Run the /scan command to execute a full LLM red-team pipeline";
      case "analyze":
        return "Run the /analyze command to statically inspect the target LLM app for prompt-injection surface";
      case "attack":
        return "Run the /attack command to send a specific attack payload";
      case "diff":
        return "Run the /diff command to compare two prior red-team runs";
      case "report":
        return "Run the /report command to generate a consolidated red-team report from prior scans";
      case "config":
        return "Run the /config command to inspect or scaffold promptarmor.yaml";
    }
  })();
  const lines: string[] = [
    `You are operating the promptarmor-plugin that is already loaded for you.`,
    `${header}.`,
    "",
    "Write artifacts to `.prompt-armor/` under the repo root, using the contract the",
    "command documents. When you are done, summarize what you produced in one short",
    "paragraph so the caller can surface it in a CLI result.",
  ];
  if (augment.trim()) {
    lines.push("", "Caller-supplied arguments / context:", augment.trim());
  }
  return lines.join("\n");
}

async function runPromptArmor(params: PromptArmorRunParams): Promise<PromptArmorRunResult> {
  const prompt = buildPromptArmorPrompt(params.command, params.promptAugment);

  let costUsd = 0;
  for await (const message of params.runtime.query({
    prompt,
    options: {
      cwd: params.repoRoot,
      model: params.model,
      allowedTools: params.allowedTools,
      permissionMode: "dontAsk",
      plugins: [{ type: "local" as const, path: params.pluginPath }],
    },
  })) {
    // Forward sub-agent actions to the live tail before the final-result
    // accounting below swallows them.
    forwardSubAgentMessage(message, params.onOutput);
    if (message.type !== "result") continue;
    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd += message.totalCostUsd;
    }
  }

  return { costUsd, outputDir: path.join(params.repoRoot, ".prompt-armor") };
}

function formatKeyValueAugment(params: Record<string, unknown>, keys: string[]): string {
  const parts: string[] = [];
  for (const key of keys) {
    const value = params[key];
    if (value === undefined || value === null) continue;
    if (Array.isArray(value)) {
      if (value.length === 0) continue;
      parts.push(`${key}: ${value.join(",")}`);
    } else if (typeof value === "object") {
      parts.push(`${key}: ${JSON.stringify(value)}`);
    } else if (String(value).trim()) {
      parts.push(`${key}: ${value}`);
    }
  }
  return parts.join("\n");
}

interface BuildToolSpec {
  command: Command;
  toolId: string;
  blurb: string;
  allowedInputs: string[];
  extraInputSchema: Record<string, unknown>;
  extraProperties?: Record<string, unknown>;
}

function buildCommandTool(spec: BuildToolSpec): ModuleTool {
  const requiresAuth = NETWORK_COMMANDS.has(spec.command);

  const baseProperties: Record<string, unknown> = {
    target: {
      type: "string",
      description: "Repository path where artifacts will be written (defaults to cwd).",
    },
    model: {
      type: "string",
      description: "Model override for this run.",
    },
    ...spec.extraInputSchema,
  };

  if (requiresAuth) {
    baseProperties.authorized = {
      type: "boolean",
      description:
        "Must be true to run this network-capable command. Confirms the caller has authorization to test the endpoint.",
    };
  }

  // Human-friendly label for the `⏺` header: "Scan" / "Analyze" / etc.
  const capitalized = spec.command.charAt(0).toUpperCase() + spec.command.slice(1);
  return {
    name: spec.toolId,
    displayName: `PromptArmor ${capitalized}`,
    formatInput(input) {
      const p = (input ?? {}) as Record<string, unknown>;
      return typeof p["target"] === "string" ? (p["target"] as string) : null;
    },
    renderResult(result) {
      const first = result.output.split("\n", 1)[0]?.trim();
      return first && first.length > 0 ? first : null;
    },
    description: `${spec.blurb} Drives the promptarmor-plugin /${spec.command} slash command.${
      requiresAuth
        ? " Requires `authorized: true` input (generates real traffic against live endpoints)."
        : ""
    }`,
    inputSchema: {
      type: "object",
      properties: baseProperties,
    },
    headless: true,
    async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
      const params = (input ?? {}) as Record<string, unknown>;

      if (requiresAuth && params.authorized !== true) {
        return {
          ok: false,
          output:
            `${spec.toolId} refuses to run: pass \`authorized: true\` to confirm you have ` +
            "authorization to test the target endpoint. This command can generate real attack traffic.",
        };
      }

      let pluginPath: string;
      try {
        pluginPath = resolvePromptArmorPluginPath();
      } catch (err) {
        return {
          ok: false,
          output: `promptarmor-plugin not resolvable: ${toErrorMessage(err)}`,
        };
      }

      const { root, name } = resolveTargetPaths(ctx, params.target as string | undefined);
      const model = resolveModel(ctx, params.model as string | undefined);
      const augment = formatKeyValueAugment(params, spec.allowedInputs);

      ctx.reportActivity?.(`${spec.toolId} · /${spec.command} on ${name} · ${model}`);

      try {
        const result = await runPromptArmor({
          runtime: ctx.runtime,
          repoRoot: root,
          pluginPath,
          command: spec.command,
          promptAugment: augment,
          model,
          allowedTools: [...resolveDefaultReadOnlyTools(), "Bash", "Write"],
          signal: ctx.signal,
          onOutput: ctx.reportOutput,
        });

        const lines = [
          `${spec.toolId} complete for ${name}`,
          `  Command:  /${spec.command}`,
          `  Output:   ${path.relative(root, result.outputDir) || ".prompt-armor"}/`,
          `  Artifacts: ${existsSync(result.outputDir) ? "present" : "none"}`,
          `  Cost:     $${result.costUsd.toFixed(4)}`,
        ];
        return {
          ok: true,
          output: lines.join("\n"),
          data: {
            target: root,
            repoName: name,
            command: spec.command,
            outputDir: result.outputDir,
          },
          costUsd: result.costUsd,
        };
      } catch (err) {
        const msg = toErrorMessage(err);
        log.warn(`${spec.toolId} error: ${msg}`);
        return { ok: false, output: `${spec.toolId} error: ${msg}` };
      }
    },
  };
}

// Tool catalog

const scanTool = buildCommandTool({
  command: "scan",
  toolId: "prompt-armor:scan",
  blurb: "Run a full LLM red-team scan — recon → plan → test → judge → report.",
  allowedInputs: ["endpoint", "suites", "mutations", "config"],
  extraInputSchema: {
    endpoint: { type: "string", description: "LLM endpoint URL (or config file-relative name)." },
    suites: {
      type: "array",
      items: { type: "string" },
      description: "Attack suites to run (jailbreak, injection, pii, tool-abuse, etc.).",
    },
    mutations: {
      type: "array",
      items: { type: "string" },
      description: "Mutation strategies to enable (base64, multilingual, etc.).",
    },
    config: {
      type: "string",
      description: "Path to promptarmor.yaml (relative to the repo root).",
    },
  },
});

const analyzeTool = buildCommandTool({
  command: "analyze",
  toolId: "prompt-armor:analyze",
  blurb: "Statically analyse the target app for prompt-injection surface (no network I/O).",
  allowedInputs: ["paths", "focus"],
  extraInputSchema: {
    paths: {
      type: "array",
      items: { type: "string" },
      description: "Specific file/dir paths to focus analysis on.",
    },
    focus: {
      type: "string",
      description: "Hint a specific surface (system-prompt, tool-use, data-flow, ...).",
    },
  },
});

const attackTool = buildCommandTool({
  command: "attack",
  toolId: "prompt-armor:attack",
  blurb: "Send a single attack payload to the target endpoint and judge the response.",
  allowedInputs: ["endpoint", "attack", "mutation", "payload"],
  extraInputSchema: {
    endpoint: { type: "string", description: "LLM endpoint URL or configured alias." },
    attack: { type: "string", description: "Attack plugin id (e.g. 'dan', 'prefix-inject')." },
    mutation: { type: "string", description: "Mutation strategy to apply to the payload." },
    payload: {
      type: "string",
      description: "Optional raw payload (overrides the attack plugin default).",
    },
  },
});

const diffTool = buildCommandTool({
  command: "diff",
  toolId: "prompt-armor:diff",
  blurb: "Diff two prior red-team runs to show regression / improvement.",
  allowedInputs: ["runA", "runB"],
  extraInputSchema: {
    runA: { type: "string", description: "First run id or path." },
    runB: { type: "string", description: "Second run id or path." },
  },
});

const reportTool = buildCommandTool({
  command: "report",
  toolId: "prompt-armor:report",
  blurb: "Generate a consolidated red-team report (Markdown / JSON / SARIF) from prior scans.",
  allowedInputs: ["runId", "format", "output"],
  extraInputSchema: {
    runId: { type: "string", description: "Run id to render (defaults to latest)." },
    format: {
      type: "string",
      description: "Output format: md (default), json, sarif.",
    },
    output: { type: "string", description: "Destination path for the rendered report." },
  },
});

const configTool = buildCommandTool({
  command: "config",
  toolId: "prompt-armor:config",
  blurb: "Inspect or scaffold promptarmor.yaml in the target repo.",
  allowedInputs: ["action"],
  extraInputSchema: {
    action: {
      type: "string",
      description: "Sub-action (init, show, validate, ...).",
    },
  },
});

// Module factory

export function createCorePromptArmorModule(): CopilotModule {
  return {
    id: "prompt-armor",
    displayName: "PromptArmor",
    category: "offense",
    version: "0.1.0",
    description:
      "LLM red-team wrapper around the promptarmor-plugin Claude Code plugin — 80+ attack " +
      "plugins, 25+ mutation strategies, code-aware remediation.",
    tools: [scanTool, analyzeTool, attackTool, diffTool, reportTool, configTool],
    async init() {
      // Lazy — tools report graceful errors if the plugin is missing.
    },
    async dispose() {
      // Nothing to release.
    },
  };
}

export const __corePromptArmorInternals = {
  buildPromptArmorPrompt,
  formatKeyValueAugment,
  NETWORK_COMMANDS,
  resolveModel,
  resolveTargetPaths,
};
