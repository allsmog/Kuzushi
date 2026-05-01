/**
 * Shinsa — compliance assessment CopilotModule.
 *
 * Thin wrapper that exposes the `shinsa-plugin` Claude Code plugin as
 * module:action tools callable from shell and run modes. The plugin ships
 * with 4 slash commands (`compliance-scan`, `quick-check`, `nist-scan`,
 * `nist-quick-check`) and 10 specialised assessor agents; each wrapper
 * tool drives the corresponding command by handing the target repo
 * to a Claude Code subprocess with the plugin loaded.
 */

import { existsSync, readdirSync } from "node:fs";
import path from "node:path";
import { resolveDefaultReadOnlyTools } from "../../agent-runtime/execution.js";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { resolveShinsaPluginPath } from "../../agents/tasks/shinsa/resolve-shinsa-plugin.js";
import { resolveRepo } from "../../cli/shared.js";
import { createLogger } from "../../logger.js";
import { toErrorMessage } from "../../utils.js";
import type { CopilotModule, ExecutionContext, ModuleTool, ToolResult } from "../types.js";

const log = createLogger({ stage: "shinsa" });

type ScanMode = "compliance-scan" | "quick-check" | "nist-scan" | "nist-quick-check";

interface ShinsaRunParams {
  runtime: AgentRuntime;
  repoRoot: string;
  pluginPath: string;
  mode: ScanMode;
  model: string;
  allowedTools: string[];
  controlsFilter?: string[];
  familyFilter?: string;
  severityFilter?: string[];
  outputDir: string;
  signal?: AbortSignal;
}

interface ShinsaRunResult {
  costUsd: number;
  outputDir: string;
}

function resolveModel(ctx: ExecutionContext, override?: string): string {
  if (override) return override;
  const cfg = ctx.config.taskConfig?.shinsa as Record<string, unknown> | undefined;
  if (cfg && typeof cfg.model === "string" && cfg.model.trim()) return cfg.model.trim();
  return ctx.config.model;
}

function resolveTargetPaths(ctx: ExecutionContext, input?: string): { root: string; name: string } {
  return resolveRepo(input ?? ctx.target ?? ctx.cwd);
}

function buildShinsaPrompt(params: {
  mode: ScanMode;
  outputDir: string;
  controls?: string[];
  family?: string;
  severity?: string[];
}): string {
  const lines: string[] = [];

  if (params.mode === "compliance-scan" || params.mode === "quick-check") {
    lines.push(
      "You are running an ISO 27001 Annex A compliance assessment on this repository",
      "using the shinsa plugin that is already loaded for you.",
      "",
      `Execute the /${params.mode} command end-to-end. Write all artifacts under`,
      `${params.outputDir}/ — both the JSON state (${params.outputDir}/shinsa-state.json)`,
      `and the Markdown report (${params.outputDir}/compliance-report.md).`,
    );
  } else if (params.mode === "nist-scan" || params.mode === "nist-quick-check") {
    lines.push(
      "You are running a NIST SP 800-53 Rev 5 compliance assessment on this repository",
      "using the shinsa plugin that is already loaded for you.",
      "",
      `Execute the /${params.mode} command end-to-end. Write artifacts under ${params.outputDir}/.`,
    );
  }

  if (params.controls && params.controls.length > 0) {
    lines.push("", `Restrict to these controls: ${params.controls.join(", ")}`);
  }
  if (params.family) {
    lines.push("", `Restrict to control family: ${params.family}`);
  }
  if (params.severity && params.severity.length > 0) {
    lines.push("", `Only report findings at severity: ${params.severity.join(", ")}`);
  }

  lines.push(
    "",
    "Ground every finding in concrete file:line citations. Do not speculate about code",
    "you have not actually read. Prefer maturity=missing over fabricated maturity=partial.",
  );

  return lines.join("\n");
}

async function runShinsaAssessment(params: ShinsaRunParams): Promise<ShinsaRunResult> {
  const prompt = buildShinsaPrompt({
    mode: params.mode,
    outputDir: params.outputDir,
    controls: params.controlsFilter,
    family: params.familyFilter,
    severity: params.severityFilter,
  });

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
    if (message.type !== "result") continue;
    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd += message.totalCostUsd;
    }
  }

  return { costUsd, outputDir: params.outputDir };
}

/**
 * List control-family skills the plugin ships with (directory names under
 * `<pluginRoot>/skills/`). Deterministic, no LLM required.
 */
function listSkillDirs(pluginPath: string): string[] {
  const skillsRoot = path.join(pluginPath, "skills");
  if (!existsSync(skillsRoot)) return [];
  return readdirSync(skillsRoot, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
}

// shinsa:scan — full ISO 27001 compliance assessment

function buildScanTool(mode: ScanMode, toolId: string, title: string, blurb: string): ModuleTool {
  return {
    name: toolId,
    description:
      `${blurb} Runs the shinsa-plugin /${mode} command against the target repository ` +
      "and writes structured state + Markdown report to <target>/shinsa-output/. Costs real USD.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Repository path (defaults to the session target or cwd).",
        },
        controls: {
          type: "array",
          items: { type: "string" },
          description: 'Subset of control IDs to assess (e.g. ["A.8.5", "A.8.24"]).',
        },
        family: {
          type: "string",
          description: 'Restrict to a control family (e.g. "A.5", "A.8", "AC", "SI").',
        },
        severity: {
          type: "array",
          items: { type: "string" },
          description: 'Severity floor: ["critical","high"] etc.',
        },
        outputDir: {
          type: "string",
          description:
            'Directory (relative to the repo root) to write artifacts. Defaults to "shinsa-output".',
        },
        model: {
          type: "string",
          description: "Model override for this run.",
        },
      },
    },
    headless: true,
    async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
      const params = (input ?? {}) as Record<string, unknown>;

      let pluginPath: string;
      try {
        pluginPath = resolveShinsaPluginPath();
      } catch (err) {
        return {
          ok: false,
          output: `shinsa-plugin not resolvable: ${toErrorMessage(err)}`,
        };
      }

      const { root, name } = resolveTargetPaths(ctx, params.target as string | undefined);
      const model = resolveModel(ctx, params.model as string | undefined);
      const outputDir =
        typeof params.outputDir === "string" && params.outputDir.trim()
          ? params.outputDir
          : "shinsa-output";

      const controls = Array.isArray(params.controls)
        ? (params.controls as unknown[]).filter((s): s is string => typeof s === "string")
        : undefined;
      const severity = Array.isArray(params.severity)
        ? (params.severity as unknown[]).filter((s): s is string => typeof s === "string")
        : undefined;
      const family = typeof params.family === "string" ? params.family : undefined;

      ctx.reportActivity?.(`${title} · ${name} · ${mode}`);

      try {
        const result = await runShinsaAssessment({
          runtime: ctx.runtime,
          repoRoot: root,
          pluginPath,
          mode,
          model,
          allowedTools: [...resolveDefaultReadOnlyTools(), "Write"],
          controlsFilter: controls,
          familyFilter: family,
          severityFilter: severity,
          outputDir,
          signal: ctx.signal,
        });

        const statePath = path.join(root, outputDir, "shinsa-state.json");
        const reportPath = path.join(root, outputDir, "compliance-report.md");

        const lines = [
          `${title} complete for ${name}`,
          `  Mode:     ${mode}`,
          `  Output:   ${outputDir}/`,
          `  Artifacts: ${existsSync(statePath) ? "state.json " : ""}${existsSync(reportPath) ? "compliance-report.md" : ""}`.trimEnd(),
          `  Cost:     $${result.costUsd.toFixed(4)}`,
        ];

        return {
          ok: true,
          output: lines.join("\n"),
          data: {
            target: root,
            repoName: name,
            mode,
            outputDir,
            statePath: existsSync(statePath) ? statePath : null,
            reportPath: existsSync(reportPath) ? reportPath : null,
          },
          costUsd: result.costUsd,
        };
      } catch (err) {
        const msg = toErrorMessage(err);
        log.warn(`${toolId} error: ${msg}`);
        return { ok: false, output: `${toolId} error: ${msg}` };
      }
    },
  };
}

const scanTool = buildScanTool(
  "compliance-scan",
  "shinsa:scan",
  "shinsa:scan",
  "Run a full ISO 27001 Annex A compliance assessment.",
);

const quickCheckTool = buildScanTool(
  "quick-check",
  "shinsa:quick-check",
  "shinsa:quick-check",
  "Run a fast ISO 27001 Annex A check on the highest-signal controls.",
);

const nistScanTool = buildScanTool(
  "nist-scan",
  "shinsa:nist-scan",
  "shinsa:nist-scan",
  "Run a full NIST SP 800-53 Rev 5 compliance assessment.",
);

const nistQuickCheckTool = buildScanTool(
  "nist-quick-check",
  "shinsa:nist-quick-check",
  "shinsa:nist-quick-check",
  "Run a fast NIST SP 800-53 Rev 5 check on the highest-signal controls.",
);

// shinsa:frameworks — list supported control families from the plugin's skills/

const frameworksTool: ModuleTool = {
  name: "shinsa:frameworks",
  displayName: "Shinsa Frameworks",
  formatInput() {
    return "";
  },
  description:
    "List the control families / framework modules the installed shinsa-plugin supports " +
    "(read from <pluginRoot>/skills/). No LLM call — cheap introspection.",
  inputSchema: { type: "object", properties: {} },
  headless: true,
  async execute(_input: unknown, _ctx: ExecutionContext): Promise<ToolResult> {
    let pluginPath: string;
    try {
      pluginPath = resolveShinsaPluginPath();
    } catch (err) {
      const msg = toErrorMessage(err);
      return { ok: false, output: `shinsa-plugin not resolvable: ${msg}` };
    }

    const skills = listSkillDirs(pluginPath);
    const lines = [
      `shinsa-plugin path: ${pluginPath}`,
      `Skill modules: ${skills.length}`,
      ...skills.map((s) => `  - ${s}`),
    ];
    return {
      ok: true,
      output: lines.join("\n"),
      data: { pluginPath, skills },
    };
  },
};

// Module factory

export function createCoreShinsaModule(): CopilotModule {
  return {
    id: "shinsa",
    displayName: "Shinsa Compliance",
    category: "governance",
    version: "0.1.0",
    description:
      "Compliance assessment wrapper around the shinsa-plugin Claude Code plugin — " +
      "ISO 27001 Annex A and NIST SP 800-53 Rev 5 with evidence-backed findings.",
    tools: [scanTool, quickCheckTool, nistScanTool, nistQuickCheckTool, frameworksTool],
    async init() {
      // Lazy — tools report graceful errors if the plugin is missing.
    },
    async dispose() {
      // Nothing to release.
    },
  };
}

export const __coreShinsaInternals = {
  buildShinsaPrompt,
  listSkillDirs,
  resolveModel,
  resolveTargetPaths,
};
