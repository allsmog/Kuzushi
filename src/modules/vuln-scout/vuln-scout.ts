/**
 * Vuln Scout — whitebox pentesting CopilotModule.
 *
 * Thin wrapper that exposes the `@kuzushi/vuln-scout` Claude Code plugin's
 * capabilities as module:action tools callable from shell and run modes.
 * Shares the `runPluginFindingScanner` implementation with the `vuln-scout`
 * pipeline task (src/agents/tasks/vuln-scout/vuln-scout.ts) so behaviour stays
 * consistent across all three execution modes.
 */

import { resolveDefaultReadOnlyTools } from "../../agent-runtime/execution.js";
import { runPluginFindingScanner } from "../../agents/tasks/plugin-finding-scanner.js";
import { resolveVulnScoutPlugin } from "../../agents/tasks/vuln-scout/resolve-vuln-scout.js";
import { buildVulnScoutPrompt, vulnScoutTask } from "../../agents/tasks/vuln-scout/vuln-scout.js";
import { resolveRepo } from "../../cli/shared.js";
import { isRecord } from "../../utils.js";
import { defineHiddenDagNodeTool } from "../hidden-dag-node.js";
import type { CopilotModule, ExecutionContext, ModuleTool, ToolResult } from "../types.js";

interface VulnScoutAuditInput {
  target?: string;
  maxFindings?: number;
  model?: string;
}

interface VulnScoutTaskConfig {
  model?: string;
  maxFindings?: number;
}

interface LocalClaudePlugin {
  type: "local";
  path: string;
}

function resolveTargetPaths(ctx: ExecutionContext, input?: string): { root: string; name: string } {
  const target = input ?? ctx.target ?? ctx.cwd;
  return resolveRepo(target);
}

function resolveModel(ctx: ExecutionContext, override?: string): string {
  if (override) return override;
  const cfg = readVulnScoutTaskConfig(ctx);
  if (cfg?.model?.trim()) return cfg.model.trim();
  return ctx.config.model;
}

function resolveMaxFindings(ctx: ExecutionContext, override?: number): number {
  if (override && override >= 1) return Math.floor(override);
  const configured = readVulnScoutTaskConfig(ctx)?.maxFindings;
  if (configured && configured >= 1) return Math.floor(configured);
  return 50;
}

// ---------------------------------------------------------------------------
// vuln-scout:audit — run the whitebox pentest plugin
// ---------------------------------------------------------------------------

const auditTool: ModuleTool = {
  name: "vuln-scout:audit",
  displayName: "VulnScout",
  formatInput(input) {
    return parseAuditInput(input).target ?? null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Run the @kuzushi/vuln-scout whitebox pentesting plugin against the target repository. " +
    "An AI agent equipped with vuln-scout's scan/verify/trace skills explores the codebase, " +
    "performs static analysis + taint tracing, identifies OWASP Top 10 and API-security issues, " +
    "and returns normalized Findings with concrete evidence. Costs real USD — use on a repository.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Repository path (defaults to the session target or cwd).",
      },
      maxFindings: {
        type: "integer",
        minimum: 1,
        maximum: 200,
        description: "Maximum findings to return (default 50).",
      },
      model: {
        type: "string",
        description: "Model override for this audit.",
      },
    },
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = parseAuditInput(input);

    let plugin: LocalClaudePlugin;
    try {
      plugin = resolveVulnScoutPlugin();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        ok: false,
        output:
          "@kuzushi/vuln-scout is not installed or is missing whitebox-pentest/.claude-plugin/plugin.json. " +
          `Install with \`pnpm add @kuzushi/vuln-scout\`. (${msg})`,
      };
    }

    const { root, name } = resolveTargetPaths(ctx, params.target);
    const model = resolveModel(ctx, params.model);
    const maxFindings = resolveMaxFindings(ctx, params.maxFindings);

    ctx.reportActivity?.(`auditing ${name} · ${model}`);

    try {
      const result = await runPluginFindingScanner({
        runtime: ctx.runtime,
        repoRoot: root,
        repoName: name,
        ref: "HEAD",
        scannerId: "vuln-scout",
        model,
        allowedTools: resolveDefaultReadOnlyTools(),
        plugins: [plugin],
        prompt: buildVulnScoutPrompt(),
        maxFindings,
        logTag: "[vuln-scout]",
        signal: ctx.signal,
        onOutput: ctx.reportOutput,
      });

      const lines = [
        `vuln-scout:audit complete for ${name} (${root})`,
        `  Findings: ${result.findings.length}`,
        `  Model:    ${model}`,
        `  Cost:     $${result.costUsd.toFixed(4)}`,
      ];
      if (result.findings.length > 0) {
        lines.push("", "Top findings:");
        for (const f of result.findings.slice(0, 10)) {
          lines.push(`  - ${f.filePath}:${f.startLine} (${f.severity}) — ${f.message}`);
        }
      }

      return {
        ok: true,
        output: lines.join("\n"),
        data: { target: root, repoName: name, findings: result.findings },
        costUsd: result.costUsd,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, output: `vuln-scout:audit error: ${msg}` };
    }
  },
};

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createCoreVulnScoutModule(): CopilotModule {
  const hiddenVulnScout = defineHiddenDagNodeTool<"vuln-scout">(vulnScoutTask, {
    moduleId: "vuln-scout",
    multiStrategy: true,
  });

  return {
    id: "vuln-scout",
    displayName: "Vuln Scout",
    category: "offense",
    version: "0.1.0",
    description:
      "Whitebox pentest wrapper around the @kuzushi/vuln-scout Claude Code plugin — " +
      "agentic SAST + taint analysis returning normalized Findings.",
    tools: [auditTool, hiddenVulnScout],
    async init() {
      // No eager plugin resolution — the tool reports a graceful error if
      // the plugin is not installed.
    },
    async dispose() {
      // Nothing to release.
    },
  };
}

export const __coreVulnScoutInternals = {
  resolveTargetPaths,
  resolveModel,
  resolveMaxFindings,
};

function parseAuditInput(input: unknown): VulnScoutAuditInput {
  if (!isRecord(input)) return {};
  return {
    target: readStringField(input, "target"),
    maxFindings: readNumberField(input, "maxFindings"),
    model: readStringField(input, "model"),
  };
}

function readVulnScoutTaskConfig(ctx: ExecutionContext): VulnScoutTaskConfig | undefined {
  const raw = ctx.config.taskConfig?.["vuln-scout"];
  if (!isRecord(raw)) return undefined;
  return {
    model: readStringField(raw, "model"),
    maxFindings: readNumberField(raw, "maxFindings"),
  };
}

function readStringField(
  record: Readonly<Record<string, unknown>>,
  key: string,
): string | undefined {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

function readNumberField(
  record: Readonly<Record<string, unknown>>,
  key: string,
): number | undefined {
  const value = record[key];
  return typeof value === "number" ? value : undefined;
}
