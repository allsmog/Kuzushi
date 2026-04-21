/**
 * Vuln Scout — whitebox pentesting CopilotModule.
 *
 * Thin wrapper that exposes the `@kuzushi/vuln-scout` Claude Code plugin's
 * capabilities as module:action tools callable from shell and run modes.
 * Shares the `runPluginFindingScanner` implementation with the `vuln-scout`
 * pipeline task (src/agents/tasks/vuln-scout/vuln-scout.ts) so behaviour stays
 * consistent across all three execution modes.
 */

import { resolveDefaultReadOnlyTools } from "../agent-runtime/execution.js";
import { runPluginFindingScanner } from "../agents/tasks/plugin-finding-scanner.js";
import { resolveVulnScoutPlugin } from "../agents/tasks/vuln-scout/resolve-vuln-scout.js";
import { buildVulnScoutPrompt } from "../agents/tasks/vuln-scout/vuln-scout.js";
import { resolveRepo } from "../cli/shared.js";
import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "./types.js";

function resolveTargetPaths(
  ctx: ToolExecutionContext,
  input?: string,
): { root: string; name: string } {
  const target = input ?? ctx.target ?? ctx.cwd;
  return resolveRepo(target);
}

function resolveModel(ctx: ToolExecutionContext, override?: string): string {
  if (override) return override;
  const cfg = ctx.config.taskConfig?.["vuln-scout"] as Record<string, unknown> | undefined;
  if (cfg && typeof cfg.model === "string" && cfg.model.trim()) return cfg.model.trim();
  return ctx.config.model;
}

function resolveMaxFindings(ctx: ToolExecutionContext, override?: unknown): number {
  const fromInput = typeof override === "number" ? override : undefined;
  if (fromInput && fromInput >= 1) return Math.floor(fromInput);
  const cfg = ctx.config.taskConfig?.["vuln-scout"] as Record<string, unknown> | undefined;
  const configured = cfg && typeof cfg.maxFindings === "number" ? cfg.maxFindings : undefined;
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
    const p = input as Record<string, unknown> | undefined;
    return typeof p?.["target"] === "string" ? (p["target"] as string) : null;
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
  async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;

    let plugin: { type: "local"; path: string };
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

    const { root, name } = resolveTargetPaths(ctx, params.target as string | undefined);
    const model = resolveModel(ctx, params.model as string | undefined);
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
  return {
    id: "vuln-scout",
    displayName: "Vuln Scout",
    category: "offense",
    version: "0.1.0",
    description:
      "Whitebox pentest wrapper around the @kuzushi/vuln-scout Claude Code plugin — " +
      "agentic SAST + taint analysis returning normalized Findings.",
    tools: [auditTool],
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
