/**
 * Trail of Bits Skills — security audit CopilotModule.
 *
 * Thin wrapper that exposes the @kuzushi/tob-skills Claude Code plugin
 * collection (fp-check, variant-analysis, sharp-edges, insecure-defaults,
 * static-analysis, differential-review, etc.) as module:action tools
 * callable from shell and run modes. Shares the `runPluginFindingScanner`
 * implementation with the `tob-audit` pipeline task.
 */

import { resolveDefaultReadOnlyTools } from "../../agent-runtime/execution.js";
import { runPluginFindingScanner } from "../../agents/tasks/plugin-finding-scanner.js";
import {
  resolveTobPlugins,
  SECURITY_PLUGINS,
} from "../../agents/tasks/tob-audit/resolve-tob-plugin.js";
import { buildTobAuditPrompt, tobAuditTask } from "../../agents/tasks/tob-audit/tob-audit.js";
import { resolveRepo } from "../../cli/shared.js";
import { exposeAgentTaskAsHiddenDagTool } from "../dag-bridge.js";
import type { CopilotModule, ModuleTool, ToolExecutionContext, ToolResult } from "../types.js";

function resolveTargetPaths(
  ctx: ToolExecutionContext,
  input?: string,
): { root: string; name: string } {
  const target = input ?? ctx.target ?? ctx.cwd;
  return resolveRepo(target);
}

function resolveModel(ctx: ToolExecutionContext, override?: string): string {
  if (override) return override;
  const cfg = ctx.config.taskConfig?.["tob-audit"] as Record<string, unknown> | undefined;
  if (cfg && typeof cfg.model === "string" && cfg.model.trim()) return cfg.model.trim();
  return ctx.config.model;
}

function resolveMaxFindings(ctx: ToolExecutionContext, override?: unknown): number {
  const fromInput = typeof override === "number" ? override : undefined;
  if (fromInput && fromInput >= 1) return Math.floor(fromInput);
  const cfg = ctx.config.taskConfig?.["tob-audit"] as Record<string, unknown> | undefined;
  const configured = cfg && typeof cfg.maxFindings === "number" ? cfg.maxFindings : undefined;
  if (configured && configured >= 1) return Math.floor(configured);
  return 50;
}

// ---------------------------------------------------------------------------
// tob:audit — run the ToB skills audit
// ---------------------------------------------------------------------------

const auditTool: ModuleTool = {
  name: "tob:audit",
  displayName: "ToB Audit",
  formatInput(input) {
    const p = input as Record<string, unknown> | undefined;
    return typeof p?.["target"] === "string" ? (p["target"] as string) : null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Run the Trail of Bits security skills audit against the target repository. " +
    "An AI agent loaded with fp-check, variant-analysis, sharp-edges, insecure-defaults, " +
    "static-analysis, and differential-review skills explores the codebase and returns " +
    "normalized Findings. Pass `skills` to restrict the audit to a subset of the available " +
    "plugins (see tob:skills for the list).",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Repository path (defaults to the session target or cwd).",
      },
      skills: {
        type: "array",
        items: { type: "string" },
        description:
          "Subset of the resolvable ToB skill plugin IDs to load. When omitted, all " +
          "resolvable skills are loaded. Unknown names are rejected.",
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

    let plugins: Array<{ type: "local"; path: string }>;
    try {
      plugins = resolveTobPlugins();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        ok: false,
        output:
          "@kuzushi/tob-skills is not installed or has no resolvable security plugins. " +
          `Install with \`pnpm add @kuzushi/tob-skills\`. (${msg})`,
      };
    }

    if (Array.isArray(params.skills)) {
      const requested = (params.skills as unknown[]).filter(
        (s): s is string => typeof s === "string",
      );
      const unknown = requested.filter((s) => !SECURITY_PLUGINS.includes(s));
      if (unknown.length > 0) {
        return {
          ok: false,
          output:
            `tob:audit unknown skill(s): ${unknown.join(", ")}. ` +
            `Valid names: ${SECURITY_PLUGINS.join(", ")}.`,
        };
      }
      plugins = plugins.filter((p) => requested.some((r) => p.path.endsWith(`/${r}`)));
      if (plugins.length === 0) {
        return {
          ok: false,
          output:
            `tob:audit none of the requested skills are resolvable locally: ${requested.join(", ")}. ` +
            "Run `tob:skills` to see what is available.",
        };
      }
    }

    const { root, name } = resolveTargetPaths(ctx, params.target as string | undefined);
    const model = resolveModel(ctx, params.model as string | undefined);
    const maxFindings = resolveMaxFindings(ctx, params.maxFindings);

    ctx.reportActivity?.(`auditing ${name} · ${plugins.length} skill(s) · ${model}`);

    try {
      const result = await runPluginFindingScanner({
        runtime: ctx.runtime,
        repoRoot: root,
        repoName: name,
        ref: "HEAD",
        scannerId: "tob-audit",
        model,
        allowedTools: resolveDefaultReadOnlyTools(),
        plugins,
        prompt: buildTobAuditPrompt(),
        maxFindings,
        logTag: "[tob-audit]",
        signal: ctx.signal,
        onOutput: ctx.reportOutput,
      });

      const lines = [
        `tob:audit complete for ${name} (${root})`,
        `  Plugins: ${plugins.length}`,
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
        data: {
          target: root,
          repoName: name,
          plugins: plugins.map((p) => p.path),
          findings: result.findings,
        },
        costUsd: result.costUsd,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, output: `tob:audit error: ${msg}` };
    }
  },
};

// ---------------------------------------------------------------------------
// tob:skills — list resolvable skill plugins
// ---------------------------------------------------------------------------

const skillsTool: ModuleTool = {
  name: "tob:skills",
  displayName: "ToB Skills",
  formatInput() {
    return "";
  },
  description:
    "List the Trail of Bits security skill plugins that are currently resolvable " +
    "from the installed @kuzushi/tob-skills package. Returns plugin IDs and absolute paths.",
  inputSchema: { type: "object", properties: {} },
  headless: true,
  async execute(_input: unknown, _ctx: ToolExecutionContext): Promise<ToolResult> {
    let plugins: Array<{ type: "local"; path: string }>;
    try {
      plugins = resolveTobPlugins();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        ok: false,
        output:
          "@kuzushi/tob-skills is not installed or has no resolvable security plugins. " +
          `(${msg})`,
      };
    }

    const rows = plugins.map((p) => {
      const id = p.path.split("/").pop() ?? p.path;
      return { id, path: p.path };
    });
    const lines = [`Resolvable ToB skill plugins: ${rows.length}`];
    for (const r of rows) lines.push(`  - ${r.id}  (${r.path})`);
    const unresolved = SECURITY_PLUGINS.filter((name) => !rows.some((r) => r.id === name));
    if (unresolved.length > 0) {
      lines.push("", `Declared but not resolvable: ${unresolved.join(", ")}`);
    }

    return {
      ok: true,
      output: lines.join("\n"),
      data: { resolvable: rows, unresolved, declared: SECURITY_PLUGINS },
    };
  },
};

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createCoreTobModule(): CopilotModule {
  const hiddenTobAudit = exposeAgentTaskAsHiddenDagTool<"tob">(tobAuditTask, {
    moduleId: "tob",
    multiStrategy: true,
  });

  return {
    id: "tob",
    displayName: "Trail of Bits Skills",
    category: "offense",
    version: "0.1.0",
    description:
      "Audit wrapper around the @kuzushi/tob-skills Claude Code plugin collection " +
      "(fp-check, variant-analysis, sharp-edges, insecure-defaults, and more).",
    tools: [auditTool, skillsTool, hiddenTobAudit],
    async init() {
      // No eager plugin resolution — the tools report graceful errors.
    },
    async dispose() {
      // Nothing to release.
    },
  };
}

export const __coreTobInternals = {
  resolveTargetPaths,
  resolveModel,
  resolveMaxFindings,
};
