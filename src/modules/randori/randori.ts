/**
 * Randori — PASTA threat modeling CopilotModule.
 *
 * Thin wrapper that exposes the @kuzushi/randori-plugin Claude Code plugin
 * as module:action tools callable from shell and run modes. Shares the
 * `runRandoriPasta` runner with the threat-model module so behaviour stays
 * consistent across all three execution modes.
 */

import path from "node:path";
import { resolveDefaultReadOnlyTools } from "../../agent-runtime/execution.js";
import { convertRandoriToThreatModel } from "../../agents/tasks/threat-modeling/randori-adapter.js";
import {
  mergeRandoriStageOutputs,
  readRandoriArtifacts,
} from "../../agents/tasks/threat-modeling/randori-artifacts.js";
import { runRandoriPasta } from "../../agents/tasks/threat-modeling/randori-runner.js";
import { resolveRandoriPluginPath } from "../../agents/tasks/threat-modeling/resolve-randori.js";
import { resolveRepo } from "../../cli/shared.js";
import { loadPersistentThreatModel } from "../../threat-model-renderer.js";
import type { CopilotModule, ExecutionContext, ModuleTool, ToolResult } from "../types.js";

const DEFAULT_STAGES = ["s1", "s2", "s3", "s4"] as const;
const VALID_STAGES = new Set(["s1", "s2", "s3", "s4"]);

function resolveTargetPaths(ctx: ExecutionContext, input?: string): { root: string; name: string } {
  const target = input ?? ctx.target ?? ctx.cwd;
  return resolveRepo(target);
}

function resolveModel(ctx: ExecutionContext, override?: string): string {
  if (override) return override;
  const cfg = ctx.config.taskConfig?.["threat-model-randori"] as
    | Record<string, unknown>
    | undefined;
  if (cfg && typeof cfg.model === "string" && cfg.model.trim()) return cfg.model.trim();
  return ctx.config.model;
}

function resolveStages(input: unknown): { stages: string[]; unknown: string[] } {
  if (!Array.isArray(input)) return { stages: [...DEFAULT_STAGES], unknown: [] };
  const raw = (input as unknown[]).filter((s): s is string => typeof s === "string");
  const unknown = raw.filter((s) => !VALID_STAGES.has(s));
  if (unknown.length > 0) return { stages: [], unknown };
  return { stages: raw.length > 0 ? raw : [...DEFAULT_STAGES], unknown: [] };
}

function defaultArtifactDir(runId: string): string {
  return path.join(".kuzushi", "runs", runId, "randori-output");
}

// ---------------------------------------------------------------------------
// randori:pasta — run the PASTA analysis
// ---------------------------------------------------------------------------

const pastaTool: ModuleTool = {
  name: "randori:pasta",
  displayName: "PASTA",
  formatInput(input) {
    const p = (input ?? {}) as Record<string, unknown>;
    return typeof p["target"] === "string" ? (p["target"] as string) : null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Run the Randori PASTA threat model against a target repository. Executes the " +
    "@kuzushi/randori-plugin across stages S1 (objectives), S2 (scope), S3 (DFD), S4 " +
    "(STRIDE threats), plus a narrative synthesis pass. Writes pasta-*.json artifacts " +
    "to outputDir and returns a normalized ThreatModelDocument plus (optionally) Findings. " +
    "Costs real USD — use on a repository you want modelled.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Repository path (defaults to the session target or cwd).",
      },
      outputDir: {
        type: "string",
        description:
          "Directory (relative to the repo root) where pasta-*.json artifacts are written. " +
          "Defaults to .kuzushi/runs/<workspaceId>/randori-output or a synthetic runId.",
      },
      stages: {
        type: "array",
        items: { type: "string", enum: ["s1", "s2", "s3", "s4"] },
        description:
          "Subset of PASTA stages to run (default: all four). Stages are run in order; " +
          "S4 requires at least S3 artifacts to exist.",
      },
      maxElements: {
        type: "integer",
        minimum: 5,
        maximum: 200,
        description: "Upper bound on DFD elements in the scope (default 40).",
      },
      maxThreats: {
        type: "integer",
        minimum: 1,
        maximum: 100,
        description: "Upper bound on STRIDE threat scenarios in S4 (default 30).",
      },
      emitFindings: {
        type: "boolean",
        description:
          "When true, convert the S4 threats into Finding records (default false for " +
          "interactive use — set true to mirror the scan-pipeline behaviour).",
      },
      findingThreshold: {
        type: "string",
        enum: ["low", "medium", "high", "critical"],
        description: "Impact floor for emitted findings (default 'medium').",
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
      pluginPath = resolveRandoriPluginPath();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return {
        ok: false,
        output:
          "@kuzushi/randori-plugin is not installed or is missing .claude-plugin/plugin.json. " +
          `Install with \`pnpm add @kuzushi/randori-plugin\`. (${msg})`,
      };
    }

    const { stages, unknown } = resolveStages(params.stages);
    if (unknown.length > 0) {
      return {
        ok: false,
        output: `randori:pasta unknown stage(s): ${unknown.join(", ")}. Valid: s1, s2, s3, s4.`,
      };
    }

    const { root, name } = resolveTargetPaths(ctx, params.target as string | undefined);
    const runId = ctx.workspaceId ?? `adhoc-${Date.now()}`;
    const artifactDir =
      typeof params.outputDir === "string" && params.outputDir.trim()
        ? params.outputDir
        : defaultArtifactDir(runId);

    const model = resolveModel(ctx, params.model as string | undefined);
    const maxElements =
      typeof params.maxElements === "number" && params.maxElements >= 5
        ? Math.floor(params.maxElements)
        : 40;
    const maxThreats =
      typeof params.maxThreats === "number" && params.maxThreats >= 1
        ? Math.floor(params.maxThreats)
        : 30;
    const emitFindings = params.emitFindings === true;
    const findingThreshold =
      typeof params.findingThreshold === "string" ? params.findingThreshold : "medium";

    const previousModel = loadPersistentThreatModel(root);

    try {
      const result = await runRandoriPasta({
        runtime: ctx.runtime,
        repoRoot: root,
        repoName: name,
        pluginPath,
        model,
        allowedTools: [...resolveDefaultReadOnlyTools(), "Write"],
        stages,
        artifactDir,
        maxElements,
        maxThreats,
        emitFindings,
        findingThreshold,
        previousModel,
        signal: ctx.signal,
        logTag: "[randori]",
        onOutput: ctx.reportOutput,
      });

      const lines = [
        `randori:pasta complete for ${name} (${root})`,
        `  Stages:   ${stages.join(", ")}`,
        `  Artifact: ${artifactDir}`,
        `  Threats:  ${result.document.threats.length}`,
        `  DFD:      ${result.document.dfd.nodes.length} nodes · ${result.document.dfd.flows.length} flows`,
        `  Findings: ${result.findings.length}${emitFindings ? "" : " (emitFindings=false)"}`,
        `  Cost:     $${result.costUsd.toFixed(4)}`,
      ];
      if (result.empty) {
        lines.push("", "No usable artifacts produced — empty threat model returned.");
      } else if (result.document.threats.length > 0) {
        lines.push("", "Top threats:");
        for (const t of result.document.threats.slice(0, 5)) {
          lines.push(`  - [${t.category}] ${t.title} (impact=${t.impact})`);
        }
      }

      return {
        ok: !result.empty,
        output: lines.join("\n"),
        data: {
          target: root,
          repoName: name,
          artifactDir,
          stages,
          document: result.document,
          findings: result.findings,
        },
        costUsd: result.costUsd,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, output: `randori:pasta error: ${msg}` };
    }
  },
};

// ---------------------------------------------------------------------------
// randori:threat-model — read artifacts from a prior run
// ---------------------------------------------------------------------------

const threatModelTool: ModuleTool = {
  name: "randori:threat-model",
  displayName: "Threat Model",
  formatInput(input) {
    const p = (input ?? {}) as Record<string, unknown>;
    return typeof p["target"] === "string" ? (p["target"] as string) : null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Read a previously-written PASTA artifact set and return the normalized " +
    "ThreatModelDocument. Does not invoke the LLM — cheap, deterministic, useful " +
    "for inspecting the output of a prior randori:pasta run.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Repository path (defaults to the session target or cwd).",
      },
      outputDir: {
        type: "string",
        description: "Directory (relative to the repo root) containing pasta-*.json artifacts.",
      },
    },
    required: ["outputDir"],
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;
    const outputDir = params.outputDir;
    if (typeof outputDir !== "string" || !outputDir.trim()) {
      return { ok: false, output: "randori:threat-model requires an outputDir." };
    }

    const { root, name } = resolveTargetPaths(ctx, params.target as string | undefined);
    const artifacts = readRandoriArtifacts(root, outputDir);
    if (Object.keys(artifacts).length === 0) {
      return {
        ok: false,
        output: `No pasta-*.json artifacts found under ${outputDir} (resolved against ${root}).`,
      };
    }

    const merged = mergeRandoriStageOutputs(artifacts);
    if (!merged) {
      return {
        ok: false,
        output: `Artifacts present under ${outputDir} but no usable stage outputs to merge.`,
      };
    }

    const document = convertRandoriToThreatModel(merged);
    if (!document) {
      return {
        ok: false,
        output: `Failed to convert Randori artifacts at ${outputDir} into a ThreatModelDocument.`,
      };
    }

    return {
      ok: true,
      output: [
        `Loaded threat model for ${name} from ${outputDir}`,
        `  Threats: ${document.threats.length}`,
        `  DFD:     ${dfdNodeCount(document)} nodes · ${dfdFlowCount(document)} flows`,
      ].join("\n"),
      data: { target: root, repoName: name, outputDir, document, artifacts },
    };
  },
};

function dfdNodeCount(
  document: import("../../agents/tasks/threat-modeling/types.js").ThreatModelDocument,
): number {
  if (Array.isArray(document.dfd.nodes)) return document.dfd.nodes.length;
  return (
    document.dfd.elements?.filter((element) => (element as { type?: string }).type !== "data-flow")
      .length ?? 0
  );
}

function dfdFlowCount(
  document: import("../../agents/tasks/threat-modeling/types.js").ThreatModelDocument,
): number {
  if (Array.isArray(document.dfd.flows)) return document.dfd.flows.length;
  return (
    document.dfd.elements?.filter((element) => (element as { type?: string }).type === "data-flow")
      .length ?? 0
  );
}

// ---------------------------------------------------------------------------
// Module factory
// ---------------------------------------------------------------------------

export function createCoreRandoriModule(): CopilotModule {
  return {
    id: "randori",
    displayName: "Randori PASTA",
    category: "intel",
    version: "0.1.0",
    description:
      "PASTA threat modeling wrapper around the @kuzushi/randori-plugin Claude Code plugin — " +
      "runs S1-S4 plus narrative synthesis and returns a ThreatModelDocument.",
    tools: [pastaTool, threatModelTool],
    async init() {
      // No eager plugin resolution — tools report a graceful error if missing.
    },
    async dispose() {
      // Nothing to release.
    },
  };
}

export const __coreRandoriInternals = {
  DEFAULT_STAGES,
  resolveTargetPaths,
  resolveStages,
  resolveModel,
  defaultArtifactDir,
};
