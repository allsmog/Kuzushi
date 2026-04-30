import {
  readXRayReportArtifacts,
  renderXRayReportSummary,
  runXRayReport,
  type XRayReportData,
} from "../../agents/tasks/x-ray/runner.js";
import { resolveRepo } from "../../cli/shared.js";
import { isRecord } from "../../utils.js";
import { indexXRayArtifacts } from "../_shared/artifact-kb/index.js";
import { defineDagTool, defineModule, defineTool } from "../define.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";

interface XRayRunInput {
  target?: string;
  model?: string;
  maxBudgetUsd?: number;
  effort?: "low" | "medium" | "high" | "max" | "xhigh";
}

interface XRayReadInput {
  target?: string;
  index?: boolean;
}

interface XRayTaskConfig {
  model?: string;
  maxBudgetUsd?: number;
  effort?: "low" | "medium" | "high" | "max" | "xhigh";
}

const runInputSchema = {
  type: "object",
  properties: {
    target: {
      type: "string",
      description: "Repository path (defaults to the session target or cwd).",
    },
    model: {
      type: "string",
      description: "Model override for this X-Ray run.",
    },
    maxBudgetUsd: {
      type: "number",
      minimum: 0,
      description: "Optional hard budget cap passed to the underlying AI runtime.",
    },
    effort: {
      type: "string",
      enum: ["low", "medium", "high", "max", "xhigh"],
      description: "Optional reasoning effort override.",
    },
  },
  additionalProperties: false,
} as const;

const readInputSchema = {
  type: "object",
  properties: {
    target: {
      type: "string",
      description: "Repository path containing an x-ray/ artifact directory.",
    },
    index: {
      type: "boolean",
      default: false,
      description: "When true, index validated X-Ray artifacts into the repo-local Artifact KB.",
    },
  },
  additionalProperties: false,
} as const;

const runTool = defineTool<"x-ray">({
  name: "x-ray:run",
  displayName: "Run X-Ray",
  description:
    "Generate a Pashov X-Ray pre-audit report under the target repository's x-ray/ directory.",
  inputSchema: runInputSchema,
  headless: true,
  formatInput(input) {
    return parseRunInput(input).target ?? null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = parseRunInput(input);
    const { root, name } = resolveTargetPaths(ctx, params.target);
    const model = resolveModel(ctx, params.model);
    const maxBudgetUsd = resolveBudget(ctx, params.maxBudgetUsd);
    const effort = resolveEffort(ctx, params.effort);

    ctx.reportActivity?.(`running X-Ray for ${name} - ${ctx.runtime.id} - ${model}`);

    try {
      const data = await runXRayReport({
        runtime: ctx.runtime,
        repoRoot: root,
        repoName: name,
        model,
        maxBudgetUsd,
        effort,
        signal: ctx.signal,
        onOutput: ctx.reportOutput,
      });
      const artifactKb = tryIndexXRayArtifacts(root, data, ctx);

      return {
        ok: true,
        output: renderXRayWithArtifactKb(renderXRayReportSummary(data), artifactKb),
        data: {
          ...data,
          ...(artifactKb.indexed ? { artifactKb: artifactKb.indexed } : {}),
          ...(artifactKb.error ? { artifactKbError: artifactKb.error } : {}),
        },
        costUsd: data.costUsd,
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, output: `x-ray:run error: ${message}` };
    }
  },
});

const readTool = defineTool<"x-ray">({
  name: "x-ray:read",
  displayName: "Read X-Ray",
  description: "Read and validate existing Pashov X-Ray artifacts from the target repository.",
  inputSchema: readInputSchema,
  headless: true,
  formatInput(input) {
    return parseReadInput(input).target ?? null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = parseReadInput(input);
    const { root, name } = resolveTargetPaths(ctx, params.target);

    try {
      const data = readXRayReportArtifacts({
        repoRoot: root,
        repoName: name,
        runtimeMode: "codex",
        costUsd: 0,
      });
      const artifactKb = params.index ? tryIndexXRayArtifacts(root, data, ctx) : {};
      return {
        ok: true,
        output: renderXRayWithArtifactKb(renderXRayReadSummary(data), artifactKb),
        data: {
          ...data,
          ...(artifactKb.indexed ? { artifactKb: artifactKb.indexed } : {}),
          ...(artifactKb.error ? { artifactKbError: artifactKb.error } : {}),
        },
      };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { ok: false, output: `x-ray:read error: ${message}` };
    }
  },
});

const xRayDagTool = defineDagTool<"x-ray", XRayRunInput, XRayReportData>({
  name: "x-ray:x-ray",
  displayName: "X-Ray",
  description: "Generate a hidden Pashov X-Ray report artifact for scan-mode report consumers.",
  inputSchema: runInputSchema,
  headless: true,
  hidden: true,
  dag: {
    outputKind: "report",
    dependsOn: ["context:context-gatherer"],
  },
  async run(input: XRayRunInput, ctx: ExecutionContext): Promise<XRayReportData> {
    const params = parseRunInput(input);
    const target = params.target ?? ctx.dag?.scanPath ?? ctx.dag?.workRoot ?? ctx.target ?? ctx.cwd;
    const { root, name } = resolveTargetPaths(ctx, target);
    const model = resolveModel(ctx, params.model);
    const maxBudgetUsd = resolveBudget(ctx, params.maxBudgetUsd);
    const effort = resolveEffort(ctx, params.effort);

    ctx.reportActivity?.(`running X-Ray report node for ${name}`);

    const data = await runXRayReport({
      runtime: ctx.runtime,
      repoRoot: root,
      repoName: name,
      model,
      maxBudgetUsd,
      effort,
      signal: ctx.signal,
      onOutput: ctx.reportOutput,
    });
    tryIndexXRayArtifacts(root, data, ctx);
    return data;
  },
});

export function createXRayModule(): CopilotModule {
  return defineModule({
    id: "x-ray",
    displayName: "X-Ray",
    category: "intel",
    version: "0.1.0",
    rank: "good",
    description:
      "Generate Pashov X-Ray pre-audit reports as portable artifacts across Claude, pi-ai, and Codex.",
    longDescription:
      "Runs the vendored Pashov X-Ray skill through the best available runtime path: native Claude plugin loading, pi-ai prompt injection with TodoWrite/Task shims, or Codex prompt injection with artifact validation.",
    references: [
      {
        type: "URL",
        value: "https://github.com/pashov/skills/tree/main/x-ray",
      },
    ],
    tools: [runTool, readTool, xRayDagTool],
  });
}

function resolveTargetPaths(ctx: ExecutionContext, input?: string): { root: string; name: string } {
  const target = input ?? ctx.target ?? ctx.cwd;
  return resolveRepo(target);
}

function resolveModel(ctx: ExecutionContext, override?: string): string {
  if (override?.trim()) return override.trim();
  if (ctx.toolModel?.trim()) return ctx.toolModel.trim();
  const cfg = readXRayTaskConfig(ctx);
  if (cfg?.model?.trim()) return cfg.model.trim();
  return ctx.config.model;
}

function resolveBudget(ctx: ExecutionContext, override?: number): number | undefined {
  if (typeof override === "number" && Number.isFinite(override) && override >= 0) return override;
  const configured = readXRayTaskConfig(ctx)?.maxBudgetUsd;
  if (typeof configured === "number" && Number.isFinite(configured) && configured >= 0) {
    return configured;
  }
  return undefined;
}

function resolveEffort(
  ctx: ExecutionContext,
  override?: XRayRunInput["effort"],
): XRayRunInput["effort"] | undefined {
  if (override) return override;
  return readXRayTaskConfig(ctx)?.effort;
}

function readXRayTaskConfig(ctx: ExecutionContext): XRayTaskConfig | undefined {
  const raw = ctx.config.taskConfig?.["x-ray"];
  if (!isRecord(raw)) return undefined;
  return {
    model: readStringField(raw, "model"),
    maxBudgetUsd: readNumberField(raw, "maxBudgetUsd"),
    effort: readEffortField(raw, "effort"),
  };
}

function parseRunInput(input: unknown): XRayRunInput {
  if (!isRecord(input)) return {};
  return {
    target: readStringField(input, "target"),
    model: readStringField(input, "model"),
    maxBudgetUsd: readNumberField(input, "maxBudgetUsd"),
    effort: readEffortField(input, "effort"),
  };
}

function parseReadInput(input: unknown): XRayReadInput {
  if (!isRecord(input)) return {};
  return {
    target: readStringField(input, "target"),
    index: readBooleanField(input, "index"),
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

function readBooleanField(
  record: Readonly<Record<string, unknown>>,
  key: string,
): boolean | undefined {
  const value = record[key];
  return typeof value === "boolean" ? value : undefined;
}

function readEffortField(
  record: Readonly<Record<string, unknown>>,
  key: string,
): XRayRunInput["effort"] | undefined {
  const value = record[key];
  if (
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "max" ||
    value === "xhigh"
  ) {
    return value;
  }
  return undefined;
}

function renderXRayReadSummary(data: XRayReportData): string {
  return [
    `x-ray:read validated artifacts for ${data.repoName} (${data.target})`,
    `  Verdict:      ${data.verdict.tier ?? "unknown"}${data.verdict.summary ? ` - ${data.verdict.summary}` : ""}`,
    `  Entry points: ${data.entryPointCounts.total}`,
    `  Invariants:   ${data.invariantCounts.total}`,
  ].join("\n");
}

function tryIndexXRayArtifacts(
  root: string,
  data: XRayReportData,
  ctx: ExecutionContext,
): { indexed?: ReturnType<typeof indexXRayArtifacts>; error?: string } {
  try {
    const indexed = indexXRayArtifacts({
      repoRoot: root,
      report: data,
      ...(ctx.workspaceId ? { runId: ctx.workspaceId } : {}),
    });
    ctx.reportActivity?.(`indexed Artifact KB (${indexed.chunks} X-Ray chunks)`);
    return { indexed };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    ctx.reportActivity?.(`Artifact KB indexing skipped: ${error}`);
    return { error };
  }
}

function renderXRayWithArtifactKb(
  base: string,
  artifactKb: { indexed?: ReturnType<typeof indexXRayArtifacts>; error?: string },
): string {
  if (artifactKb.indexed) return `${base}\n  Artifact KB: ${artifactKb.indexed.chunks} chunks`;
  if (artifactKb.error) return `${base}\n  Artifact KB: skipped (${artifactKb.error})`;
  return base;
}

export const __xRayModuleInternals = {
  parseRunInput,
  parseReadInput,
  resolveModel,
  resolveBudget,
  resolveEffort,
};
