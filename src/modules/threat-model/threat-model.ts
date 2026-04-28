import path from "node:path";
import { resolveDefaultReadOnlyTools } from "../../agent-runtime/execution.js";
import { resolveThreatModelConfig } from "../../agents/tasks/threat-modeling/config.js";
import {
  applyThreatModelMethodology,
  normalizeThreatModelMethodology,
} from "../../agents/tasks/threat-modeling/methodology.js";
import { threatModelRandoriTask } from "../../agents/tasks/threat-modeling/randori.js";
import { convertRandoriToThreatModel } from "../../agents/tasks/threat-modeling/randori-adapter.js";
import {
  mergeRandoriStageOutputs,
  readRandoriArtifacts,
} from "../../agents/tasks/threat-modeling/randori-artifacts.js";
import { runRandoriPasta } from "../../agents/tasks/threat-modeling/randori-runner.js";
import { resolveRandoriPluginPath } from "../../agents/tasks/threat-modeling/resolve-randori.js";
import type { ThreatModelMethodology } from "../../agents/tasks/threat-modeling/types.js";
import { threatScenarioBuildTask } from "../../agents/tasks/threat-scenario-build.js";
import { resolveRepo } from "../../cli/shared.js";
import {
  loadPersistentThreatModel,
  savePersistentThreatModel,
} from "../../threat-model-renderer.js";
import {
  buildHomeSlice,
  createAttachmentTools,
  renderUntrustedAttachments,
} from "../_shared/attachments/index.js";
import { exposeAgentTaskAsHiddenDagTool } from "../dag-bridge.js";
import type { CopilotModule, ExecutionContext, ModuleTool, ToolResult } from "../types.js";
import {
  loadThreatModelAttachments,
  THREAT_MODEL_KIND_SPEC,
  threatModelAttachmentAdapter,
} from "./attachments.js";

const DEFAULT_STAGES = ["s1", "s2", "s3", "s4"] as const;
const VALID_STAGES = new Set(["s1", "s2", "s3", "s4"]);
const METHODOLOGIES: ThreatModelMethodology[] = ["pasta", "stride", "dread"];
const THREAT_MODEL_SLICES = ["all", "dfd", "stride", "stories", "scope", "scenarios"] as const;
type ThreatModelSlice = (typeof THREAT_MODEL_SLICES)[number];

function resolveTargetPaths(ctx: ExecutionContext, input?: string): { root: string; name: string } {
  const target = input ?? ctx.target ?? ctx.cwd;
  return resolveRepo(target);
}

function resolveModel(ctx: ExecutionContext, override?: string, fallback?: string): string {
  if (override?.trim()) return override.trim();
  const cfg = ctx.config.taskConfig?.["threat-model"];
  if (cfg && typeof cfg === "object" && !Array.isArray(cfg)) {
    const record = cfg as Record<string, unknown>;
    const value = record["model"] ?? record["strideModel"];
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return fallback ?? ctx.config.model;
}

function resolveStages(
  input: unknown,
  fallback: readonly string[] = DEFAULT_STAGES,
): {
  stages: string[];
  unknown: string[];
} {
  if (!Array.isArray(input)) return { stages: [...fallback], unknown: [] };
  const raw = input.filter((s): s is string => typeof s === "string");
  const unknown = raw.filter((s) => !VALID_STAGES.has(s));
  if (unknown.length > 0) return { stages: [], unknown };
  return { stages: raw.length > 0 ? raw : [...fallback], unknown: [] };
}

function defaultArtifactDir(runId: string): string {
  return path.join(".kuzushi", "runs", runId, "threat-model-output");
}

function readMethodology(
  params: Record<string, unknown>,
  fallback: ThreatModelMethodology,
): ThreatModelMethodology {
  return normalizeThreatModelMethodology(params["methodology"] ?? params["type"], fallback);
}

function readPositiveInt(value: unknown, fallback: number, min = 1): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < min) return fallback;
  return Math.floor(numeric);
}

function readBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function readSlice(value: unknown): ThreatModelSlice {
  return THREAT_MODEL_SLICES.includes(value as ThreatModelSlice)
    ? (value as ThreatModelSlice)
    : "all";
}

function hasAnyArtifact(artifacts: object): boolean {
  return Object.values(artifacts).some((value) => value != null);
}

function methodologyLabel(methodology: ThreatModelMethodology): string {
  switch (methodology) {
    case "pasta":
      return "PASTA";
    case "stride":
      return "STRIDE";
    case "dread":
      return "DREAD";
  }
}

const buildTool: ModuleTool = {
  name: "threat-model:build",
  displayName: "Build",
  formatInput(input) {
    const p = (input ?? {}) as Record<string, unknown>;
    return typeof p["target"] === "string" ? (p["target"] as string) : null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Build a normalized ThreatModelDocument. Select methodology=pasta, stride, or dread. " +
    "The current provider is Randori/PASTA: PASTA runs the full S1-S4 model, STRIDE exposes " +
    "the bounded DFD + STRIDE threat library, and DREAD adds a DREAD scoring overlay.",
  inputSchema: {
    type: "object",
    properties: {
      target: {
        type: "string",
        description: "Repository path (defaults to the session target or cwd).",
      },
      methodology: {
        type: "string",
        enum: METHODOLOGIES,
        description:
          "Threat modeling methodology to return (default taskConfig.threat-model.methodology or pasta).",
      },
      type: {
        type: "string",
        enum: METHODOLOGIES,
        description: "Alias for methodology.",
      },
      slice: {
        type: "string",
        enum: [...THREAT_MODEL_SLICES],
        default: "all",
        description:
          "Threat-model slice to regenerate. dfd/stride/stories/scope/scenarios currently share the same provider-backed build and persist the normalized document.",
      },
      outputDir: {
        type: "string",
        description:
          "Directory (relative to the repo root) where threat-model artifacts are written. Defaults to .kuzushi/runs/<workspaceId>/threat-model-output.",
      },
      stages: {
        type: "array",
        items: { type: "string", enum: ["s1", "s2", "s3", "s4"] },
        description: "Provider stages to run (default: configured randoriStages or s1-s4).",
      },
      maxElements: {
        type: "integer",
        minimum: 5,
        maximum: 200,
        description: "Upper bound on DFD elements in the scope.",
      },
      maxThreats: {
        type: "integer",
        minimum: 1,
        maximum: 100,
        description: "Upper bound on threat scenarios.",
      },
      emitFindings: {
        type: "boolean",
        description: "When true, convert threat scenarios into Finding records.",
      },
      findingThreshold: {
        type: "string",
        enum: ["low", "medium", "high", "critical"],
        description: "Impact floor for emitted findings.",
      },
      model: {
        type: "string",
        description: "Model override for this run.",
      },
      preserveUserEdits: {
        type: "boolean",
        default: true,
        description:
          "When true, keep an existing operator-edited .kuzushi/threat-model.json instead of overwriting it.",
      },
    },
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;
    const cfg = resolveThreatModelConfig(ctx.config);
    const methodology = readMethodology(params, cfg.methodology);
    const slice = readSlice(params["slice"]);

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

    const { stages, unknown } = resolveStages(params["stages"], cfg.randoriStages);
    if (unknown.length > 0) {
      return {
        ok: false,
        output: `threat-model:build unknown stage(s): ${unknown.join(", ")}. Valid: s1, s2, s3, s4.`,
      };
    }

    const { root, name } = resolveTargetPaths(ctx, params["target"] as string | undefined);
    const runId = ctx.workspaceId ?? `adhoc-${Date.now()}`;
    const artifactDir =
      typeof params["outputDir"] === "string" && params["outputDir"].trim()
        ? params["outputDir"]
        : defaultArtifactDir(runId);
    const emitFindings = readBoolean(params["emitFindings"], false);
    const findingThreshold =
      typeof params["findingThreshold"] === "string"
        ? params["findingThreshold"]
        : cfg.findingThreshold;

    // Operator-staged reference material (architecture diagrams, RFCs,
    // runbooks, audit reports). Loaded from disk so scan-mode + shell mode
    // pick up the same attachments without any flag plumbing.
    const attachments = loadThreatModelAttachments(ctx.cwd);
    const rendered =
      attachments.length > 0
        ? renderUntrustedAttachments(attachments, {
            moduleId: "threat-model",
            emptyPlaceholder: "",
          })
        : null;
    const systemPromptAddendum = rendered?.block ?? undefined;

    try {
      const result = await runRandoriPasta({
        runtime: ctx.runtime,
        repoRoot: root,
        repoName: name,
        pluginPath,
        model: resolveModel(ctx, params["model"] as string | undefined, cfg.model),
        allowedTools: [...resolveDefaultReadOnlyTools(), "Write"],
        stages,
        artifactDir,
        maxElements: readPositiveInt(params["maxElements"], cfg.maxElements, 5),
        maxThreats: readPositiveInt(params["maxThreats"], cfg.maxThreats),
        emitFindings,
        findingThreshold,
        previousModel: loadPersistentThreatModel(root),
        signal: ctx.signal,
        logTag: "[threat-model]",
        onOutput: ctx.reportOutput,
        ...(cfg.effort ? { effort: cfg.effort } : {}),
        wallClockBudgetMs: cfg.wallClockBudgetMs,
        ...(systemPromptAddendum ? { systemPromptAddendum } : {}),
      });
      const document = applyThreatModelMethodology(result.document, methodology);
      const preserveUserEdits = readBoolean(params["preserveUserEdits"], true);
      const persisted = savePersistentThreatModel(root, document, !preserveUserEdits);
      const lines = [
        `threat-model:build complete for ${name} (${root})`,
        `  Method:   ${methodologyLabel(methodology)}`,
        `  Slice:    ${slice}`,
        "  Provider: randori-pasta",
        `  Stages:   ${stages.join(", ")}`,
        `  Artifact: ${artifactDir}`,
        `  Saved:    ${persisted ? ".kuzushi/threat-model.json" : "skipped (operator-edited model preserved)"}`,
        `  Threats:  ${document.threats.length}`,
        `  DFD:      ${document.dfd.elements.length} elements`,
        `  Findings: ${result.findings.length}${emitFindings ? "" : " (emitFindings=false)"}`,
        `  Cost:     $${result.costUsd.toFixed(4)}`,
      ];
      if (document.riskScores?.methodology === "dread") {
        lines.push("", "Top DREAD scores:");
        for (const score of document.riskScores.threats
          .slice()
          .sort((a, b) => b.score - a.score)
          .slice(0, 5)) {
          lines.push(`  - ${score.threatId}: ${score.score}/10 (${score.rating})`);
        }
      } else if (document.threats.length > 0) {
        lines.push("", "Top threats:");
        for (const t of document.threats.slice(0, 5)) {
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
          threatModelPath: path.join(root, ".kuzushi", "threat-model.json"),
          provider: "randori-pasta",
          methodology,
          slice,
          stages,
          document,
          findings: result.findings,
          persisted,
        },
        costUsd: result.costUsd,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { ok: false, output: `threat-model:build error: ${msg}` };
    }
  },
};

const readTool: ModuleTool = {
  name: "threat-model:read",
  displayName: "Read",
  formatInput(input) {
    const p = (input ?? {}) as Record<string, unknown>;
    return typeof p["outputDir"] === "string" ? (p["outputDir"] as string) : null;
  },
  renderResult(result) {
    const first = result.output.split("\n", 1)[0]?.trim();
    return first && first.length > 0 ? first : null;
  },
  description:
    "Read a previously-written threat model artifact set and return the normalized ThreatModelDocument. " +
    "Does not invoke the LLM.",
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
      methodology: {
        type: "string",
        enum: METHODOLOGIES,
        description: "Methodology overlay to apply while reading.",
      },
      type: {
        type: "string",
        enum: METHODOLOGIES,
        description: "Alias for methodology.",
      },
    },
    required: ["outputDir"],
  },
  headless: true,
  async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
    const params = (input ?? {}) as Record<string, unknown>;
    const outputDir = params["outputDir"];
    if (typeof outputDir !== "string" || !outputDir.trim()) {
      return { ok: false, output: "threat-model:read requires an outputDir." };
    }
    const cfg = resolveThreatModelConfig(ctx.config);
    const methodology = readMethodology(params, cfg.methodology);
    const { root, name } = resolveTargetPaths(ctx, params["target"] as string | undefined);
    const artifacts = readRandoriArtifacts(root, outputDir);
    if (!hasAnyArtifact(artifacts)) {
      return {
        ok: false,
        output: `No threat-model artifacts found under ${outputDir} (resolved against ${root}).`,
      };
    }

    const merged = mergeRandoriStageOutputs(artifacts, { fallbackMaxThreats: cfg.maxThreats });
    if (!merged) {
      return {
        ok: false,
        output: `Artifacts present under ${outputDir} but no usable stage outputs to merge.`,
      };
    }
    const converted = convertRandoriToThreatModel(merged);
    if (!converted) {
      return {
        ok: false,
        output: `Failed to convert artifacts at ${outputDir} into a ThreatModelDocument.`,
      };
    }

    const document = applyThreatModelMethodology(converted, methodology);
    return {
      ok: true,
      output: [
        `Loaded ${methodologyLabel(methodology)} threat model for ${name} from ${outputDir}`,
        `  Threats: ${document.threats.length}`,
        `  DFD:     ${document.dfd.elements.length} elements`,
      ].join("\n"),
      data: { target: root, repoName: name, outputDir, methodology, document, artifacts },
    };
  },
};

const methodologiesTool: ModuleTool = {
  name: "threat-model:methodologies",
  displayName: "Methodologies",
  description: "List selectable threat model methodologies and the current implementation mapping.",
  inputSchema: { type: "object" },
  headless: true,
  async execute(): Promise<ToolResult> {
    return {
      ok: true,
      output: [
        "Selectable threat model methodologies:",
        "- pasta: risk-first PASTA flow using Randori stages S1-S4 plus narrative synthesis.",
        "- stride: DFD + bounded STRIDE threat scenarios from the same evidence-grounded provider.",
        "- dread: DREAD risk scoring overlay over generated threat scenarios.",
      ].join("\n"),
      data: {
        methodologies: METHODOLOGIES,
        provider: "randori-pasta",
      },
    };
  },
};

export function createThreatModelModule(): CopilotModule {
  // Knowledge-base verbs (`attach` / `attachments` / `detach` / `reparse`)
  // are registered through the shared factory so the parser, storage, and
  // operator UX match the other KB-enabled modules. Attachments seed the
  // Randori prompt addendum at run time (see `buildTool.execute`).
  const attachmentTools = createAttachmentTools("threat-model", THREAT_MODEL_KIND_SPEC, {
    adapter: threatModelAttachmentAdapter(),
    afterMutation: ({ ctx, cwd, documents }) => {
      // Keep the home view's "draft scope" badge in sync after every
      // attach/detach/reparse so operators see the new doc count without
      // navigating away. The slice itself was already patched by the
      // shared factory; this is a no-op stub today but reserves the hook
      // for future per-module home extensions (missing-artifact hints,
      // coverage warnings, etc.).
      void ctx;
      void cwd;
      void documents;
    },
  });
  const hide = (task: Parameters<typeof exposeAgentTaskAsHiddenDagTool<"threat-model">>[0]) =>
    exposeAgentTaskAsHiddenDagTool<"threat-model">(task, { moduleId: "threat-model" });
  const hiddenDagTools = [hide(threatModelRandoriTask), hide(threatScenarioBuildTask)];
  return {
    id: "threat-model",
    displayName: "Threat Model",
    category: "intel",
    version: "0.1.0",
    description:
      "Build and inspect repository threat models. Operators select a methodology " +
      "(PASTA, STRIDE, or DREAD) while providers such as Randori handle the heavy analysis. " +
      "Attach reference material (RFCs, diagrams, runbooks, audit reports) with `attach`.",
    tools: [...attachmentTools, buildTool, readTool, methodologiesTool, ...hiddenDagTools],
  };
}

/**
 * Build the home-view slice for the focused module. Used by the shell to
 * seed `shell.kbState["threat-model"]` when the operator types `/use
 * threat-model` so the home view renders the existing attachments without
 * requiring an explicit `attachments` invocation first.
 */
export function buildThreatModelKbSlice(cwd: string): ReturnType<typeof buildHomeSlice> {
  const docs = loadThreatModelAttachments(cwd);
  return buildHomeSlice(
    "threat-model",
    threatModelAttachmentAdapter().pathFor(cwd),
    docs,
    THREAT_MODEL_KIND_SPEC,
  );
}

export const __threatModelModuleInternals = {
  DEFAULT_STAGES,
  METHODOLOGIES,
  THREAT_MODEL_SLICES,
  resolveStages,
  resolveModel,
  defaultArtifactDir,
  readMethodology,
  readSlice,
};
