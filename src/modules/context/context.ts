/**
 * Context module — application "map" builder.
 *
 * Pure `ModuleTool` (`context:build`) — the shell entry point drives
 * `generateContextSnapshot` (which internally runs its own mini-DAG of
 * context-gatherer → context-enricher → app-model-build → threat-model →
 * threat-scenario-build). Hidden DagTools on this module expose the
 * individual infrastructure DAG nodes (context-gatherer,
 * context-enricher, app-model-build, threat-scenario-build,
 * code-config-detect, call-graph-assist, code-graph-build/enrich,
 * invariant-extract/check) so the module registry owns their lifecycle
 * instead of `createDefaultTaskRegistry`.
 *
 * Produces the ContextSnapshot consumed downstream by randori /
 * agentic-sast / taint-iris / threat-hunt.
 */

import { appModelBuildTask } from "../../agents/tasks/app-model-build.js";
import { callGraphAssistTask } from "../../agents/tasks/call-graph-assist.js";
import { codeConfigDetectTask } from "../../agents/tasks/code-config-detect.js";
import { codeGraphBuildTask } from "../../agents/tasks/code-graph/build.js";
import { codeGraphEnrichTask } from "../../agents/tasks/code-graph/enrich.js";
import { contextEnricherTask } from "../../agents/tasks/context-enricher.js";
import { contextGathererTask } from "../../agents/tasks/context-gatherer.js";
import { invariantCheckTask } from "../../agents/tasks/invariant-analysis/check.js";
import { invariantExtractTask } from "../../agents/tasks/invariant-analysis/extract.js";
import { threatScenarioBuildTask } from "../../agents/tasks/threat-scenario-build.js";
import type { ContextGenerationSlice } from "../../ui/state.js";
import { exposeAgentTaskAsHiddenDagTool } from "../dag-bridge.js";
import { defineModule, defineTool } from "../define.js";
import { saveContextSnapshot } from "../sast/context-persist.js";
import { formatContextSummary, generateContextSnapshot } from "../sast/shared.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";

const CONTEXT_GENERATION_SLICES = [
  "all",
  "repo",
  "enrichment",
  "app-model",
  "dfd",
  "stride",
  "stories",
  "scope",
  "scenarios",
] as const satisfies readonly ContextGenerationSlice[];

export function createContextModule(): CopilotModule {
  const contextBuildTool = defineTool<"context">({
    name: "context:build",
    displayName: "Build Context",
    formatInput(input) {
      const p = input as Record<string, unknown> | undefined;
      const target = typeof p?.["target"] === "string" ? (p["target"] as string) : undefined;
      return target ?? null;
    },
    renderResult(result) {
      const firstLine = result.output.split("\n", 1)[0]?.trim();
      return firstLine && firstLine.length > 0 ? firstLine : null;
    },
    description:
      "Generate the application context map for a target repository. Runs context " +
      "gathering, LLM enrichment, app model extraction, PASTA threat modeling, " +
      "and threat scenario building. Results are cached.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Path to the repository to analyze." },
        discovery: {
          type: "string",
          enum: ["auto", "flat", "modules"],
          default: "auto",
          description: "auto = detect monorepo, flat = single project, modules = force per-module.",
        },
        enrichment: {
          type: "boolean",
          default: true,
          description: "Run LLM context enrichment (1 API call).",
        },
        threatModel: {
          type: "boolean",
          default: true,
          description: "Run PASTA S1-S4 threat modeling.",
        },
        scenarios: {
          type: "boolean",
          default: true,
          description: "Build threat scenarios from STRIDE threats.",
        },
        scope: {
          type: "string",
          enum: [...CONTEXT_GENERATION_SLICES],
          default: "all",
          description:
            "Regenerate one generated context slice. all = full rebuild; dfd/stride/stories/scope target threat-model slices.",
        },
        preserveUserEdits: {
          type: "boolean",
          default: true,
          description:
            "Preserve operator-edited threat-model artifacts unless the user explicitly accepts a patch.",
        },
        CONTEXT_PROMPT: {
          type: "string",
          description:
            "Override the context-enricher system prompt. Accepts inline text or a path to .md/.txt.",
          "x-advanced": true,
        },
      },
      required: ["target"],
    },
    headless: true,
    async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
      const p = input as Record<string, unknown>;
      const target = (p.target as string) ?? ctx.target;
      if (!target) return { ok: false, output: "context:build requires a target (repo path)." };

      const enrichment = p.enrichment !== false;
      const threatModel = p.threatModel !== false;
      const scenarios = p.scenarios !== false && threatModel;
      const discovery = (p.discovery as string) ?? "auto";
      const scope = parseContextScope(p.scope);

      try {
        const scoped = optionsForScope(scope, { enrichment, threatModel, scenarios });
        const snapshot = await generateContextSnapshot(target, ctx, {
          ...scoped,
          discovery: discovery as "auto" | "flat" | "modules",
        });
        snapshot.generatedSlices = scope === "all" ? [...CONTEXT_GENERATION_SLICES] : [scope];
        snapshot.staleSlices = staleSlicesFor(scope);

        const uiStoreInternal = ctx.uiStore as import("../../ui/state.js").UIStore | undefined;
        if (uiStoreInternal) {
          const shell = uiStoreInternal.getState().shell;
          if (shell) uiStoreInternal.update({ shell: { ...shell, contextSnapshot: snapshot } });
        }

        saveContextSnapshot(target, snapshot);

        return { ok: true, output: formatContextSummary(snapshot), data: snapshot };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        return { ok: false, output: `Context generation error: ${msg}` };
      }
    },
  });

  const hide = (task: Parameters<typeof exposeAgentTaskAsHiddenDagTool<"context">>[0]) =>
    exposeAgentTaskAsHiddenDagTool<"context">(task, { moduleId: "context" });

  const hiddenInfraDagTools = [
    hide(contextGathererTask),
    hide(contextEnricherTask),
    hide(appModelBuildTask),
    hide(threatScenarioBuildTask),
    hide(codeConfigDetectTask),
    hide(callGraphAssistTask),
    hide(codeGraphBuildTask),
    hide(codeGraphEnrichTask),
    hide(invariantExtractTask),
    hide(invariantCheckTask),
  ];

  return defineModule({
    id: "context",
    displayName: "Context Map",
    category: "intel",
    version: "0.17.2",
    description:
      "Builds the application context snapshot: repo model, routes, app model, " +
      "threat model seed. Required by agentic / taint-iris / threat-hunt.",
    rank: "excellent",
    references: [{ type: "URL", value: "https://owasp.org/Threat-Modeling" }],
    notes: {
      stability: ["stable"],
      reliability: ["reliable"],
      sideEffects: ["costs LLM tokens"],
    },
    tools: [contextBuildTool, ...hiddenInfraDagTools],
  });
}

function parseContextScope(value: unknown): ContextGenerationSlice {
  return CONTEXT_GENERATION_SLICES.includes(value as ContextGenerationSlice)
    ? (value as ContextGenerationSlice)
    : "all";
}

function optionsForScope(
  scope: ContextGenerationSlice,
  defaults: { enrichment: boolean; threatModel: boolean; scenarios: boolean },
): { enrichment: boolean; threatModel: boolean; scenarios: boolean } {
  switch (scope) {
    case "repo":
      return { enrichment: false, threatModel: false, scenarios: false };
    case "enrichment":
    case "app-model":
      return { enrichment: true, threatModel: false, scenarios: false };
    case "dfd":
    case "stride":
    case "stories":
    case "scope":
      return { enrichment: true, threatModel: true, scenarios: false };
    case "scenarios":
      return { enrichment: true, threatModel: true, scenarios: true };
    default:
      return defaults;
  }
}

function staleSlicesFor(scope: ContextGenerationSlice): ContextGenerationSlice[] {
  switch (scope) {
    case "repo":
      return ["enrichment", "app-model", "dfd", "stride", "stories", "scope", "scenarios"];
    case "enrichment":
      return ["app-model", "dfd", "stride", "stories", "scope", "scenarios"];
    case "app-model":
      return ["dfd", "stride", "stories", "scope", "scenarios"];
    case "dfd":
      return ["stride", "stories", "scope", "scenarios"];
    case "stride":
      return ["stories", "scope", "scenarios"];
    case "stories":
    case "scope":
      return ["scenarios"];
    default:
      return [];
  }
}
