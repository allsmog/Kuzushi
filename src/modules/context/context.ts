/**
 * Context module — application "map" builder.
 *
 * Pure `ModuleTool` — the shell entry point drives `generateContextSnapshot`
 * (which internally runs its own mini-DAG of context-gatherer →
 * context-enricher → app-model-build → threat-model → threat-scenario-build).
 * The individual DAG tasks remain registered in `src/agents/index.ts`; the
 * context module wraps them into a single shell-facing verb.
 *
 * Produces the ContextSnapshot consumed downstream by randori /
 * agentic-sast / taint-iris / threat-hunt.
 */

import { defineModule, defineTool } from "../define.js";
import { saveContextSnapshot } from "../sast/context-persist.js";
import { formatContextSummary, generateContextSnapshot } from "../sast/shared.js";
import type { CopilotModule, ToolExecutionContext, ToolResult } from "../types.js";

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
    async execute(input: unknown, ctx: ToolExecutionContext): Promise<ToolResult> {
      const p = input as Record<string, unknown>;
      const target = (p.target as string) ?? ctx.target;
      if (!target) return { ok: false, output: "context:build requires a target (repo path)." };

      const enrichment = p.enrichment !== false;
      const threatModel = p.threatModel !== false;
      const scenarios = p.scenarios !== false && threatModel;
      const discovery = (p.discovery as string) ?? "auto";

      try {
        const snapshot = await generateContextSnapshot(target, ctx, {
          enrichment,
          threatModel,
          scenarios,
          discovery: discovery as "auto" | "flat" | "modules",
        });

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
    tools: [contextBuildTool],
  });
}
