/**
 * Context module — application "map" builder.
 *
 * Pure `ModuleTool` (`context:build`) — the shell entry point drives
 * `generateContextSnapshot` (which internally runs its own mini-DAG of
 * context-gatherer → context-enricher → app-model-build). Hidden DagTools on
 * this module expose the individual infrastructure DAG nodes
 * (context-gatherer, context-enricher, app-model-build,
 * code-config-detect, call-graph-assist, code-graph-build/enrich,
 * invariant-extract/check) so the module registry owns their lifecycle
 * instead of `createDefaultDagRegistry`.
 *
 * Produces the ContextSnapshot consumed downstream by threat-model /
 * agentic-sast / taint-iris / carlini-threat-hunt.
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
import type { ContextGenerationSlice, ContextSnapshot } from "../../ui/state.js";
import { indexContextSnapshotArtifact } from "../_shared/artifact-kb/index.js";
import { createAttachmentTools } from "../_shared/attachments/index.js";
import { defineModule, defineTool } from "../define.js";
import { defineHiddenDagNodeTool } from "../hidden-dag-node.js";
import { saveContextSnapshot } from "../sast/context-persist.js";
import { formatContextSummary, generateContextSnapshot } from "../sast/shared.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";
import {
  CONTEXT_KIND_SPEC,
  contextAttachmentAdapter,
  loadContextAttachments,
} from "./attachments.js";

const CONTEXT_GENERATION_SLICES = [
  "all",
  "repo",
  "enrichment",
  "app-model",
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
      "gathering, optional LLM enrichment, and app/surface model extraction. " +
      "Results are cached.",
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
        scope: {
          type: "string",
          enum: [...CONTEXT_GENERATION_SLICES],
          default: "all",
          description: "Regenerate one context slice. all = full rebuild.",
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
      const discovery = (p.discovery as string) ?? "auto";
      const scope = parseContextScope(p.scope);

      // Steps drive the ✓/→/○ rows in `ModuleRunView`. Major phases of
      // the context build map to one row each. The renderer is no-op when
      // no run is active (run/headless mode), so this is safe to call
      // unconditionally.
      const stepIds = stepIdsForScope(scope, { enrichment });
      const steps: Array<{
        id: string;
        title: string;
        status: "pending" | "running" | "done" | "error";
      }> = stepIds.map((id) => ({
        id,
        title: STEP_TITLES[id] ?? id,
        status: "pending",
      }));
      const advance = (id: string, status: "running" | "done" | "error"): void => {
        const ix = steps.findIndex((s) => s.id === id);
        if (ix < 0) return;
        steps[ix] = { ...steps[ix]!, status };
        ctx.uiStore?.setModuleRunSteps?.(steps.slice());
      };

      try {
        advance("snapshot", "running");
        const scoped = optionsForScope(scope, { enrichment });
        const snapshot = await generateContextSnapshot(target, ctx, {
          ...scoped,
          discovery: discovery as "auto" | "flat" | "modules",
        });
        snapshot.generatedSlices = generatedSlicesFor(scope, scoped);
        snapshot.staleSlices = staleSlicesFor(scope);
        advance("snapshot", "done");

        advance("publish", "running");
        const uiStoreInternal = ctx.uiStore as import("../../ui/state.js").UIStore | undefined;
        if (uiStoreInternal) {
          const shell = uiStoreInternal.getState().shell;
          if (shell) uiStoreInternal.update({ shell: { ...shell, contextSnapshot: snapshot } });
        }
        advance("publish", "done");

        advance("save", "running");
        const saved = saveContextSnapshot(target, snapshot);
        const artifactKb = saved
          ? tryIndexContextArtifact(target, snapshot, ctx)
          : {
              error: "context snapshot was not saved; artifact KB indexing skipped",
            };
        advance("save", "done");

        const output = artifactKb?.indexed
          ? `${formatContextSummary(snapshot)}\n  Artifact KB: ${artifactKb.indexed.chunks} chunks`
          : formatContextSummary(snapshot);
        return {
          ok: true,
          output,
          data: {
            ...snapshot,
            ...(artifactKb?.indexed ? { artifactKb: artifactKb.indexed } : {}),
            ...(artifactKb?.error ? { artifactKbError: artifactKb.error } : {}),
          },
        };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const running = steps.find((s) => s.status === "running");
        if (running) advance(running.id, "error");
        return { ok: false, output: `Context generation error: ${msg}` };
      }
    },
  });

  const hide = (task: Parameters<typeof defineHiddenDagNodeTool<"context">>[0]) =>
    defineHiddenDagNodeTool<"context">(task, { moduleId: "context" });

  const hiddenInfraDagTools = [
    hide(contextGathererTask),
    hide(contextEnricherTask),
    hide(appModelBuildTask),
    hide(codeConfigDetectTask),
    hide(callGraphAssistTask),
    hide(codeGraphBuildTask),
    hide(codeGraphEnrichTask),
    hide(invariantExtractTask),
    hide(invariantCheckTask),
  ];

  // Knowledge-base verbs (`attach` / `attachments` / `detach` / `reparse`)
  // are registered through the shared factory. The context enricher reads
  // the persisted KB and passes the rendered block into its system prompt
  // (see `agents/tasks/context-enricher.ts`).
  const attachmentTools = createAttachmentTools("context", CONTEXT_KIND_SPEC, {
    adapter: contextAttachmentAdapter(),
  });

  return defineModule({
    id: "context",
    displayName: "Context Map",
    category: "intel",
    version: "0.17.2",
    description:
      "Builds the target context snapshot: repo model, enrichment, and app/surface model.",
    longDescription:
      "Required by agentic / taint-iris / carlini-threat-hunt. " +
      "Attach reference material (architecture docs, API specs, runbooks) with `attach`.",
    rank: "excellent",
    references: [{ type: "URL", value: "https://c4model.com/" }],
    notes: {
      stability: ["stable"],
      reliability: ["reliable"],
      sideEffects: ["costs LLM tokens"],
    },
    tools: [contextBuildTool, ...attachmentTools, ...hiddenInfraDagTools],
  });
}

function tryIndexContextArtifact(
  target: string,
  snapshot: ContextSnapshot,
  ctx: ExecutionContext,
): { indexed?: ReturnType<typeof indexContextSnapshotArtifact>; error?: string } {
  try {
    const indexed = indexContextSnapshotArtifact({
      repoRoot: target,
      snapshot,
      ...(ctx.workspaceId ? { runId: ctx.workspaceId } : {}),
      attachments: loadContextAttachments(target),
    });
    ctx.reportActivity?.(`indexed Artifact KB (${indexed.chunks} context chunks)`);
    return { indexed };
  } catch (err) {
    const error = err instanceof Error ? err.message : String(err);
    ctx.reportActivity?.(`Artifact KB indexing skipped: ${error}`);
    return { error };
  }
}

function parseContextScope(value: unknown): ContextGenerationSlice {
  return CONTEXT_GENERATION_SLICES.includes(value as ContextGenerationSlice)
    ? (value as ContextGenerationSlice)
    : "all";
}

function optionsForScope(
  scope: ContextGenerationSlice,
  defaults: { enrichment: boolean },
): { enrichment: boolean } {
  switch (scope) {
    case "repo":
      return { enrichment: false };
    case "enrichment":
    case "app-model":
      return { enrichment: true };
    default:
      return defaults;
  }
}

/**
 * Step ids surfaced in `ModuleRunView`. Decides which rows render based
 * on the operator's context-scope choice.
 */
const STEP_TITLES: Record<string, string> = {
  snapshot: "build context snapshot",
  publish: "publish to shell state",
  save: "persist .kuzushi/context-snapshot.json",
};

function stepIdsForScope(scope: ContextGenerationSlice, _opts: { enrichment: boolean }): string[] {
  void scope;
  return ["snapshot", "publish", "save"];
}

function staleSlicesFor(scope: ContextGenerationSlice): ContextGenerationSlice[] {
  switch (scope) {
    case "repo":
      return ["enrichment", "app-model"];
    case "enrichment":
      return ["app-model"];
    case "app-model":
      return [];
    default:
      return [];
  }
}

function generatedSlicesFor(
  scope: ContextGenerationSlice,
  opts: { enrichment: boolean },
): ContextGenerationSlice[] {
  if (scope !== "all") return [scope];

  const slices: ContextGenerationSlice[] = ["repo", "app-model"];
  if (opts.enrichment) slices.push("enrichment");
  if (opts.enrichment) {
    return ["all", ...slices];
  }
  return slices;
}
