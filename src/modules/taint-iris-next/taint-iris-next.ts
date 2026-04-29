/**
 * Taint IRIS Next — agent-forward taint hunting inspired by IRIS.
 *
 * This module intentionally lives beside the legacy `taint-iris` task. V1 is
 * context/threat-model first, deterministic structural evidence first, and one
 * bounded agent session for final CWE selection and finding normalization.
 */

import { defineModule, defineTool } from "../define.js";
import { targetProperty } from "../sast/schema-fragments.js";
import type { CopilotModule, ExecutionContext, ToolResult } from "../types.js";
import { buildTaintIrisNextAgentPrompt, runTaintIrisNextAgent } from "./agent.js";
import {
  TAINT_IRIS_NEXT_ATTRIBUTION,
  TAINT_IRIS_NEXT_DISPLAY_NAME,
  TAINT_IRIS_NEXT_ID,
  TAINT_IRIS_NEXT_REFERENCES,
  TAINT_IRIS_NEXT_SHORT_DESCRIPTION,
  TAINT_IRIS_NEXT_TUI_HEADER_LINES,
} from "./copy.js";
import { TAINT_IRIS_NEXT_CWE_CATALOG } from "./cwe-reference.js";
import { extractTaintIrisNextEvidence } from "./extractors.js";
import {
  buildTaintIrisNextPlan,
  DEFAULT_TAINT_IRIS_NEXT_CAPS,
  hasRequiredContext,
  renderMissingContextGate,
} from "./planner.js";
import type {
  TaintIrisNextAgentResult,
  TaintIrisNextEvidenceResult,
  TaintIrisNextInput,
  TaintIrisNextPlan,
} from "./types.js";

const MODULE_RUN_PHASES = [
  "context",
  "threat-model",
  "cwe-catalog",
  "structural-extract",
  "backend-evidence",
  "agent-hunt",
  "finding-normalize",
] as const;

function renderRunOutput(
  plan: TaintIrisNextPlan,
  evidenceResult: TaintIrisNextEvidenceResult,
  agentResult?: TaintIrisNextAgentResult,
): string {
  const warnings = [
    ...plan.backend.warnings,
    ...evidenceResult.warnings,
    ...(agentResult?.warnings ?? []),
  ];
  const findingsCount = agentResult?.findings.length ?? 0;
  const selectedCwes = agentResult?.selectedCwes.map((selection) => selection.cwe) ?? [];

  return [
    ...TAINT_IRIS_NEXT_TUI_HEADER_LINES,
    "",
    TAINT_IRIS_NEXT_ATTRIBUTION,
    "",
    `target: ${plan.target}`,
    `mode: ${plan.mode}`,
    `backend: ${plan.backend.requested} -> ${plan.backend.selected}`,
    plan.backend.codeqlDbPath
      ? `existing CodeQL DB: ${plan.backend.codeqlDbPath}`
      : "existing CodeQL DB: none",
    `context: ${plan.repoContext ? "loaded" : "missing"}`,
    `threat model: ${plan.threatModel ? "loaded" : "missing"}`,
    `languages: ${plan.languages.join(", ") || "unknown"}`,
    `CWE catalog: ${plan.catalog.length}/${TAINT_IRIS_NEXT_CWE_CATALOG.length} ranked candidates`,
    `structural query seeds: ${plan.structuralQueries.length}`,
    `evidence: ${evidenceResult.evidence.length} matches via ${evidenceResult.tool}`,
    `agent selected CWEs: ${selectedCwes.length > 0 ? selectedCwes.join(", ") : plan.mode === "hunt" ? "none" : "not run"}`,
    `findings: ${findingsCount}`,
    warnings.length > 0 ? `warnings: ${dedupe(warnings).join("; ")}` : "",
    "",
    plan.mode === "plan"
      ? "Status: deterministic plan complete. Hunt mode will feed this bounded catalog and evidence bundle into one scoped agent session."
      : "Status: hunt complete.",
    "",
    plan.promptCatalog,
  ]
    .filter((line) => line !== "")
    .join("\n");
}

function reportPlanningProgress(ctx: ExecutionContext, plan: TaintIrisNextPlan): void {
  ctx.reportActivity?.(
    `${plan.repoContext ? "context loaded" : "context missing"} for ${plan.target}`,
    { phase: "context", step: 1, total: MODULE_RUN_PHASES.length },
  );
  ctx.reportActivity?.(plan.threatModel ? "threat model loaded" : "threat model missing", {
    phase: "threat-model",
    step: 2,
    total: MODULE_RUN_PHASES.length,
  });
  ctx.reportActivity?.(
    `ranked ${plan.catalog.length}/${TAINT_IRIS_NEXT_CWE_CATALOG.length} CWE candidates`,
    { phase: "cwe-catalog", step: 3, total: MODULE_RUN_PHASES.length },
  );
}

function reportEvidenceProgress(
  ctx: ExecutionContext,
  plan: TaintIrisNextPlan,
  evidenceResult: TaintIrisNextEvidenceResult,
): void {
  ctx.reportActivity?.(
    `structural extraction searched ${evidenceResult.queryCount} query seeds; ${evidenceResult.evidence.length} evidence matches`,
    { phase: "structural-extract", step: 4, total: MODULE_RUN_PHASES.length },
  );
  ctx.reportActivity?.(
    `backend ${plan.backend.selected} using ${evidenceResult.tool}; active evidence ${evidenceResult.evidence.length}`,
    { phase: "backend-evidence", step: 5, total: MODULE_RUN_PHASES.length },
  );
}

function reportAgentProgress(
  ctx: ExecutionContext,
  plan: TaintIrisNextPlan,
  agentResult: TaintIrisNextAgentResult,
): void {
  ctx.reportActivity?.(
    `agent selected ${agentResult.selectedCwes.length} CWE themes from ${plan.catalog.length} candidates`,
    { phase: "agent-hunt", step: 6, total: MODULE_RUN_PHASES.length },
  );
  ctx.reportActivity?.(`normalized ${agentResult.findings.length} IRIS Next findings`, {
    phase: "finding-normalize",
    step: 7,
    total: MODULE_RUN_PHASES.length,
  });
}

function dedupe(items: readonly string[]): string[] {
  return [...new Set(items.filter((item) => item.trim().length > 0))];
}

export function createTaintIrisNextModule(): CopilotModule {
  const hunt = defineTool<"taint-iris-next">({
    name: "taint-iris-next:hunt",
    displayName: TAINT_IRIS_NEXT_DISPLAY_NAME,
    description: TAINT_IRIS_NEXT_SHORT_DESCRIPTION,
    headless: true,
    runLifecycle: {
      persistence: "ephemeral",
      resume: "none",
    },
    references: TAINT_IRIS_NEXT_REFERENCES,
    inputSchema: {
      type: "object",
      properties: {
        target: targetProperty,
        mode: {
          type: "string",
          enum: ["plan", "hunt"],
          default: "plan",
          description:
            "Plan deterministically or run one bounded agent session over the generated evidence bundle.",
        },
        backend: {
          type: "string",
          enum: ["auto", "structural", "semgrep", "codeql", "joern", "language"],
          default: "auto",
          description:
            "Evidence backend preference. auto runs structural extraction first; heavy backends are opt-in and never create databases in V1.",
        },
        languages: {
          type: "array",
          items: { type: "string" },
          description:
            "Optional language hints used to rank the CWE catalog when context has not been built yet.",
        },
        maxCatalogEntries: {
          type: "integer",
          default: DEFAULT_TAINT_IRIS_NEXT_CAPS.maxCatalogEntries,
          minimum: 1,
          description:
            "Maximum ranked CWE catalog entries to pass into the agent-facing prompt section.",
        },
        maxEvidencePerCwe: {
          type: "integer",
          default: DEFAULT_TAINT_IRIS_NEXT_CAPS.maxEvidencePerCwe,
          minimum: 1,
          description: "Maximum deterministic evidence rows retained per CWE.",
        },
        maxFilesPerQuery: {
          type: "integer",
          default: DEFAULT_TAINT_IRIS_NEXT_CAPS.maxFilesPerQuery,
          minimum: 1,
          description: "Maximum distinct files retained for a single structural query pattern.",
        },
        maxAgentFindings: {
          type: "integer",
          default: DEFAULT_TAINT_IRIS_NEXT_CAPS.maxAgentFindings,
          minimum: 1,
          description: "Maximum findings accepted from the bounded agent session.",
        },
      },
      required: ["target"],
    },
    formatInput(input) {
      const p = input as Record<string, unknown> | undefined;
      return typeof p?.["target"] === "string" ? (p["target"] as string) : null;
    },
    renderResult(result) {
      if (!result.ok) return null;
      const data = result.data as { mode?: string; findings?: unknown[] } | undefined;
      if (data?.mode === "hunt")
        return `IRIS Next hunt complete (${data.findings?.length ?? 0} findings)`;
      return "IRIS Next plan complete";
    },
    async execute(input: unknown, ctx: ExecutionContext): Promise<ToolResult> {
      const parsed = (input && typeof input === "object" ? input : {}) as TaintIrisNextInput;
      const plan = buildTaintIrisNextPlan(parsed, ctx);
      reportPlanningProgress(ctx, plan);

      if (!hasRequiredContext(plan)) {
        return {
          ok: false,
          output: renderMissingContextGate(plan),
          data: {
            status: "missing-context",
            target: plan.target,
            missing: {
              context: !plan.repoContext,
              threatModel: !plan.threatModel,
            },
          },
        };
      }

      const evidenceResult = await extractTaintIrisNextEvidence(plan, ctx);
      reportEvidenceProgress(ctx, plan, evidenceResult);

      if (plan.mode === "plan") {
        return {
          ok: true,
          output: renderRunOutput(plan, evidenceResult),
          data: {
            status: "planned",
            attribution: TAINT_IRIS_NEXT_ATTRIBUTION,
            references: TAINT_IRIS_NEXT_REFERENCES,
            target: plan.target,
            mode: plan.mode,
            backend: plan.backend,
            caps: plan.caps,
            languages: plan.languages,
            cweCatalog: plan.catalog,
            promptCatalog: plan.promptCatalog,
            structuralQueries: plan.structuralQueries,
            evidence: evidenceResult.evidence,
            agentPrompt: buildTaintIrisNextAgentPrompt(plan, evidenceResult),
          },
        };
      }

      ctx.reportActivity?.(
        `agent hunting across ${plan.catalog.length} candidates and ${evidenceResult.evidence.length} evidence rows`,
        { phase: "agent-hunt", step: 6, total: MODULE_RUN_PHASES.length },
      );
      const agentResult = await runTaintIrisNextAgent(plan, evidenceResult, ctx);
      reportAgentProgress(ctx, plan, agentResult);

      return {
        ok: true,
        output: renderRunOutput(plan, evidenceResult, agentResult),
        costUsd: agentResult.costUsd,
        data: {
          status: "hunted",
          attribution: TAINT_IRIS_NEXT_ATTRIBUTION,
          references: TAINT_IRIS_NEXT_REFERENCES,
          target: plan.target,
          mode: plan.mode,
          backend: plan.backend,
          caps: plan.caps,
          languages: plan.languages,
          cweCatalog: plan.catalog,
          promptCatalog: plan.promptCatalog,
          structuralQueries: plan.structuralQueries,
          evidence: evidenceResult.evidence,
          selectedCwes: agentResult.selectedCwes,
          findings: agentResult.findings,
          warnings: agentResult.warnings,
          rawAgentOutput: agentResult.rawOutput,
        },
      };
    },
  });

  return defineModule({
    id: TAINT_IRIS_NEXT_ID,
    displayName: TAINT_IRIS_NEXT_DISPLAY_NAME,
    category: "defense",
    version: "0.17.2",
    description: TAINT_IRIS_NEXT_SHORT_DESCRIPTION,
    rank: "normal",
    references: TAINT_IRIS_NEXT_REFERENCES,
    notes: {
      stability: ["experimental"],
      reliability: ["backend-dependent"],
      sideEffects: [
        "costs LLM tokens",
        "runs structural search",
        "may run static-analysis backends",
      ],
    },
    requires: [
      { kind: "snapshot", moduleId: "context", field: "appModel" },
      { kind: "snapshot", moduleId: "threat-model", field: "threatModel" },
    ],
    examples: ["use taint-iris-next\nrun . backend=auto mode=plan"],
    tools: [hunt],
  });
}

export const __taintIrisNextInternals = {
  buildTaintIrisNextPlan,
  buildTaintIrisNextAgentPrompt,
  extractTaintIrisNextEvidence,
  renderRunOutput,
};
