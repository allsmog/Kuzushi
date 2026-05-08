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
  TAINT_IRIS_NEXT_LONG_DESCRIPTION,
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
  "spec-inference",
  "link-analysis",
  "backend-evidence",
  "contextual-triage",
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
  const confirmedFindingsCount = agentResult ? confirmedFindingCount(agentResult) : 0;
  const reviewCandidateCount = agentResult?.reviewCandidates.length ?? 0;
  const selectedCwes = agentResult?.selectedCwes.map((selection) => selection.cwe) ?? [];
  const outcome = agentResult?.outcome ?? evidenceResult.outcome;
  const triageSummary = agentResult?.triageSummary ?? evidenceResult.triageSummary;

  return [
    ...TAINT_IRIS_NEXT_TUI_HEADER_LINES,
    "",
    TAINT_IRIS_NEXT_ATTRIBUTION,
    "",
    `target: ${plan.target}`,
    `mode: ${plan.mode}`,
    `outcome: ${outcome}`,
    `backend: ${plan.backend.requested} -> ${plan.backend.selected}`,
    `structural engine: ${evidenceResult.structuralEngine}`,
    plan.backend.corroborateWithCodeql
      ? "CodeQL corroboration: enabled"
      : "CodeQL corroboration: disabled",
    plan.backend.codeqlDbPath
      ? `existing CodeQL DB: ${plan.backend.codeqlDbPath}`
      : "existing CodeQL DB: none",
    `scan root: ${plan.scanRoot}`,
    `repo root: ${plan.repoRoot}`,
    evidenceResult.artifacts?.codeqlLanguage
      ? `CodeQL language: ${evidenceResult.artifacts.codeqlLanguage}`
      : "",
    evidenceResult.artifacts?.codeqlQueryPath
      ? `CodeQL query: ${evidenceResult.artifacts.codeqlQueryPath}`
      : "",
    evidenceResult.artifacts?.codeqlQueryPaths &&
    evidenceResult.artifacts.codeqlQueryPaths.length > 1
      ? `CodeQL queries: ${evidenceResult.artifacts.codeqlQueryPaths.length} per-CWE generated queries`
      : "",
    evidenceResult.artifacts?.codeqlCompileStatus
      ? `CodeQL compile: ${evidenceResult.artifacts.codeqlCompileStatus}`
      : "",
    evidenceResult.artifacts?.codeqlQueryStatuses?.length
      ? `CodeQL per-CWE: ${renderCodeqlStatuses(evidenceResult.artifacts.codeqlQueryStatuses)}`
      : "",
    `context: ${plan.contextStatus.ok ? "loaded" : "missing/incomplete"} (${plan.contextStatus.path ?? plan.contextStatus.reason})`,
    `threat model: ${plan.threatModelStatus.ok ? "loaded" : "warning"} (${plan.threatModelStatus.path ?? plan.threatModelStatus.reason})`,
    `languages: ${plan.languages.join(", ") || "unknown"}`,
    plan.maxBudgetUsd !== undefined ? `max agent budget: $${plan.maxBudgetUsd}` : "",
    `min evidence level: ${plan.caps.minEvidenceLevel}`,
    `CWE catalog: ${plan.catalog.length}/${TAINT_IRIS_NEXT_CWE_CATALOG.length} ranked candidates`,
    `structural query seeds: ${plan.structuralQueries.length}`,
    `candidates: ${evidenceResult.candidates.length} (${renderCounts(evidenceResult.candidateCounts)})`,
    `labeled specs: ${evidenceResult.labeledSpecs.length} (${renderCounts(evidenceResult.labeledSpecCounts)})`,
    `linked stories: ${evidenceResult.linkedStoryCount}`,
    evidenceResult.linkedStories.length > 0
      ? `linked examples: ${renderLinkedStoryExamples(evidenceResult)}`
      : "",
    `backend paths: ${evidenceResult.backendPathCount}`,
    `evidence: ${evidenceResult.evidence.length} rows via ${evidenceResult.tool}`,
    agentResult?.agentStatus ? `agent status: ${agentResult.agentStatus}` : "",
    `agent selected CWEs: ${selectedCwes.length > 0 ? selectedCwes.join(", ") : plan.mode === "hunt" ? "none" : "not run"}`,
    `triage: findings=${triageSummary.finding} candidates=${triageSummary.candidate} rejected=${triageSummary.rejected}`,
    `findings: ${confirmedFindingsCount}`,
    reviewCandidateCount > 0 ? `review candidates: ${reviewCandidateCount}` : "",
    agentResult && !agentResult.structuredOutputValid
      ? `agent output: invalid strict JSON after ${agentResult.structuredOutputRetryCount} repair retry`
      : agentResult
        ? `agent output: valid strict JSON${agentResult.structuredOutputRetryCount ? " after repair retry" : ""}`
        : "",
    agentResult?.parseError ? `agent parse error: ${agentResult.parseError}` : "",
    evidenceResult.legacyComparisonStatus
      ? `legacy comparison status: ${evidenceResult.legacyComparisonStatus}`
      : "",
    warnings.length > 0 ? `warnings: ${dedupe(warnings).join("; ")}` : "",
    "",
    plan.mode === "plan"
      ? "Status: deterministic plan complete. Hunt mode will feed this bounded catalog and evidence bundle into one scoped agent session."
      : outcome === "agent-output-invalid" && findingsCount > 0
        ? "Status: agent output was invalid; deterministic linked review candidates were emitted."
        : outcome === "agent-output-invalid"
          ? "Status: hunt failed closed because the agent did not return valid strict JSON."
          : "Status: hunt complete.",
    "",
    plan.promptCatalog,
  ]
    .filter((line) => line !== "")
    .join("\n");
}

function confirmedFindingCount(agentResult: TaintIrisNextAgentResult): number {
  if (agentResult.reviewCandidates.length === 0) return agentResult.findings.length;
  return Math.max(0, agentResult.findings.length - agentResult.reviewCandidates.length);
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
    `structural extraction via ${evidenceResult.structuralEngine} produced ${evidenceResult.candidates.length} candidates from ${evidenceResult.queryCount} query seeds`,
    { phase: "structural-extract", step: 4, total: MODULE_RUN_PHASES.length },
  );
  ctx.reportActivity?.(
    `spec inference produced ${evidenceResult.labeledSpecs.length} typed IRIS specs`,
    { phase: "spec-inference", step: 5, total: MODULE_RUN_PHASES.length },
  );
  ctx.reportActivity?.(
    `link analysis produced ${evidenceResult.linkedStoryCount} deterministic source-to-sink/control stories`,
    { phase: "link-analysis", step: 6, total: MODULE_RUN_PHASES.length },
  );
  ctx.reportActivity?.(
    `backend evidence used ${plan.backend.selected}/${evidenceResult.tool}; backend paths=${evidenceResult.backendPathCount}`,
    { phase: "backend-evidence", step: 7, total: MODULE_RUN_PHASES.length },
  );
}

function reportAgentProgress(
  ctx: ExecutionContext,
  plan: TaintIrisNextPlan,
  agentResult: TaintIrisNextAgentResult,
): void {
  ctx.reportActivity?.(
    `agent selected ${agentResult.selectedCwes.length} CWE themes from ${plan.catalog.length} candidates`,
    { phase: "contextual-triage", step: 8, total: MODULE_RUN_PHASES.length },
  );
  ctx.reportActivity?.(`normalized ${agentResult.findings.length} IRIS Next findings`, {
    phase: "finding-normalize",
    step: 9,
    total: MODULE_RUN_PHASES.length,
  });
}

function renderCounts(counts: Record<string, number>): string {
  const entries = Object.entries(counts)
    .sort((left, right) => right[1] - left[1])
    .slice(0, 6)
    .map(([cwe, count]) => `${cwe}:${count}`);
  return entries.join(", ") || "none";
}

function dedupe(items: readonly string[]): string[] {
  return [...new Set(items.filter((item) => item.trim().length > 0))];
}

function renderCodeqlStatuses(
  statuses: NonNullable<TaintIrisNextEvidenceResult["artifacts"]>["codeqlQueryStatuses"],
): string {
  return (statuses ?? [])
    .slice(0, 8)
    .map(
      (status) =>
        `${status.cwe} compile=${status.compileStatus} analyze=${status.analyzeStatus} rows=${status.evidenceRows}`,
    )
    .join("; ");
}

function renderLinkedStoryExamples(evidenceResult: TaintIrisNextEvidenceResult): string {
  const candidatesById = new Map(
    evidenceResult.candidates.map((candidate) => [candidate.id, candidate]),
  );
  return evidenceResult.linkedStories
    .slice(0, 4)
    .map((story) => {
      const source = candidatesById.get(story.sourceCandidateId);
      const sink = candidatesById.get(story.sinkCandidateId);
      return `${story.cwe} ${story.filePath}:${story.sourceLine}->${story.sinkLine} ${source?.pattern ?? "source"} => ${sink?.pattern ?? "sink"}`;
    })
    .join("; ");
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
        maxCwes: {
          type: "integer",
          minimum: 1,
          description:
            "Alias for maxCatalogEntries, kept for compatibility with taint-iris-style invocations.",
          "x-advanced": true,
        },
        maxEvidencePerCwe: {
          type: "integer",
          default: DEFAULT_TAINT_IRIS_NEXT_CAPS.maxEvidencePerCwe,
          minimum: 1,
          description: "Maximum deterministic evidence rows retained per CWE.",
        },
        maxCandidatesPerCwe: {
          type: "integer",
          default: DEFAULT_TAINT_IRIS_NEXT_CAPS.maxCandidatesPerCwe,
          minimum: 1,
          description: "Maximum candidate APIs retained per CWE after deterministic extraction.",
        },
        maxFilesPerQuery: {
          type: "integer",
          default: DEFAULT_TAINT_IRIS_NEXT_CAPS.maxFilesPerQuery,
          minimum: 1,
          description: "Maximum distinct files retained for a single structural query pattern.",
        },
        maxSpecsPerCwe: {
          type: "integer",
          default: DEFAULT_TAINT_IRIS_NEXT_CAPS.maxSpecsPerCwe,
          minimum: 1,
          description: "Maximum IRIS-style typed source/sink/sanitizer specs retained per CWE.",
        },
        maxAgentFindings: {
          type: "integer",
          default: DEFAULT_TAINT_IRIS_NEXT_CAPS.maxAgentFindings,
          minimum: 1,
          description: "Maximum findings accepted from the bounded agent session.",
        },
        codeqlAnalyzeTimeoutMs: {
          type: "integer",
          default: DEFAULT_TAINT_IRIS_NEXT_CAPS.codeqlAnalyzeTimeoutMs,
          minimum: 30000,
          maximum: 900000,
          description:
            "Timeout for each generated CodeQL database analyze call. V1 keeps a hard upper cap.",
          "x-advanced": true,
        },
        minEvidenceLevel: {
          type: "string",
          enum: ["path", "linked", "candidate"],
          default: DEFAULT_TAINT_IRIS_NEXT_CAPS.minEvidenceLevel,
          description:
            "Minimum evidence level accepted for agent findings. path requires backend path evidence; linked allows clear source-to-sink/control stories; candidate allows raw candidates.",
        },
        maxBudgetUsd: {
          type: "number",
          minimum: 0,
          description: "Maximum spend for the single IRIS Next agent session.",
          "x-advanced": true,
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
      const data = result.data as
        | {
            mode?: string;
            findings?: unknown[];
            stats?: { totalFindings?: number; totalReviewCandidates?: number };
          }
        | undefined;
      if (data?.mode === "hunt")
        return `IRIS Next hunt complete (${data.stats?.totalFindings ?? data.findings?.length ?? 0} findings${
          data.stats?.totalReviewCandidates
            ? `, ${data.stats.totalReviewCandidates} review candidates`
            : ""
        })`;
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
            contextStatus: plan.contextStatus,
            threatModelStatus: plan.threatModelStatus,
            missing: {
              context: !plan.contextStatus.ok,
              threatModel: !plan.threatModelStatus.ok,
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
            maxBudgetUsd: plan.maxBudgetUsd,
            languages: plan.languages,
            cweCatalog: plan.catalog,
            promptCatalog: plan.promptCatalog,
            structuralQueries: plan.structuralQueries,
            evidence: evidenceResult.evidence,
            candidates: evidenceResult.candidates,
            linkedStories: evidenceResult.linkedStories,
            labeledSpecs: evidenceResult.labeledSpecs,
            outcome: evidenceResult.outcome,
            candidateCounts: evidenceResult.candidateCounts,
            labeledSpecCounts: evidenceResult.labeledSpecCounts,
            linkedStoryCount: evidenceResult.linkedStoryCount,
            backendPathCount: evidenceResult.backendPathCount,
            structuralEngine: evidenceResult.structuralEngine,
            triageSummary: evidenceResult.triageSummary,
            legacyComparisonStatus: evidenceResult.legacyComparisonStatus,
            evidenceResult,
            agentPrompt: buildTaintIrisNextAgentPrompt(plan, evidenceResult),
          },
        };
      }

      ctx.reportActivity?.(
        `contextual triage across ${plan.catalog.length} catalog candidates and ${evidenceResult.evidence.length} evidence rows`,
        { phase: "contextual-triage", step: 8, total: MODULE_RUN_PHASES.length },
      );
      const agentResult = await runTaintIrisNextAgent(plan, evidenceResult, ctx);
      reportAgentProgress(ctx, plan, agentResult);
      const invalidAgentOutput = agentResult.outcome === "agent-output-invalid";
      const hardInvalidAgentOutput = invalidAgentOutput && agentResult.findings.length === 0;
      const totalFindings = confirmedFindingCount(agentResult);
      const totalReviewCandidates = agentResult.reviewCandidates.length;

      return {
        ok: !hardInvalidAgentOutput,
        output: renderRunOutput(plan, evidenceResult, agentResult),
        costUsd: agentResult.costUsd,
        data: {
          status: invalidAgentOutput
            ? agentResult.findings.length > 0
              ? "hunted-with-agent-output-invalid"
              : "agent-output-invalid"
            : "hunted",
          attribution: TAINT_IRIS_NEXT_ATTRIBUTION,
          references: TAINT_IRIS_NEXT_REFERENCES,
          target: plan.target,
          mode: plan.mode,
          backend: plan.backend,
          caps: plan.caps,
          maxBudgetUsd: plan.maxBudgetUsd,
          languages: plan.languages,
          cweCatalog: plan.catalog,
          promptCatalog: plan.promptCatalog,
          structuralQueries: plan.structuralQueries,
          evidence: evidenceResult.evidence,
          candidates: evidenceResult.candidates,
          linkedStories: evidenceResult.linkedStories,
          labeledSpecs: evidenceResult.labeledSpecs,
          outcome: agentResult.outcome,
          candidateCounts: evidenceResult.candidateCounts,
          labeledSpecCounts: evidenceResult.labeledSpecCounts,
          linkedStoryCount: evidenceResult.linkedStoryCount,
          backendPathCount: evidenceResult.backendPathCount,
          structuralEngine: evidenceResult.structuralEngine,
          triageSummary: agentResult.triageSummary,
          legacyComparisonStatus: evidenceResult.legacyComparisonStatus,
          stats: {
            totalFindings,
            totalReviewCandidates,
            totalCandidates: evidenceResult.candidates.length,
            totalLinkedStories: evidenceResult.linkedStoryCount,
            backendPathCount: evidenceResult.backendPathCount,
            totalCostUsd: agentResult.costUsd,
          },
          evidenceResult,
          agentStatus: agentResult.agentStatus,
          selectedCwes: agentResult.selectedCwes,
          findings: agentResult.findings,
          reviewCandidates: agentResult.reviewCandidates,
          triage: agentResult.triage,
          warnings: agentResult.warnings,
          rawAgentOutput: agentResult.rawOutput,
          structuredOutputValid: agentResult.structuredOutputValid,
          structuredOutputRetryCount: agentResult.structuredOutputRetryCount,
          parseError: agentResult.parseError,
          resultTextExcerpt: agentResult.resultTextExcerpt,
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
    longDescription: TAINT_IRIS_NEXT_LONG_DESCRIPTION,
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
    requires: [{ kind: "snapshot", moduleId: "context", field: "appModel" }],
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
