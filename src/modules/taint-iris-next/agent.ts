import { createHash } from "node:crypto";
import path from "node:path";
import type { AgentMessage } from "../../agent-runtime/types.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TaintPathStep } from "../../scanners/types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { ExecutionContext } from "../types.js";
import { queryIrisAgentOnce, resolveIrisAgentStatus } from "./agent-adapter.js";
import { TAINT_IRIS_NEXT_ATTRIBUTION, TAINT_IRIS_NEXT_TUI_HEADER_LINES } from "./copy.js";
import { validateAgentCweSelections } from "./cwe-reference.js";
import {
  createIrisEvidenceTools,
  evidenceMeetsMinimum,
  rankLinkedStoriesForReview,
  strongestEvidenceLevelForCwe,
  summarizeTriage,
} from "./evidence-tools.js";
import type {
  TaintIrisNextAgentFinding,
  TaintIrisNextAgentOutput,
  TaintIrisNextAgentResult,
  TaintIrisNextAgentSelection,
  TaintIrisNextAgentTriageDecision,
  TaintIrisNextEvidence,
  TaintIrisNextEvidenceLevel,
  TaintIrisNextEvidenceResult,
  TaintIrisNextPlan,
  TaintIrisNextTriageSummary,
} from "./types.js";

export const TAINT_IRIS_NEXT_AGENT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["selectedCwes", "findings", "triage", "notes"],
  properties: {
    selectedCwes: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "cwe",
          "reason",
          "catalogSignals",
          "sourceSpec",
          "sinkSpec",
          "sanitizerSpec",
          "customCweRationale",
        ],
        properties: {
          cwe: { type: "string" },
          reason: { type: "string" },
          catalogSignals: { type: "array", items: { type: "string" } },
          sourceSpec: { type: "string" },
          sinkSpec: { type: "string" },
          sanitizerSpec: { type: "string" },
          customCweRationale: { type: "string" },
        },
      },
    },
    findings: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "title",
          "cwe",
          "severity",
          "confidence",
          "evidenceLevel",
          "filePath",
          "startLine",
          "message",
          "sourceSinkTrace",
          "catalogSignals",
          "customCweRationale",
          "taintPath",
        ],
        properties: {
          title: { type: "string" },
          cwe: { type: "string" },
          severity: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
          confidence: { type: "string", enum: ["high", "medium", "low"] },
          evidenceLevel: { type: "string", enum: ["path", "linked", "candidate"] },
          filePath: { type: "string" },
          startLine: { type: "integer" },
          message: { type: "string" },
          sourceSinkTrace: { type: "string" },
          catalogSignals: { type: "array", items: { type: "string" } },
          customCweRationale: { type: "string" },
          taintPath: {
            type: "array",
            items: {
              type: "object",
              additionalProperties: false,
              required: ["filePath", "line", "message", "snippet"],
              properties: {
                filePath: { type: "string" },
                line: { type: "integer" },
                message: { type: "string" },
                snippet: { type: "string" },
              },
            },
          },
        },
      },
    },
    triage: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: [
          "status",
          "cwe",
          "evidenceLevel",
          "rationale",
          "filePath",
          "line",
          "catalogSignals",
        ],
        properties: {
          status: { type: "string", enum: ["finding", "candidate", "rejected"] },
          cwe: { type: "string" },
          evidenceLevel: { type: "string", enum: ["path", "linked", "candidate"] },
          rationale: { type: "string" },
          filePath: { type: "string" },
          line: { type: "integer" },
          catalogSignals: { type: "array", items: { type: "string" } },
        },
      },
    },
    notes: { type: "array", items: { type: "string" } },
  },
} as const;

export function buildTaintIrisNextAgentPrompt(
  plan: TaintIrisNextPlan,
  evidenceResult: TaintIrisNextEvidenceResult,
): string {
  return [
    ...TAINT_IRIS_NEXT_TUI_HEADER_LINES,
    "",
    TAINT_IRIS_NEXT_ATTRIBUTION,
    "",
    "You are Kuzushi's Taint IRIS Next agent. This is an agent-forward adaptation inspired by the IRIS paper, not the original IRIS implementation.",
    "",
    "## Objective",
    "Mirror the IRIS paper shape while adapting it to Kuzushi: candidate extraction, typed source/sink labeling, backend path detection, then contextual false-positive triage.",
    "Use the deterministic context, threat model, CWE catalog, candidates, typed specs, and evidence bundles below to select relevant CWE themes and report only defensible findings.",
    "Do not invent a vulnerability class when a catalog CWE fits. If you use a non-catalog CWE, include customCweRationale.",
    "",
    "## IRIS-Inspired Phases",
    `candidate extraction: ${evidenceResult.candidates.length} candidates from structural/backend/context signals`,
    `spec inference: ${evidenceResult.labeledSpecs.length} typed source/sink/sanitizer/propagator specs`,
    `link analysis: ${evidenceResult.linkedStoryCount} deterministic linked source-to-sink/control stories`,
    `path detection: ${evidenceResult.backendPathCount} backend path evidence rows`,
    "contextual triage: classify each path/linked story as finding, candidate, or rejected with rationale",
    `minimum finding evidence level: ${plan.caps.minEvidenceLevel}`,
    "",
    "## Backend",
    `requested: ${plan.backend.requested}`,
    `selected: ${plan.backend.selected}`,
    `structural engine: ${evidenceResult.structuralEngine}`,
    `evidence tool: ${evidenceResult.tool}`,
    `CodeQL corroboration: ${plan.backend.corroborateWithCodeql ? "enabled" : "disabled"}`,
    plan.backend.codeqlDbPath
      ? `existing CodeQL DB: ${plan.backend.codeqlDbPath}`
      : "existing CodeQL DB: none",
    "",
    "## Context Summary",
    renderContextSummary(plan),
    "",
    "## Threat Model Summary",
    renderThreatModelSummary(plan),
    "",
    plan.promptCatalog,
    "",
    "## Candidate And Spec Counts",
    `candidateCounts: ${JSON.stringify(evidenceResult.candidateCounts)}`,
    `labeledSpecCounts: ${JSON.stringify(evidenceResult.labeledSpecCounts)}`,
    "",
    "## Evidence Bundles",
    renderEvidenceBundles(evidenceResult.evidence),
    "",
    "## Linked Stories",
    renderLinkedStories(evidenceResult),
    "",
    "## Available IRIS Evidence Tools",
    "- list_candidates: inspect bounded deterministic candidates by CWE/role/track.",
    "- get_candidate_context: inspect nearby same-file evidence for one candidate.",
    "- label_taint_specs: inspect generated IRIS-style typed specs.",
    "- run_backend_query: inspect already-run backend query artifacts and path evidence.",
    "- get_path_context: inspect path or linked source-to-sink/control evidence.",
    "- record_triage: validate contextual triage decisions before final JSON.",
    "",
    "## Contract",
    "- Select final CWE themes only from the CWE Candidate Catalog unless customCweRationale is present.",
    "- Cite catalogSignals for every selected CWE and every finding.",
    "- Refine sourceSpec, sinkSpec, and sanitizerSpec from the evidence and threat model.",
    "- Return strict JSON matching the schema: { selectedCwes, findings, triage, notes }.",
    `- Return at most ${plan.caps.maxAgentFindings} findings.`,
    "- Findings must include evidenceLevel, filePath, startLine, sourceSinkTrace, catalogSignals, and taintPath.",
    "- Raw keyword/structural hits are candidate evidence only. They are not findings-grade evidence by themselves.",
    "- Findings require backend path evidence or a clearly linked source-to-sink/control story unless minEvidenceLevel=candidate.",
    "- Authz/auth/control CWEs require guard/policy/path-context reasoning, not generic source-to-sink taint claims.",
    "- If evidence bundles are non-empty but you select no CWEs, notes[0] must start with NO_SELECTION: and explain why the evidence is insufficient.",
  ].join("\n");
}

export async function runTaintIrisNextAgent(
  plan: TaintIrisNextPlan,
  evidenceResult: TaintIrisNextEvidenceResult,
  ctx: ExecutionContext,
): Promise<TaintIrisNextAgentResult> {
  const prompt = buildTaintIrisNextAgentPrompt(plan, evidenceResult);
  const abortController = new AbortController();
  const abortFromContext = (): void => abortController.abort();
  if (ctx.signal?.aborted) abortController.abort();
  ctx.signal?.addEventListener("abort", abortFromContext, { once: true });

  const fingerprint = "taint-iris-next:agent";
  ctx.reportAgentActivity?.(fingerprint, "tool-start", {
    toolName: "IRIS Next Agent",
    summary: "selecting CWE themes from bounded evidence",
    index: 1,
    total: 1,
  });

  const customTools = createIrisEvidenceTools(plan, evidenceResult);
  let retryCount = 0;
  let queryResult: AgentQueryOnceResult = {
    agentRuntimeBackend: ctx.runtime.id,
    resultText: "",
    structuredOutput: undefined,
    costUsd: 0,
    runtimeErrors: [],
  };

  try {
    queryResult = await queryAgentOnce({
      ctx,
      plan,
      prompt,
      abortController,
      fingerprint,
      customTools,
    });
    let parsedRaw = parseRawAgentOutput(queryResult.structuredOutput, queryResult.resultText);
    const budgetExceededAfterFirstCall =
      plan.maxBudgetUsd !== undefined && queryResult.costUsd >= plan.maxBudgetUsd;
    if (!isRecord(parsedRaw.rawOutput) && !ctx.signal?.aborted && !budgetExceededAfterFirstCall) {
      retryCount = 1;
      ctx.reportAgentActivity?.(fingerprint, "reasoning", {
        summary: "structured output missing; retrying with compact JSON-only repair prompt",
      });
      const repair = await queryAgentOnce({
        ctx,
        plan,
        prompt: buildCompactRepairPrompt(plan, evidenceResult, parsedRaw.parseError),
        abortController,
        fingerprint: `${fingerprint}:repair`,
        customTools,
      });
      queryResult = {
        agentRuntimeBackend: repair.agentRuntimeBackend,
        resultText: repair.resultText,
        structuredOutput: repair.structuredOutput,
        costUsd: queryResult.costUsd + repair.costUsd,
        runtimeErrors: [...queryResult.runtimeErrors, ...repair.runtimeErrors],
      };
      parsedRaw = parseRawAgentOutput(queryResult.structuredOutput, queryResult.resultText);
    }

    if (!isRecord(parsedRaw.rawOutput)) {
      const warnings = [
        ...queryResult.runtimeErrors.map((error) => `agent runtime error: ${error}`),
        "agent returned no structured JSON output",
        `parse error: ${parsedRaw.parseError}`,
      ];
      if (budgetExceededAfterFirstCall) {
        warnings.push(
          `agent repair retry skipped because cost $${queryResult.costUsd.toFixed(4)} reached maxBudgetUsd $${plan.maxBudgetUsd?.toFixed(4)}`,
        );
      }
      const fallbackFindings = buildDeterministicLinkedFindings(plan, evidenceResult);
      const fallbackSelections = buildDeterministicLinkedSelections(evidenceResult);
      const fallbackTriage = buildDeterministicLinkedTriage(evidenceResult);
      if (fallbackFindings.length > 0) {
        warnings.push(
          `agent output invalid; returning ${fallbackFindings.length} deterministic linked finding candidate(s) for review`,
        );
      }
      return {
        agentRuntimeBackend: queryResult.agentRuntimeBackend,
        agentStatus: "invalid-json",
        selectedCwes: fallbackSelections,
        findings: fallbackFindings,
        reviewCandidates: fallbackFindings,
        triage: fallbackTriage,
        triageSummary: summarizeTriage(fallbackTriage),
        outcome: "agent-output-invalid",
        rawOutput: parsedRaw.rawOutput,
        structuredOutputValid: false,
        structuredOutputRetryCount: retryCount,
        parseError: parsedRaw.parseError,
        resultTextExcerpt: excerpt(queryResult.resultText),
        warnings,
        costUsd: queryResult.costUsd,
      };
    }
  } catch (error) {
    throw new Error(`[taint-iris-next] Agent error: ${toErrorMessage(error)}`);
  } finally {
    ctx.signal?.removeEventListener("abort", abortFromContext);
    ctx.reportAgentActivity?.(fingerprint, "tool-complete", {
      summary: "IRIS Next agent session complete",
      index: 1,
      total: 1,
      done: true,
    });
  }

  const parsedRaw = parseRawAgentOutput(queryResult.structuredOutput, queryResult.resultText);
  const rawOutput = parsedRaw.rawOutput;
  const parsed = parseAgentOutput(rawOutput);
  const warnings: string[] = [];
  warnings.push(...queryResult.runtimeErrors.map((error) => `agent runtime error: ${error}`));
  if (evidenceResult.evidence.length > 0 && parsed.selectedCwes.length === 0) {
    const rationale = parsed.notes?.find((note) => note.trim().startsWith("NO_SELECTION:"));
    warnings.push(
      rationale ??
        `agent selected no CWEs from ${evidenceResult.evidence.length} evidence row(s) and did not provide a NO_SELECTION rationale`,
    );
  }
  if (
    parsed.selectedCwes.length === 0 &&
    parsed.findings.length === 0 &&
    evidenceResult.linkedStories.length > 0 &&
    evidenceMeetsMinimum("linked", plan.caps.minEvidenceLevel)
  ) {
    const fallbackFindings = buildDeterministicLinkedFindings(plan, evidenceResult);
    const fallbackSelections = buildDeterministicLinkedSelections(evidenceResult);
    const fallbackTriage = buildDeterministicLinkedTriage(evidenceResult);
    if (fallbackFindings.length > 0) {
      warnings.push(
        `agent selected no CWEs; returning ${fallbackFindings.length} deterministic linked finding candidate(s) for review`,
      );
      return {
        agentRuntimeBackend: queryResult.agentRuntimeBackend,
        agentStatus: "no-selection-fallback",
        selectedCwes: fallbackSelections,
        findings: fallbackFindings,
        reviewCandidates: fallbackFindings,
        triage: fallbackTriage,
        triageSummary: summarizeTriage(fallbackTriage),
        outcome: "agent-no-selection",
        rawOutput,
        structuredOutputValid: true,
        structuredOutputRetryCount: retryCount,
        warnings,
        costUsd: queryResult.costUsd,
      };
    }
  }
  const selectionValidation = validateAgentCweSelections(parsed.selectedCwes, plan.catalog);
  if (!selectionValidation.valid) {
    const rejected = selectionValidation.rejected
      .map((item) => `${item.cwe}: ${item.reason}`)
      .join("; ");
    throw new Error(`[taint-iris-next] Agent selected invalid CWEs: ${rejected}`);
  }

  const findings = normalizeAgentFindings(parsed.findings, plan, evidenceResult.evidence, warnings);
  const triage = parsed.triage;
  const triageSummary =
    triage.length > 0 ? summarizeTriage(triage) : fallbackTriageSummary(findings.length);
  const agentStatus = resolveIrisAgentStatus({
    structuredOutputValid: true,
    retryCount,
    selectedCweCount: selectionValidation.accepted.length,
    findingCount: findings.length,
    reviewCandidateCount: 0,
  });
  const outcome =
    evidenceResult.evidence.length > 0 && parsed.selectedCwes.length === 0
      ? "agent-no-selection"
      : findings.length > 0
        ? evidenceResult.outcome
        : evidenceResult.outcome;
  return {
    agentRuntimeBackend: queryResult.agentRuntimeBackend,
    agentStatus,
    selectedCwes: selectionValidation.accepted,
    findings: findings.slice(0, plan.caps.maxAgentFindings),
    reviewCandidates: [],
    triage,
    triageSummary,
    outcome,
    rawOutput,
    structuredOutputValid: true,
    structuredOutputRetryCount: retryCount,
    warnings,
    costUsd: queryResult.costUsd,
  };
}

interface AgentQueryOnceResult {
  agentRuntimeBackend: string;
  resultText: string;
  structuredOutput: unknown;
  costUsd: number;
  runtimeErrors: string[];
}

async function queryAgentOnce(options: {
  ctx: ExecutionContext;
  plan: TaintIrisNextPlan;
  prompt: string;
  abortController: AbortController;
  fingerprint: string;
  customTools: ReturnType<typeof createIrisEvidenceTools>;
}): Promise<AgentQueryOnceResult> {
  const result = await queryIrisAgentOnce({
    runtime: options.ctx.runtime,
    prompt: options.prompt,
    cwd: options.plan.repoRoot,
    model: options.ctx.toolModel ?? options.ctx.modelOverride ?? options.ctx.config.model,
    allowedTools: ["Read", "Grep", "Glob", ...options.customTools.map((tool) => tool.name)],
    customTools: options.customTools,
    abortController: options.abortController,
    taskId: "taint-iris-next:hunt",
    fingerprint: options.fingerprint,
    maxBudgetUsd: options.plan.maxBudgetUsd,
    outputFormat: {
      type: "json_schema",
      schema: TAINT_IRIS_NEXT_AGENT_SCHEMA,
      strict: true,
      retryInvalidStructuredOutput: 2,
    },
    signal: options.ctx.signal,
    forwardActivity: (message) => forwardAgentActivity(options.ctx, options.fingerprint, message),
  });

  return {
    agentRuntimeBackend: result.agentRuntimeBackend,
    resultText: result.resultText,
    structuredOutput: result.structuredOutput,
    costUsd: result.costUsd,
    runtimeErrors: result.runtimeErrors,
  };
}

function buildCompactRepairPrompt(
  plan: TaintIrisNextPlan,
  evidenceResult: TaintIrisNextEvidenceResult,
  parseError: string,
): string {
  return [
    'Return only strict JSON matching this shape: {"selectedCwes":[],"findings":[],"triage":[],"notes":[]}.',
    "No markdown, no prose outside JSON.",
    `Previous structured output parse error: ${parseError}`,
    `Minimum finding evidence level: ${plan.caps.minEvidenceLevel}`,
    `Backend: ${plan.backend.selected}; structural engine: ${evidenceResult.structuralEngine}; evidence rows: ${evidenceResult.evidence.length}; linked stories: ${evidenceResult.linkedStoryCount}; backend paths: ${evidenceResult.backendPathCount}`,
    `Candidate counts: ${JSON.stringify(evidenceResult.candidateCounts)}`,
    `Catalog CWEs: ${plan.catalog.map((entry) => entry.cwe).join(", ")}`,
    "If you select no CWEs while evidence rows exist, notes[0] must start with NO_SELECTION:.",
    "Candidate evidence summary:",
    renderEvidenceBundles(evidenceResult.evidence.slice(0, 24)),
    "Linked story summary:",
    renderLinkedStories(evidenceResult),
  ].join("\n");
}

export function parseAgentOutput(raw: unknown): TaintIrisNextAgentOutput {
  if (!isRecord(raw)) return { selectedCwes: [], findings: [], triage: [], notes: [] };
  const selectedCwes = Array.isArray(raw["selectedCwes"])
    ? raw["selectedCwes"]
        .map(parseSelection)
        .filter((item): item is TaintIrisNextAgentSelection => !!item)
    : [];
  const findings = Array.isArray(raw["findings"])
    ? raw["findings"].map(parseFinding).filter((item): item is TaintIrisNextAgentFinding => !!item)
    : [];
  const notes = Array.isArray(raw["notes"])
    ? raw["notes"].filter((item): item is string => typeof item === "string")
    : [];
  const triage = Array.isArray(raw["triage"])
    ? raw["triage"]
        .map(parseTriageDecision)
        .filter((item): item is TaintIrisNextAgentTriageDecision => !!item)
    : [];
  return { selectedCwes, findings, triage, notes };
}

function normalizeAgentFindings(
  rawFindings: readonly TaintIrisNextAgentFinding[],
  plan: TaintIrisNextPlan,
  evidence: readonly TaintIrisNextEvidence[],
  warnings: string[],
): Finding[] {
  const catalogIds = new Set(plan.catalog.map((entry) => entry.cwe));
  const out: Finding[] = [];

  for (const item of rawFindings) {
    const cwe = item.cwe.trim().toUpperCase();
    if (!catalogIds.has(cwe) && !item.customCweRationale?.trim()) {
      warnings.push(`dropped finding with non-catalog CWE ${cwe} and no customCweRationale`);
      continue;
    }
    if (!item.title.trim() || !item.filePath.trim() || !item.message.trim()) continue;

    const severity = mapSeverity(item.severity);
    const confidence = mapConfidence(item.confidence);
    const normalizedPath = normalizePath(plan.repoRoot, item.filePath);
    const startLine = Math.max(1, Math.floor(Number(item.startLine) || 1));
    const relatedEvidence = evidence.filter((candidate) => candidate.cwe === cwe).slice(0, 4);
    const evidenceLevel = evidenceLevelForFinding(item, cwe, evidence);
    if (!evidenceMeetsMinimum(evidenceLevel, plan.caps.minEvidenceLevel)) {
      warnings.push(
        `dropped ${cwe} finding below minEvidenceLevel=${plan.caps.minEvidenceLevel}; strongest evidence was ${evidenceLevel}`,
      );
      continue;
    }
    const taintPath = normalizeTaintPath(item, plan.repoRoot, relatedEvidence);
    const fingerprint = createHash("sha256")
      .update(
        ["taint-iris-next", plan.repoRoot, cwe, normalizedPath, startLine, item.title].join("|"),
      )
      .digest("hex");

    out.push({
      taskId: "taint-iris-next",
      fingerprint,
      ruleId: `taint-iris-next/${cwe || "custom"}`,
      filePath: normalizedPath,
      startLine,
      severity,
      message: `[${cwe}] ${item.title}: ${item.message}`,
      evidence: item.sourceSinkTrace || renderEvidenceSummary(relatedEvidence),
      scannerConfidence: confidence,
      subcategory: [
        "taint",
        plan.catalog.find((entry) => entry.cwe === cwe)?.taintClass ?? "custom",
      ],
      likelihood: confidence,
      impact: severity === "ERROR" ? "HIGH" : severity === "WARNING" ? "MEDIUM" : "LOW",
      cwe: cwe ? [cwe] : [],
      score: scoreFindingMetadata({
        severity,
        likelihood: confidence,
        impact: severity === "ERROR" ? "HIGH" : severity === "WARNING" ? "MEDIUM" : "LOW",
        subcategory: ["taint"],
      }),
      taintPath: taintPath.length > 0 ? taintPath : undefined,
      proofState: "symbolic_only",
      engineProvenance: [
        {
          kind: "agentic",
          detail: `taint-iris-next agent-forward adaptation; backend=${plan.backend.selected}; cwe=${cwe}; evidenceLevel=${evidenceLevel}`,
        },
        {
          kind: plan.backend.selected === "codeql" ? "codeql" : "taint-analysis",
          detail: `evidence source=${plan.backend.selected}; bundled signals=${relatedEvidence.length}; minEvidenceLevel=${plan.caps.minEvidenceLevel}`,
        },
      ],
    });
  }

  return out;
}

function buildDeterministicLinkedSelections(
  evidenceResult: TaintIrisNextEvidenceResult,
): TaintIrisNextAgentSelection[] {
  const candidatesById = new Map(
    evidenceResult.candidates.map((candidate) => [candidate.id, candidate]),
  );
  const byCwe = new Map<string, TaintIrisNextAgentSelection>();
  for (const story of rankLinkedStoriesForReview(
    evidenceResult.linkedStories,
    evidenceResult.candidates,
  )) {
    const source = candidatesById.get(story.sourceCandidateId);
    const sink = candidatesById.get(story.sinkCandidateId);
    if (!source || !sink) continue;
    if (byCwe.has(story.cwe)) continue;
    byCwe.set(story.cwe, {
      cwe: story.cwe,
      reason: `Deterministic structural linker produced ${story.evidenceLevel} evidence before agent JSON validation failed.`,
      catalogSignals: [source.catalogSignal, sink.catalogSignal],
      sourceSpec: source.catalogSignal,
      sinkSpec: sink.catalogSignal,
      sanitizerSpec: "",
      customCweRationale: "",
    });
  }
  return [...byCwe.values()];
}

function buildDeterministicLinkedTriage(
  evidenceResult: TaintIrisNextEvidenceResult,
): TaintIrisNextAgentTriageDecision[] {
  const candidatesById = new Map(
    evidenceResult.candidates.map((candidate) => [candidate.id, candidate]),
  );
  return rankLinkedStoriesForReview(evidenceResult.linkedStories, evidenceResult.candidates)
    .slice(0, 20)
    .map((story) => {
      const source = candidatesById.get(story.sourceCandidateId);
      const sink = candidatesById.get(story.sinkCandidateId);
      return {
        status: "finding",
        cwe: story.cwe,
        evidenceLevel: "linked",
        rationale: `Deterministic fallback: ${story.rationale}`,
        filePath: story.filePath,
        line: story.sinkLine,
        catalogSignals: [source?.catalogSignal, sink?.catalogSignal].filter(
          (signal): signal is string => !!signal,
        ),
      };
    });
}

function buildDeterministicLinkedFindings(
  plan: TaintIrisNextPlan,
  evidenceResult: TaintIrisNextEvidenceResult,
): Finding[] {
  if (!evidenceMeetsMinimum("linked", plan.caps.minEvidenceLevel)) return [];
  const candidatesById = new Map(
    evidenceResult.candidates.map((candidate) => [candidate.id, candidate]),
  );
  const findings: Finding[] = [];
  const rankedStories = rankLinkedStoriesForReview(
    evidenceResult.linkedStories,
    evidenceResult.candidates,
  );
  for (const story of rankedStories.slice(0, plan.caps.maxAgentFindings)) {
    const source = candidatesById.get(story.sourceCandidateId);
    const sink = candidatesById.get(story.sinkCandidateId);
    if (!source || !sink) continue;
    const severity = deterministicSeverityForCwe(story.cwe);
    const confidence = story.sharedTokens.length > 0 ? "MEDIUM" : "LOW";
    const fingerprint = createHash("sha256")
      .update(
        [
          "taint-iris-next",
          "deterministic-linked",
          plan.repoRoot,
          story.cwe,
          story.filePath,
          story.sourceLine,
          story.sinkLine,
          story.rationale,
        ].join("|"),
      )
      .digest("hex");
    findings.push({
      taskId: "taint-iris-next",
      fingerprint,
      ruleId: `taint-iris-next/${story.cwe}`,
      filePath: story.filePath,
      startLine: story.sinkLine,
      severity,
      message: `[${story.cwe}] Linked ${story.taintClass} candidate: ${story.rationale}. Agent triage output was invalid, so review before treating as confirmed.`,
      evidence: `${source.snippet} -> ${sink.snippet}`,
      scannerConfidence: confidence,
      subcategory: ["taint", story.taintClass],
      likelihood: confidence,
      impact: severity === "ERROR" ? "HIGH" : severity === "WARNING" ? "MEDIUM" : "LOW",
      cwe: [story.cwe],
      score: scoreFindingMetadata({
        severity,
        likelihood: confidence,
        impact: severity === "ERROR" ? "HIGH" : severity === "WARNING" ? "MEDIUM" : "LOW",
        subcategory: ["taint"],
      }),
      taintPath: [
        {
          filePath: source.filePath,
          line: source.line,
          message: `source: ${source.catalogSignal}`,
          snippet: source.snippet,
        },
        {
          filePath: sink.filePath,
          line: sink.line,
          message: `sink: ${sink.catalogSignal}`,
          snippet: sink.snippet,
        },
      ],
      proofState: "symbolic_only",
      engineProvenance: [
        {
          kind: "taint-analysis",
          detail: `taint-iris-next deterministic structural fallback; backend=${plan.backend.selected}; cwe=${story.cwe}; linkedStory=${story.id}`,
        },
        {
          kind: "agentic",
          detail:
            "agent output was invalid strict JSON; finding emitted as review candidate from linked evidence",
        },
      ],
    });
  }
  return findings;
}

function deterministicSeverityForCwe(cwe: string): Finding["severity"] {
  if (cwe === "CWE-77" || cwe === "CWE-78" || cwe === "CWE-89" || cwe === "CWE-94") {
    return "ERROR";
  }
  if (cwe === "CWE-22" || cwe === "CWE-502" || cwe === "CWE-611" || cwe === "CWE-918") {
    return "WARNING";
  }
  return "NOTE";
}

function parseSelection(raw: unknown): TaintIrisNextAgentSelection | undefined {
  if (!isRecord(raw)) return undefined;
  const cwe = str(raw["cwe"]);
  if (!cwe) return undefined;
  return {
    cwe,
    reason: str(raw["reason"]) || undefined,
    signalCitations: stringArray(raw["signalCitations"]),
    catalogSignals: stringArray(raw["catalogSignals"]),
    sourceSpec: str(raw["sourceSpec"]) || undefined,
    sinkSpec: str(raw["sinkSpec"]) || undefined,
    sanitizerSpec: str(raw["sanitizerSpec"]) || undefined,
    customCweRationale: str(raw["customCweRationale"]) || undefined,
  };
}

function parseFinding(raw: unknown): TaintIrisNextAgentFinding | undefined {
  if (!isRecord(raw)) return undefined;
  const title = str(raw["title"]);
  const cwe = str(raw["cwe"]);
  const filePath = str(raw["filePath"]);
  const message = str(raw["message"]);
  if (!title || !cwe || !filePath || !message) return undefined;
  return {
    title,
    cwe,
    severity: mapAgentSeverity(str(raw["severity"])),
    confidence: mapAgentConfidence(str(raw["confidence"])),
    evidenceLevel: mapEvidenceLevel(str(raw["evidenceLevel"])),
    filePath,
    startLine: Math.max(1, Math.floor(Number(raw["startLine"]) || 1)),
    message,
    sourceSinkTrace: str(raw["sourceSinkTrace"]),
    catalogSignals: stringArray(raw["catalogSignals"]),
    customCweRationale: str(raw["customCweRationale"]) || undefined,
    taintPath: parseTaintPath(raw["taintPath"]),
  };
}

function parseTriageDecision(raw: unknown): TaintIrisNextAgentTriageDecision | undefined {
  if (!isRecord(raw)) return undefined;
  const cwe = str(raw["cwe"]);
  const rationale = str(raw["rationale"]);
  if (!cwe || !rationale) return undefined;
  const decision: TaintIrisNextAgentTriageDecision = {
    status: mapTriageStatus(str(raw["status"])),
    cwe,
    evidenceLevel: mapEvidenceLevel(str(raw["evidenceLevel"])),
    rationale,
    line: Math.max(1, Math.floor(Number(raw["line"]) || 1)),
    catalogSignals: stringArray(raw["catalogSignals"]),
  };
  const filePath = str(raw["filePath"]);
  if (filePath) decision.filePath = filePath;
  return decision;
}

function parseTaintPath(raw: unknown): TaintIrisNextAgentFinding["taintPath"] {
  if (!Array.isArray(raw)) return [];
  const out: NonNullable<TaintIrisNextAgentFinding["taintPath"]> = [];
  for (const item of raw) {
    if (!isRecord(item)) continue;
    const filePath = str(item["filePath"]);
    if (!filePath) continue;
    out.push({
      filePath,
      line: Math.max(1, Math.floor(Number(item["line"]) || 1)),
      message: str(item["message"]) || undefined,
      snippet: str(item["snippet"]) || undefined,
    });
  }
  return out;
}

function evidenceLevelForFinding(
  item: TaintIrisNextAgentFinding,
  cwe: string,
  evidence: readonly TaintIrisNextEvidence[],
): TaintIrisNextEvidenceLevel {
  const strongest = strongestEvidenceLevelForCwe(cwe, evidence);
  if (strongest === "path") return "path";
  if (strongest === "linked") return "linked";
  if ((item.taintPath?.length ?? 0) >= 2) return "linked";
  if (item.evidenceLevel === "path" || item.evidenceLevel === "linked") {
    return strongest === "candidate" ? "candidate" : item.evidenceLevel;
  }
  return "candidate";
}

function fallbackTriageSummary(findingCount: number): TaintIrisNextTriageSummary {
  return { finding: findingCount, candidate: 0, rejected: 0 };
}

function normalizeTaintPath(
  item: TaintIrisNextAgentFinding,
  repoRoot: string,
  evidence: readonly TaintIrisNextEvidence[],
): TaintPathStep[] {
  const explicit = item.taintPath ?? [];
  if (explicit.length > 0) {
    return explicit.map((step) => ({
      filePath: normalizePath(repoRoot, step.filePath),
      line: Math.max(1, step.line),
      message: step.message,
      snippet: step.snippet,
    }));
  }
  return evidence.slice(0, 3).map((step) => ({
    filePath: step.filePath,
    line: step.line,
    message: `${step.role}: ${step.catalogSignal}`,
    snippet: step.snippet,
  }));
}

function renderContextSummary(plan: TaintIrisNextPlan): string {
  const context = plan.repoContext;
  if (!context) return "No context loaded.";
  return [
    `languages: ${context.languages.join(", ") || plan.languages.join(", ") || "unknown"}`,
    `frameworks: ${context.frameworks.join(", ") || "none"}`,
    `auth: ${context.authPatterns.join(", ") || "none"}`,
    `db/orm: ${context.ormOrDb.join(", ") || "none"}`,
    `entry points: ${context.entryPoints.slice(0, 12).join(", ") || "none"}`,
  ].join("\n");
}

function renderThreatModelSummary(plan: TaintIrisNextPlan): string {
  const threatModel = plan.threatModel;
  if (!threatModel) return "No threat model loaded.";
  const lines = [`threats: ${threatModel.threats.length}`];
  for (const threat of threatModel.threats.slice(0, 10)) {
    lines.push(
      `- ${threat.id}: ${threat.title} [${threat.impact}/${threat.likelihood}] CWE=${(threat.relatedCwe ?? []).join(", ") || "n/a"}`,
    );
  }
  return lines.join("\n");
}

function renderEvidenceBundles(evidence: readonly TaintIrisNextEvidence[]): string {
  if (evidence.length === 0) {
    return "No structural evidence matched. The agent should return no findings unless repository reads reveal a defensible path.";
  }
  const byCwe = new Map<string, TaintIrisNextEvidence[]>();
  for (const item of evidence) {
    const group = byCwe.get(item.cwe) ?? [];
    group.push(item);
    byCwe.set(item.cwe, group);
  }

  const lines: string[] = [];
  for (const [cwe, items] of byCwe) {
    lines.push(`### ${cwe} (${items[0]?.taintClass ?? "taint"})`);
    for (const item of items.slice(0, 16)) {
      lines.push(
        `- ${item.evidenceLevel ?? "candidate"} ${item.role} ${item.catalogSignal} @ ${item.filePath}:${item.line} [${item.language}, ${item.confidence}, ${item.source ?? "structural"}] ${item.snippet}`,
      );
    }
  }
  return lines.join("\n");
}

function renderLinkedStories(evidenceResult: TaintIrisNextEvidenceResult): string {
  if (evidenceResult.linkedStories.length === 0) {
    return "No deterministic linked stories. Candidate-only evidence must be triaged as candidate/rejected unless minEvidenceLevel=candidate.";
  }
  return rankLinkedStoriesForReview(evidenceResult.linkedStories, evidenceResult.candidates)
    .slice(0, 30)
    .map(
      (story) =>
        `- ${story.id} ${story.cwe} ${story.filePath}:${story.sourceLine}->${story.sinkLine} source=${story.sourceCandidateId} sink=${story.sinkCandidateId} tokens=${story.sharedTokens.join(",") || "none"} rationale=${story.rationale}`,
    )
    .join("\n");
}

function renderEvidenceSummary(evidence: readonly TaintIrisNextEvidence[]): string | null {
  if (evidence.length === 0) return null;
  return evidence
    .map((item) => `${item.role} ${item.catalogSignal} at ${item.filePath}:${item.line}`)
    .join("\n");
}

function forwardAgentActivity(
  ctx: ExecutionContext,
  fingerprint: string,
  message: AgentMessage,
): void {
  if (message.type === "assistant") {
    for (const block of message.content) {
      const blockType = typeof block["type"] === "string" ? block["type"] : "";
      if (blockType === "tool_use") {
        ctx.reportAgentActivity?.(fingerprint, "tool-start", {
          toolName: str(block["name"]) || "tool",
          toolInput: isRecord(block["input"]) ? block["input"] : {},
        });
      } else if (blockType === "text") {
        const text = str(block["text"]);
        if (text) {
          ctx.reportAgentActivity?.(fingerprint, "reasoning", {
            summary: text.length > 180 ? `${text.slice(0, 177)}...` : text,
          });
        }
      }
    }
    return;
  }
  if (message.type === "tool-progress") {
    ctx.reportAgentActivity?.(fingerprint, "tool-progress", {
      toolName: message.toolName,
      elapsedSeconds: message.elapsedSeconds,
    });
    return;
  }
  if (message.type === "tool-summary") {
    ctx.reportAgentActivity?.(fingerprint, "tool-complete", { summary: message.summary });
    return;
  }
  if (message.type === "tool-result") {
    ctx.reportAgentActivity?.(fingerprint, "tool-complete", {
      summary: message.isError ? "tool result errored" : "tool result returned",
      toolName: message.toolUseId,
    });
  }
}

function normalizePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const rel = path.relative(repoRoot, filePath);
  return rel.startsWith("..") ? filePath : rel || filePath;
}

function mapSeverity(severity: string): string {
  switch (severity.toLowerCase()) {
    case "critical":
    case "high":
      return "ERROR";
    case "medium":
      return "WARNING";
    default:
      return "INFO";
  }
}

function mapConfidence(confidence: string | undefined): string {
  switch ((confidence ?? "").toLowerCase()) {
    case "high":
      return "HIGH";
    case "low":
      return "LOW";
    default:
      return "MEDIUM";
  }
}

function mapAgentSeverity(severity: string): TaintIrisNextAgentFinding["severity"] {
  if (severity === "critical" || severity === "high" || severity === "low" || severity === "info") {
    return severity;
  }
  return "medium";
}

function mapAgentConfidence(confidence: string): "high" | "medium" | "low" {
  if (confidence === "high" || confidence === "low") return confidence;
  return "medium";
}

function mapEvidenceLevel(level: string): TaintIrisNextEvidenceLevel {
  if (level === "path" || level === "linked" || level === "candidate") return level;
  return "candidate";
}

function mapTriageStatus(status: string): TaintIrisNextAgentTriageDecision["status"] {
  if (status === "finding" || status === "rejected") return status;
  return "candidate";
}

function str(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function stringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function parseRawAgentOutput(
  structuredOutput: unknown,
  resultText: string,
): { rawOutput: unknown; parseError: string } {
  if (structuredOutput !== undefined) {
    return {
      rawOutput: structuredOutput,
      parseError: isRecord(structuredOutput) ? "" : "structured output was not a JSON object",
    };
  }
  const extracted = extractJsonObject(resultText);
  if (!extracted) return { rawOutput: null, parseError: "response did not contain JSON" };
  try {
    const parsed = JSON.parse(extracted);
    if (!looksLikeAgentOutputRecord(parsed)) {
      return { rawOutput: null, parseError: "parsed JSON did not match IRIS agent output schema" };
    }
    return {
      rawOutput: parsed,
      parseError: isRecord(parsed) ? "" : "parsed JSON was not an object",
    };
  } catch (error) {
    return { rawOutput: null, parseError: toErrorMessage(error) };
  }
}

function looksLikeAgentOutputRecord(value: unknown): boolean {
  if (!isRecord(value)) return false;
  return (
    Array.isArray(value["selectedCwes"]) &&
    Array.isArray(value["findings"]) &&
    Array.isArray(value["triage"]) &&
    Array.isArray(value["notes"])
  );
}

function extractJsonObject(text: string): string | null {
  const trimmed = text.trim();
  if (!trimmed) return null;
  const fence = trimmed.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/iu);
  if (fence?.[1]) return fence[1].trim();
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start >= 0 && end > start) return trimmed.slice(start, end + 1);
  return trimmed.startsWith("{") ? trimmed : null;
}

function excerpt(text: string): string {
  const compact = text.replace(/\s+/gu, " ").trim();
  return compact.length > 500 ? `${compact.slice(0, 497)}...` : compact;
}
