import {
  DEFAULT_READ_ONLY_TOOLS,
  extractJson,
  resolveRepoContextAndRuntimeOptions,
  runStructuredAgentQuery,
  type AgentActivity,
  type AgentActivityCallback,
  type AgentRuntimeOptions,
} from "./agent-runtime/execution.js";
import type {
  AllowedTriageTool,
  Finding,
  TriageAgentConfig,
} from "./scanners/types.js";
import { formatEnrichedRepoContext, formatRepoContext } from "./repo-context.js";
import {
  composePromptModules,
  confidenceEscalationModule,
  falseDismissalModule,
  frameworkAwarenessModule,
} from "./prompts/modules.js";
import { renderTemplate } from "./prompts/template.js";
import { TRIAGE_TEMPLATE } from "./prompts/templates/triage.js";
import { BATCH_TRIAGE_TEMPLATE } from "./prompts/templates/triage.js";
import { buildTriageContext, buildBatchTriageContext } from "./prompts/context.js";
import type { EnrichedRepoContext, RepoContext, TriageResult, Verdict } from "./types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "./utils.js";
import { RawTriageOutputSchema, RawBatchTriageOutputSchema, formatZodErrors } from "./schemas.js";

export type { AgentActivity, AgentActivityCallback } from "./agent-runtime/execution.js";
export { extractJson } from "./agent-runtime/execution.js";

export const TRIAGE_RESULT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["fingerprint", "verdict", "confidence", "rationale", "verification_steps"],
  properties: {
    fingerprint: { type: "string" },
    verdict: { type: "string", enum: ["tp", "fp", "needs_review"] },
    confidence: { type: "number", minimum: 0, maximum: 1 },
    rationale: { type: "string" },
    verification_steps: { type: "array", items: { type: "string" }, minItems: 1 },
    fix_patch: { type: ["string", "null"] },
    source: {
      type: "object",
      additionalProperties: false,
      required: ["why", "is_false_positive", "evidence"],
      properties: {
        why: { type: "string" },
        is_false_positive: { type: "boolean" },
        evidence: { type: "string" },
      },
    },
    sink: {
      type: "object",
      additionalProperties: false,
      required: ["why", "is_false_positive", "evidence"],
      properties: {
        why: { type: "string" },
        is_false_positive: { type: "boolean" },
        evidence: { type: "string" },
      },
    },
    is_vulnerable: { type: "boolean" },
    exploit_scenario: { type: "string" },
    recommended_fix: { type: "string" },
    rule_refinement_hint: { type: "string" },
    triage_schema_version: { type: "string" },
    evidence_trail: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["level", "evidence"],
        properties: {
          level: { type: "string" },
          evidence: { type: "string" },
        },
      },
    },
    evidence_chain: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["step_type", "description", "confidence", "evidence"],
        properties: {
          step_type: {
            type: "string",
            enum: [
              "source-reachability", "sink-danger", "sanitization-check",
              "config-review", "dataflow-trace", "exploit-feasibility",
              "framework-protection",
            ],
          },
          description: { type: "string" },
          confidence: { type: "number", minimum: 0, maximum: 1 },
          evidence: { type: "string" },
        },
      },
    },
  },
} as const;

export const DEFAULT_TOOLS: AllowedTriageTool[] = [...DEFAULT_READ_ONLY_TOOLS];
export const DEFAULT_MAX_TURNS = 10;

export interface TriageRuntimeOptions extends AgentRuntimeOptions {
  enrichedContext?: EnrichedRepoContext["enrichment"];
}

export interface TriageConfigProvider {
  has(id: string): boolean;
  get(id: string): {
    triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig;
  };
}

export interface TriageOutput {
  result: TriageResult;
  costUsd: number;
}

export interface BatchTriageOutput {
  results: Map<string, TriageResult>;
  costUsd: number;
}

export const BATCH_TRIAGE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["results"],
  properties: {
    results: {
      type: "array",
      items: TRIAGE_RESULT_SCHEMA,
    },
  },
} as const;

export class TriageExecutionError extends Error {
  readonly costUsd: number;

  constructor(message: string, costUsd = 0) {
    super(message);
    this.name = "TriageExecutionError";
    this.costUsd = normalizeCostUsd(costUsd);
  }
}

export function triageSystemPromptPrefix(
  repoContext?: RepoContext,
  enrichedContext?: EnrichedRepoContext["enrichment"],
): string {
  const repoSection = formatRepoContext(repoContext);
  const enrichedSection = formatEnrichedRepoContext(enrichedContext);
  const repoBlock = repoSection.length > 0
    ? "## Repository Context\n" + repoSection.join("\n") + "\n\n"
    : "";
  const enrichedBlock = enrichedSection.length > 0
    ? "## Enriched Repository Context\n" + enrichedSection.join("\n") + "\n\n"
    : "";
  return repoBlock + enrichedBlock + composePromptModules(
    frameworkAwarenessModule(repoContext),
    confidenceEscalationModule("triage"),
    falseDismissalModule(),
  );
}

export async function triageFindingWithAgent(
  registry: TriageConfigProvider,
  finding: Finding,
  repoRoot: string,
  repoName: string,
  model: string,
  maxTurns: number | null,
  repoContextOrRuntimeOptions?: RepoContext | TriageRuntimeOptions,
  maybeRuntimeOptions: TriageRuntimeOptions = {},
  /** Optional extra context appended to the triage prompt (trajectories, evidence chain instructions). */
  extraPromptContext?: string,
  /** Optional custom triage template override (loaded from config). */
  triageTemplate?: string,
): Promise<TriageOutput> {
  const { repoContext, runtimeOptions } = resolveRepoContextAndRuntimeOptions(
    repoContextOrRuntimeOptions,
    maybeRuntimeOptions,
  );
  const agentConfig = resolveAgentConfig(registry, finding, repoName, triageTemplate);
  const prompt = extraPromptContext
    ? agentConfig.prompt + "\n\n" + extraPromptContext
    : agentConfig.prompt;
  const allowedTools = normalizeAllowedTools(agentConfig.allowedTools);
  const effectiveMaxTurns = normalizeTurns(agentConfig.maxTurns ?? maxTurns);
  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    maxTurns: effectiveMaxTurns,
    allowedTools,
    runtimeOptions,
    systemPromptPrefix: triageSystemPromptPrefix(repoContext, runtimeOptions.enrichedContext),
    schema: TRIAGE_RESULT_SCHEMA,
  });

  if (executionError) {
    throw new TriageExecutionError(`triage agent failed: ${executionError}`, costUsd);
  }

  let parsedResult: TriageResult;
  try {
    parsedResult = parseAgentOutput(structuredOutput ?? resultText, finding.fingerprint);
  } catch (error) {
    throw new TriageExecutionError(
      `triage output parse failed: ${toErrorMessage(error)}`,
      costUsd,
    );
  }

  return {
    result: parsedResult,
    costUsd,
  };
}

export const BATCH_TRIAGE_FALLBACK_RATIONALE = "Finding was not included in batch triage agent response.";

export const DEFAULT_BATCH_SIZE = 15;

export async function triageFindingsBatch(
  findings: Finding[],
  repoRoot: string,
  repoName: string,
  model: string,
  repoContext?: RepoContext,
  runtimeOptions: TriageRuntimeOptions = {},
  maxBatchSize: number = DEFAULT_BATCH_SIZE,
  maxTurns: number | null = null,
  batchTemplate?: string,
): Promise<BatchTriageOutput> {
  if (findings.length === 0) {
    return { results: new Map(), costUsd: 0 };
  }

  const effectiveBatchSize = Math.max(1, Math.floor(maxBatchSize));

  if (findings.length <= effectiveBatchSize) {
    return triageSingleBatch(findings, repoRoot, repoName, model, repoContext, runtimeOptions, maxTurns, batchTemplate);
  }

  const allResults = new Map<string, TriageResult>();
  let totalCost = 0;

  for (let i = 0; i < findings.length; i += effectiveBatchSize) {
    const chunk = findings.slice(i, i + effectiveBatchSize);
    const { results, costUsd } = await triageSingleBatch(
      chunk,
      repoRoot,
      repoName,
      model,
      repoContext,
      runtimeOptions,
      maxTurns,
      batchTemplate,
    );

    for (const [fp, result] of results) {
      allResults.set(fp, result);
    }
    totalCost += costUsd;
  }

  return { results: allResults, costUsd: totalCost };
}

async function triageSingleBatch(
  findings: Finding[],
  repoRoot: string,
  repoName: string,
  model: string,
  repoContext: RepoContext | undefined,
  runtimeOptions: TriageRuntimeOptions,
  maxTurns: number | null = null,
  batchTemplate?: string,
): Promise<BatchTriageOutput> {
  const prompt = buildBatchTriagePrompt(findings, repoName, batchTemplate);
  const effectiveMaxTurns = normalizeTurns(maxTurns);
  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    maxTurns: effectiveMaxTurns,
    allowedTools: DEFAULT_TOOLS,
    runtimeOptions,
    systemPromptPrefix: triageSystemPromptPrefix(repoContext, runtimeOptions.enrichedContext),
    schema: BATCH_TRIAGE_SCHEMA,
    strict: true,
    retryInvalidStructuredOutput: 2,
  });

  if (executionError) {
    throw new TriageExecutionError(`batch triage agent failed: ${executionError}`, costUsd);
  }

  const results = parseBatchTriageOutput(structuredOutput ?? resultText, findings);
  return { results, costUsd };
}

function buildBatchTriagePrompt(
  findings: Finding[],
  repoName: string,
  template?: string,
): string {
  const context = buildBatchTriageContext(findings, repoName);
  return renderTemplate(template ?? BATCH_TRIAGE_TEMPLATE, context as any);
}

function parseBatchTriageOutput(
  raw: unknown,
  findings: Finding[],
): Map<string, TriageResult> {
  const results = new Map<string, TriageResult>();
  const fingerprintSet = new Set(findings.map((f) => f.fingerprint));

  let items: unknown[] = [];

  // First try structured Zod validation for the batch envelope
  if (isRecord(raw)) {
    const batchValidation = RawBatchTriageOutputSchema.safeParse(raw);
    if (batchValidation.success) {
      items = batchValidation.data.results;
    } else {
      // Fall back to lenient extraction
      if (Array.isArray((raw as Record<string, unknown>)["results"])) {
        items = (raw as Record<string, unknown>)["results"] as unknown[];
      }
      const errors = formatZodErrors(batchValidation.error.issues);
      console.warn(
        `[triage] Batch triage output has schema issues: ${errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
      );
    }
  } else if (Array.isArray(raw)) {
    items = raw;
  } else if (typeof raw === "string") {
    try {
      const jsonStr = extractJson(raw);
      const parsed = JSON.parse(jsonStr);
      if (isRecord(parsed) && Array.isArray(parsed["results"])) {
        items = parsed["results"] as unknown[];
      } else if (Array.isArray(parsed)) {
        items = parsed;
      }
    } catch {
      // Fall through — missing findings will get needs_review below
    }
  }

  for (const item of items) {
    if (!isRecord(item)) continue;
    const fp = asString((item as Record<string, unknown>)["fingerprint"], "");
    if (!fp || !fingerprintSet.has(fp)) continue;

    results.set(fp, {
      fingerprint: fp,
      verdict: parseVerdict(asString((item as Record<string, unknown>)["verdict"], "needs_review")),
      confidence: clampConfidence((item as Record<string, unknown>)["confidence"]),
      rationale: asString((item as Record<string, unknown>)["rationale"], ""),
      verificationSteps: normalizeVerificationSteps((item as Record<string, unknown>)["verification_steps"]),
      fixPatch: normalizeFixPatch((item as Record<string, unknown>)["fix_patch"]),
      source: parsePathAssessment((item as Record<string, unknown>)["source"]),
      sink: parsePathAssessment((item as Record<string, unknown>)["sink"]),
      isVulnerable: asOptionalBoolean((item as Record<string, unknown>)["is_vulnerable"]),
      exploitScenario: asOptionalString((item as Record<string, unknown>)["exploit_scenario"]),
      recommendedFix: asOptionalString((item as Record<string, unknown>)["recommended_fix"]),
      ruleRefinementHint: asOptionalString((item as Record<string, unknown>)["rule_refinement_hint"]),
      triageSchemaVersion: asOptionalString((item as Record<string, unknown>)["triage_schema_version"]),
    });
  }

  // Fill in any missing findings with needs_review
  for (const finding of findings) {
    if (!results.has(finding.fingerprint)) {
      results.set(finding.fingerprint, {
        fingerprint: finding.fingerprint,
        verdict: "needs_review",
        confidence: 0,
        rationale: BATCH_TRIAGE_FALLBACK_RATIONALE,
        verificationSteps: [],
        fixPatch: null,
        source: undefined,
        sink: undefined,
        isVulnerable: undefined,
        exploitScenario: undefined,
        recommendedFix: undefined,
        ruleRefinementHint: undefined,
        triageSchemaVersion: undefined,
      });
    }
  }

  return results;
}

export function parseAgentOutput(raw: unknown, fingerprint: string): TriageResult {
  if (isRecord(raw)) {
    // Validate raw LLM output against schema; log warnings but proceed
    // with lenient parsing to handle partial/non-conforming outputs gracefully.
    const validation = RawTriageOutputSchema.safeParse(raw);
    if (!validation.success) {
      const errors = formatZodErrors(validation.error.issues);
      console.warn(
        `[triage] LLM output for ${fingerprint} has schema issues: ${errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
      );
    }

    return {
      fingerprint: asString(raw["fingerprint"], fingerprint),
      verdict: parseVerdict(asString(raw["verdict"], "needs_review")),
      confidence: clampConfidence(raw["confidence"]),
      rationale: asString(raw["rationale"], ""),
      verificationSteps: normalizeVerificationSteps(raw["verification_steps"]),
      fixPatch: normalizeFixPatch(raw["fix_patch"]),
      source: parsePathAssessment(raw["source"]),
      sink: parsePathAssessment(raw["sink"]),
      isVulnerable: asOptionalBoolean(raw["is_vulnerable"]),
      exploitScenario: asOptionalString(raw["exploit_scenario"]),
      recommendedFix: asOptionalString(raw["recommended_fix"]),
      ruleRefinementHint: asOptionalString(raw["rule_refinement_hint"]),
      triageSchemaVersion: asOptionalString(raw["triage_schema_version"]),
      evidenceTrail: parseEvidenceTrail(raw["evidence_trail"]),
      evidenceChain: parseEvidenceChain(raw["evidence_chain"]),
    };
  }

  if (typeof raw === "string") {
    return parseTriageResponse(raw, fingerprint);
  }

  return parseTriageResponse(String(raw ?? ""), fingerprint);
}

export function buildDefaultTriageAgentConfig(
  finding: Finding,
  repoName: string,
  template?: string,
): TriageAgentConfig {
  const context = buildTriageContext(finding, repoName);
  return {
    prompt: renderTemplate(template ?? TRIAGE_TEMPLATE, context as any),
  };
}

function resolveAgentConfig(
  registry: TriageConfigProvider,
  finding: Finding,
  repoName: string,
  template?: string,
): TriageAgentConfig {
  if (!registry.has(finding.scanner)) {
    return buildDefaultTriageAgentConfig(finding, repoName, template);
  }

  try {
    const config = registry.get(finding.scanner).triageAgentConfig(finding, repoName);
    if (!config.prompt || !config.prompt.trim()) {
      return buildDefaultTriageAgentConfig(finding, repoName, template);
    }
    return config;
  } catch {
    return buildDefaultTriageAgentConfig(finding, repoName, template);
  }
}

function normalizeAllowedTools(tools: AllowedTriageTool[] | undefined): AllowedTriageTool[] {
  if (!Array.isArray(tools) || tools.length === 0) {
    return [...DEFAULT_TOOLS];
  }

  const normalized = tools
    .filter((tool): tool is AllowedTriageTool => (
      tool === "Read" || tool === "Glob" || tool === "Grep"
      || tool === "GetCallers" || tool === "GetCallees" || tool === "GetFunctionBody"
    ));

  return normalized.length > 0 ? normalized : [...DEFAULT_TOOLS];
}

function normalizeTurns(value: number | null | undefined): number | null {
  if (value == null) return null;
  if (!Number.isFinite(value) || value < 1) return null;
  return Math.floor(value);
}

/** Parse a verdict string, defaulting to needs_review for unknown values. */
export function parseVerdict(v: string): Verdict {
  const normalized = v.trim().toLowerCase();
  if (normalized === "tp" || normalized === "fp" || normalized === "needs_review") return normalized;
  return "needs_review";
}

/** Parse raw LLM text into a TriageResult. */
export function parseTriageResponse(
  text: string,
  fingerprint: string,
): TriageResult {
  try {
    const jsonStr = extractJson(text);
    const parsed = JSON.parse(jsonStr);

    // Validate parsed JSON against schema; log warnings but proceed leniently
    const validation = RawTriageOutputSchema.safeParse(parsed);
    if (!validation.success) {
      const errors = formatZodErrors(validation.error.issues);
      console.warn(
        `[triage] LLM text output for ${fingerprint} has schema issues: ${errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
      );
    }

    return {
      fingerprint: asString(parsed.fingerprint, fingerprint),
      verdict: parseVerdict(asString(parsed.verdict, "needs_review")),
      confidence: clampConfidence(parsed.confidence),
      rationale: asString(parsed.rationale, ""),
      verificationSteps: normalizeVerificationSteps(parsed.verification_steps),
      fixPatch: normalizeFixPatch(parsed.fix_patch),
      source: parsePathAssessment(parsed.source),
      sink: parsePathAssessment(parsed.sink),
      isVulnerable: asOptionalBoolean(parsed.is_vulnerable),
      exploitScenario: asOptionalString(parsed.exploit_scenario),
      recommendedFix: asOptionalString(parsed.recommended_fix),
      ruleRefinementHint: asOptionalString(parsed.rule_refinement_hint),
      triageSchemaVersion: asOptionalString(parsed.triage_schema_version),
      evidenceTrail: parseEvidenceTrail(parsed.evidence_trail),
      evidenceChain: parseEvidenceChain(parsed.evidence_chain),
    };
  } catch (error) {
    throw new Error(`Invalid triage JSON response: ${toErrorMessage(error)}`);
  }
}

function normalizeVerificationSteps(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((step) => String(step).trim())
    .filter(Boolean);
}

function clampConfidence(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(1, numeric));
}

function normalizeFixPatch(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value !== "string") return null;
  return value;
}

function asString(value: unknown, fallback: string): string {
  if (typeof value === "string") return value;
  if (value == null) return fallback;
  return String(value);
}

function asOptionalString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed || undefined;
}

function asOptionalBoolean(value: unknown): boolean | undefined {
  if (typeof value !== "boolean") {
    return undefined;
  }
  return value;
}

function parseEvidenceTrail(value: unknown): Array<{ level: string; evidence: string }> | undefined {
  if (!Array.isArray(value)) return undefined;
  const trail: Array<{ level: string; evidence: string }> = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const level = typeof item["level"] === "string" ? item["level"].trim() : "";
    const evidence = typeof item["evidence"] === "string" ? item["evidence"].trim() : "";
    if (level && evidence) {
      trail.push({ level, evidence });
    }
  }
  return trail.length > 0 ? trail : undefined;
}

function parseEvidenceChain(value: unknown): import("./types.js").EvidenceStep[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const chain: import("./types.js").EvidenceStep[] = [];
  for (const item of value) {
    if (!isRecord(item)) continue;
    const stepType = typeof item["step_type"] === "string" ? item["step_type"].trim() : "";
    const description = typeof item["description"] === "string" ? item["description"].trim() : "";
    const confidence = clampConfidence(item["confidence"]);
    const evidence = typeof item["evidence"] === "string" ? item["evidence"].trim() : "";
    if (stepType && description) {
      chain.push({ stepType, description, confidence, evidence });
    }
  }
  return chain.length > 0 ? chain : undefined;
}

function parsePathAssessment(value: unknown): TriageResult["source"] | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const why = asString(value["why"], "").trim();
  const evidence = asString(value["evidence"], "").trim();
  const isFalsePositive = value["is_false_positive"] === true;
  if (!why && !evidence) {
    return undefined;
  }

  return {
    why,
    isFalsePositive,
    evidence,
  };
}
