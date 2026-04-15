import { readFile } from "node:fs/promises";
import path from "node:path";
import {
  extractJson,
  resolveDefaultReadOnlyTools,
  resolveRepoContextAndRuntimeOptions,
  runStructuredAgentQuery,
  runStructuredSessionQuery,
  type AgentActivity,
  type AgentActivityCallback,
  type AgentRuntimeOptions,
} from "./agent-runtime/execution.js";
import type { AgentSession } from "./agent-runtime/types.js";
import { writeBatchFile, cleanupBatchFiles } from "./agent-runtime/batch-files.js";
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
import { getLogger } from "./logger.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "./utils.js";
import { RawTriageOutputSchema, RawBatchTriageOutputSchema, formatZodErrors } from "./schemas.js";

export type { AgentActivity, AgentActivityCallback } from "./agent-runtime/execution.js";
export { extractJson } from "./agent-runtime/execution.js";

const log = getLogger("triage");

/** Lite triage schema — core fields only, used by default. */
export const TRIAGE_RESULT_SCHEMA_LITE = {
  type: "object",
  additionalProperties: false,
  required: ["fingerprint", "verdict", "confidence", "rationale", "verification_steps"],
  properties: {
    fingerprint: { type: "string" },
    title: { type: "string", description: "A concise, human-readable title for this finding (5-12 words). Should describe the vulnerability, not the rule. Example: 'SQL Injection in BSim Database Name Parameter'" },
    attack_narrative: { type: ["string", "null"], description: "A 2-3 sentence Alice-and-Bob style attack scenario. Use concrete actor names (e.g. 'An attacker on the local network', 'A malicious analyst with repository access'). Describe: who the attacker is, what they do, and what they gain. Example: 'Alice, a network attacker, connects to the TraceRMI port while Bob is debugging. She injects false register values, causing Bob to conclude the binary is benign when it is actually malicious.'" },
    display_severity: { type: "string", enum: ["critical", "high", "medium", "low"], description: "The assessed security severity. critical = remote code execution, auth bypass, data destruction. high = injection, privilege escalation, sensitive data exposure. medium = information disclosure, weak crypto, missing validation. low = informational, best-practice deviation." },
    verdict: { type: "string", enum: ["tp", "fp", "needs_review"] },
    confidence: { type: "number", minimum: 0, maximum: 1 },
    rationale: { type: "string" },
    verification_steps: { type: "array", items: { type: "string" }, minItems: 1 },
    fix_patch: { type: ["string", "null"] },
    sink_function: { type: ["string", "null"], description: "The dangerous function or API that data flows into (e.g. 'eval', 'popen', 'SafeExecWithTimeout', 'SQL query'). Null if not applicable." },
  },
} as const;

/** Full triage schema — includes evidence chain, source/sink analysis, etc. */
export const TRIAGE_RESULT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["fingerprint", "verdict", "confidence", "rationale", "verification_steps"],
  properties: {
    ...TRIAGE_RESULT_SCHEMA_LITE.properties,
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

export const BATCH_TRIAGE_TOOLS: AllowedTriageTool[] = ["Read", "Glob", "Grep"];
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
  missingFingerprints: string[];
  incomplete: boolean;
  recoveredByRetry: string[];
}

export function resolveDefaultTriageTools(
  runtime: AgentRuntimeOptions["runtime"] | undefined,
): AllowedTriageTool[] {
  return normalizeAllowedTriageToolNames(resolveDefaultReadOnlyTools(runtime));
}

export const BATCH_TRIAGE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["results"],
  properties: {
    results: {
      type: "array",
      items: TRIAGE_RESULT_SCHEMA_LITE,
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
  repoContextOrRuntimeOptions?: RepoContext | TriageRuntimeOptions,
  maybeRuntimeOptions: TriageRuntimeOptions = {},
  /** Optional extra context appended to the triage prompt (trajectories, evidence chain instructions). */
  extraPromptContext?: string,
  /** Optional custom triage template override (loaded from config). */
  triageTemplate?: string,
  /** Optional pre-computed system prompt prefix (for prompt caching across findings). */
  precomputedSystemPromptPrefix?: string,
): Promise<TriageOutput> {
  const { repoContext, runtimeOptions } = resolveRepoContextAndRuntimeOptions(
    repoContextOrRuntimeOptions,
    maybeRuntimeOptions,
  );
  const agentConfig = resolveAgentConfig(registry, finding, repoName, triageTemplate);
  const prompt = extraPromptContext
    ? agentConfig.prompt + "\n\n" + extraPromptContext
    : agentConfig.prompt;
  const allowedTools = normalizeAllowedTools(agentConfig.allowedTools, runtimeOptions.runtime);
  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    allowedTools,
    runtimeOptions,
    systemPromptPrefix: precomputedSystemPromptPrefix ?? triageSystemPromptPrefix(repoContext, runtimeOptions.enrichedContext),
    schema: TRIAGE_RESULT_SCHEMA_LITE,
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

export const DEFAULT_BATCH_SIZE = 5;

export async function triageFindingsBatch(
  findings: Finding[],
  repoRoot: string,
  repoName: string,
  model: string,
  repoContext?: RepoContext,
  runtimeOptions: TriageRuntimeOptions = {},
  maxBatchSize: number = DEFAULT_BATCH_SIZE,
  batchTemplate?: string,
): Promise<BatchTriageOutput> {
  if (findings.length === 0) {
    return {
      results: new Map(),
      costUsd: 0,
      missingFingerprints: [],
      incomplete: false,
      recoveredByRetry: [],
    };
  }

  const effectiveBatchSize = Math.max(1, Math.floor(maxBatchSize));

  if (findings.length <= effectiveBatchSize) {
    return triageSingleBatch(findings, repoRoot, repoName, model, repoContext, runtimeOptions, batchTemplate);
  }

  const allResults = new Map<string, TriageResult>();
  let totalCost = 0;
  const missingFingerprints = new Set<string>();

  // Try to create a reusable session for subprocess reuse across batches
  const runtime = runtimeOptions.runtime;
  const session = runtime?.createSession?.({
    cwd: repoRoot,
    model,
    allowedTools: [...BATCH_TRIAGE_TOOLS],
    permissionMode: "dontAsk",
    outputFormat: {
      type: "json_schema",
      schema: BATCH_TRIAGE_SCHEMA,
      strict: true,
    },
    systemPromptPrefix: triageSystemPromptPrefix(repoContext, runtimeOptions.enrichedContext),
  });

  const runId = session ? crypto.randomUUID() : "";

  try {
    let batchIdx = 0;
    for (let i = 0; i < findings.length; i += effectiveBatchSize) {
      const chunk = findings.slice(i, i + effectiveBatchSize);

      const chunkResult = session
        ? await triageSingleBatchSession(
            chunk,
            repoRoot,
            repoName,
            findings,
            session,
            runId,
            batchIdx,
            batchTemplate,
          )
        : await triageSingleBatch(
            chunk,
            repoRoot,
            repoName,
            model,
            repoContext,
            runtimeOptions,
            batchTemplate,
          );

      const { results, costUsd } = chunkResult;
      for (const [fp, result] of results) {
        allResults.set(fp, result);
      }
      for (const fingerprint of chunkResult.missingFingerprints) {
        missingFingerprints.add(fingerprint);
      }
      totalCost += costUsd;
      batchIdx++;
    }
  } finally {
    await session?.close();
    if (runId) cleanupBatchFiles(repoRoot, runId);
  }

  return {
    results: allResults,
    costUsd: totalCost,
    missingFingerprints: [...missingFingerprints],
    incomplete: missingFingerprints.size > 0,
    recoveredByRetry: [],
  };
}

async function triageSingleBatchSession(
  chunk: Finding[],
  repoRoot: string,
  repoName: string,
  _allFindings: Finding[],
  session: AgentSession,
  runId: string,
  batchIdx: number,
  batchTemplate?: string,
): Promise<BatchTriageOutput> {
  const batchData = {
    repoName,
    findingCount: chunk.length,
    findings: chunk.map((f) => ({
      fingerprint: f.fingerprint,
      taskId: f.taskId,
      ruleId: f.ruleId,
      filePath: f.filePath,
      startLine: f.startLine,
      severity: f.severity,
      scannerConfidence: f.scannerConfidence,
      likelihood: f.likelihood,
      impact: f.impact,
      cwe: f.cwe,
      message: f.message,
      evidence: f.evidence || null,
    })),
  };

  const filePath = writeBatchFile(repoRoot, runId, "triage", batchIdx, batchData);
  const prompt = batchTemplate
    ? `Read ${filePath} and triage each finding using the provided template context.`
    : `Read ${filePath} and triage each finding. For each, determine verdict (tp/fp/needs_review), confidence (0-1), rationale, and verification_steps.`;

  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredSessionQuery(
    session,
    prompt,
  );

  if (executionError) {
    throw new TriageExecutionError(`batch triage agent failed: ${executionError}`, costUsd);
  }

  const parsed = parseBatchTriageOutput(structuredOutput ?? resultText, chunk);
  return {
    ...parsed,
    costUsd,
    recoveredByRetry: [],
  };
}

async function triageSingleBatch(
  findings: Finding[],
  repoRoot: string,
  repoName: string,
  model: string,
  repoContext: RepoContext | undefined,
  runtimeOptions: TriageRuntimeOptions,
  batchTemplate?: string,
): Promise<BatchTriageOutput> {
  const prompt = buildBatchTriagePrompt(findings, repoName, batchTemplate);
  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    allowedTools: BATCH_TRIAGE_TOOLS,
    runtimeOptions,
    systemPromptPrefix: triageSystemPromptPrefix(repoContext, runtimeOptions.enrichedContext),
    schema: BATCH_TRIAGE_SCHEMA,
    strict: true,
    retryInvalidStructuredOutput: 2,
  });

  if (executionError) {
    throw new TriageExecutionError(`batch triage agent failed: ${executionError}`, costUsd);
  }

  const parsed = parseBatchTriageOutput(structuredOutput ?? resultText, findings);
  return {
    ...parsed,
    costUsd,
    recoveredByRetry: [],
  };
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
): Omit<BatchTriageOutput, "costUsd" | "recoveredByRetry"> {
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
      log.warn(
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
      // Fall through — missing findings will be reported via missingFingerprints.
    }
  }

  for (const item of items) {
    if (!isRecord(item)) continue;
    const fp = asString((item as Record<string, unknown>)["fingerprint"], "");
    if (!fp || !fingerprintSet.has(fp)) continue;

    results.set(fp, {
      fingerprint: fp,
      title: asOptionalString((item as Record<string, unknown>)["title"]),
      attackNarrative: asOptionalString((item as Record<string, unknown>)["attack_narrative"]),
      displaySeverity: asOptionalString((item as Record<string, unknown>)["display_severity"]) as TriageResult["displaySeverity"],
      verdict: parseVerdict(asString((item as Record<string, unknown>)["verdict"], "needs_review")),
      confidence: clampConfidence((item as Record<string, unknown>)["confidence"]),
      rationale: asString((item as Record<string, unknown>)["rationale"], ""),
      verificationSteps: normalizeVerificationSteps((item as Record<string, unknown>)["verification_steps"]),
      fixPatch: normalizeFixPatch((item as Record<string, unknown>)["fix_patch"]),
      source: parsePathAssessment((item as Record<string, unknown>)["source"]),
      sink: parsePathAssessment((item as Record<string, unknown>)["sink"]),
      sinkFunction: asOptionalString((item as Record<string, unknown>)["sink_function"]),
      isVulnerable: asOptionalBoolean((item as Record<string, unknown>)["is_vulnerable"]),
      exploitScenario: asOptionalString((item as Record<string, unknown>)["exploit_scenario"]),
      recommendedFix: asOptionalString((item as Record<string, unknown>)["recommended_fix"]),
      ruleRefinementHint: asOptionalString((item as Record<string, unknown>)["rule_refinement_hint"]),
      triageSchemaVersion: asOptionalString((item as Record<string, unknown>)["triage_schema_version"]),
      evidenceTrail: parseEvidenceTrail((item as Record<string, unknown>)["evidence_trail"]),
      evidenceChain: parseEvidenceChain((item as Record<string, unknown>)["evidence_chain"]),
    });
  }

  const missingFingerprints = findings
    .map((finding) => finding.fingerprint)
    .filter((fingerprint) => !results.has(fingerprint));

  return {
    results,
    missingFingerprints,
    incomplete: missingFingerprints.length > 0,
  };
}

export function parseAgentOutput(raw: unknown, fingerprint: string): TriageResult {
  if (isRecord(raw)) {
    const validation = RawTriageOutputSchema.safeParse(raw);
    if (!validation.success) {
      const errors = formatZodErrors(validation.error.issues);
      log.warn(
        `[triage] LLM output for ${fingerprint} has schema issues: ${errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
      );
    }

    return {
      fingerprint: asString(raw["fingerprint"], fingerprint),
      title: asOptionalString(raw["title"]),
      attackNarrative: asOptionalString(raw["attack_narrative"]),
      displaySeverity: asOptionalString(raw["display_severity"]) as TriageResult["displaySeverity"],
      verdict: parseVerdict(asString(raw["verdict"], "needs_review")),
      confidence: clampConfidence(raw["confidence"]),
      rationale: asString(raw["rationale"], ""),
      verificationSteps: normalizeVerificationSteps(raw["verification_steps"]),
      fixPatch: normalizeFixPatch(raw["fix_patch"]),
      source: parsePathAssessment(raw["source"]),
      sink: parsePathAssessment(raw["sink"]),
      sinkFunction: asOptionalString(raw["sink_function"]),
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
  if (!registry.has(finding.taskId)) {
    return buildDefaultTriageAgentConfig(finding, repoName, template);
  }

  try {
    const config = registry.get(finding.taskId).triageAgentConfig(finding, repoName);
    if (!config.prompt || !config.prompt.trim()) {
      return buildDefaultTriageAgentConfig(finding, repoName, template);
    }
    return config;
  } catch {
    return buildDefaultTriageAgentConfig(finding, repoName, template);
  }
}

function normalizeAllowedTools(
  tools: AllowedTriageTool[] | undefined,
  runtime: AgentRuntimeOptions["runtime"] | undefined,
): AllowedTriageTool[] {
  if (!Array.isArray(tools) || tools.length === 0) {
    return resolveDefaultTriageTools(runtime);
  }

  const normalized = normalizeAllowedTriageToolNames(tools);

  return normalized.length > 0 ? normalized : resolveDefaultTriageTools(runtime);
}

function normalizeAllowedTriageToolNames(tools: readonly string[]): AllowedTriageTool[] {
  return tools.filter((tool): tool is AllowedTriageTool => (
    tool === "Read"
    || tool === "Glob"
    || tool === "Grep"
    || tool === "GetCallers"
    || tool === "GetCallees"
    || tool === "GetFunctionBody"
    || tool === "GoToDefinition"
    || tool === "FindReferences"
    || tool === "TypeAtPosition"
  ));
}

/** Parse a verdict string, defaulting to needs_review for unknown values. */
export function parseVerdict(v: string): Verdict {
  const normalized = v.trim().toLowerCase();
  if (normalized === "tp" || normalized === "fp" || normalized === "needs_review" || normalized === "by_design") return normalized;
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

    const validation = RawTriageOutputSchema.safeParse(parsed);
    if (!validation.success) {
      const errors = formatZodErrors(validation.error.issues);
      log.warn(
        `[triage] LLM text output for ${fingerprint} has schema issues: ${errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
      );
    }

    return {
      fingerprint: asString(parsed.fingerprint, fingerprint),
      title: asOptionalString(parsed.title),
      attackNarrative: asOptionalString(parsed.attack_narrative),
      displaySeverity: asOptionalString(parsed.display_severity) as TriageResult["displaySeverity"],
      verdict: parseVerdict(asString(parsed.verdict, "needs_review")),
      confidence: clampConfidence(parsed.confidence),
      rationale: asString(parsed.rationale, ""),
      verificationSteps: normalizeVerificationSteps(parsed.verification_steps),
      fixPatch: normalizeFixPatch(parsed.fix_patch),
      source: parsePathAssessment(parsed.source),
      sink: parsePathAssessment(parsed.sink),
      sinkFunction: asOptionalString(parsed.sink_function),
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

const PRE_READ_BYTE_CAP = 20_000;

/**
 * Per-run file content cache — avoids re-reading the same source file for
 * co-located findings.  Keyed by absolute path; values are raw file contents.
 */
export type FileContentCache = Map<string, string>;

/**
 * Pre-read the flagged source file for a finding, returning a formatted
 * markdown snippet centered on the finding's start line.
 * Returns empty string on any failure — triage must never fail due to pre-read.
 *
 * When a {@link FileContentCache} is provided, file contents are read from the
 * cache on subsequent calls for the same path, eliminating redundant disk I/O
 * for findings in the same file.
 */
export async function preReadForTriage(
  finding: Finding,
  repoRoot: string,
  surroundingLines = 50,
  fileCache?: FileContentCache,
): Promise<string> {
  try {
    const filePath = path.resolve(repoRoot, finding.filePath);

    let raw: string;
    if (fileCache?.has(filePath)) {
      raw = fileCache.get(filePath)!;
    } else {
      raw = await readFile(filePath, "utf-8");
      fileCache?.set(filePath, raw);
    }

    if (raw.length > PRE_READ_BYTE_CAP * 2) {
    }
    const lines = raw.split("\n");
    const start = Math.max(0, finding.startLine - 1 - surroundingLines);
    const end = Math.min(lines.length, finding.startLine + surroundingLines);
    const snippet = lines.slice(start, end).join("\n");

    if (snippet.length === 0 || snippet.length > PRE_READ_BYTE_CAP) {
      return snippet.length > PRE_READ_BYTE_CAP
        ? formatPreReadSnippet(finding, start + 1, end, snippet.slice(0, PRE_READ_BYTE_CAP))
        : "";
    }

    return formatPreReadSnippet(finding, start + 1, end, snippet);
  } catch {
    return "";
  }
}

function formatPreReadSnippet(
  finding: Finding,
  startLine: number,
  endLine: number,
  snippet: string,
): string {
  return [
    "## Pre-loaded source context",
    `File: ${finding.filePath} (lines ${startLine}-${endLine}, finding at line ${finding.startLine})`,
    "```",
    snippet,
    "```",
    "",
  ].join("\n");
}
