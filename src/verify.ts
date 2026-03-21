import {
  extractJson,
  resolveDefaultReadOnlyTools,
  resolveRepoContextAndRuntimeOptions,
  runStructuredAgentQuery,
  type AgentActivityCallback,
  type AgentRuntimeOptions,
} from "./agent-runtime/execution.js";
import type { AllowedTriageTool, Finding } from "./scanners/types.js";
import type {
  EnrichedRepoContext,
  ProofVerdict,
  RepoContext,
  TriageResult,
  VerificationResult,
} from "./types.js";
import { getBypassKnowledge } from "./bypass-knowledge.js";
import { formatEnrichedRepoContext, formatRepoContext } from "./repo-context.js";
import {
  bypassExhaustionModule,
  composePromptModules,
  confidenceEscalationModule,
  frameworkAwarenessModule,
  proofLevelModule,
} from "./prompts/modules.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "./utils.js";
import { RawVerificationOutputSchema, RawBatchVerificationOutputSchema, formatZodErrors } from "./schemas.js";
import { renderTemplate } from "./prompts/template.js";
import { VERIFY_UNIFIED_TEMPLATE } from "./prompts/templates/verify.js";
import { BATCH_VERIFY_TEMPLATE } from "./prompts/templates/verify.js";
import { buildVerifyContext, buildBatchVerifyContext } from "./prompts/context.js";

export const VERIFICATION_RESULT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: [
    "fingerprint",
    "exploitable",
    "poc_payload",
    "poc_description",
    "attack_vector",
    "preconditions",
    "confidence",
  ],
  properties: {
    fingerprint: { type: "string" },
    exploitable: { type: "boolean" },
    poc_payload: { type: ["string", "null"] },
    poc_description: { type: "string" },
    attack_vector: { type: ["string", "null"] },
    preconditions: { type: "array", items: { type: "string" } },
    confidence: { type: "number", minimum: 0, maximum: 1 },
    proof_level: { type: "integer", minimum: 1, maximum: 4 },
    proof_verdict: {
      type: "string",
      enum: ["exploited", "blocked_by_security", "out_of_scope", "false_positive"],
    },
    bypass_attempts: { type: "array", items: { type: "string" } },
  },
} as const;

export const DEFAULT_MAX_TURNS = 15;

export interface VerificationRuntimeOptions extends AgentRuntimeOptions {
  enrichedContext?: EnrichedRepoContext["enrichment"];
  /** Extra prompt context injected by knowledge registry, precedents, etc. */
  extraPromptContext?: string;
}

export interface VerificationOutput {
  result: VerificationResult;
  costUsd: number;
}

export function resolveDefaultVerificationTools(
  runtime: AgentRuntimeOptions["runtime"] | undefined,
): AllowedTriageTool[] {
  return normalizeAllowedTriageToolNames(resolveDefaultReadOnlyTools(runtime));
}

export class VerificationExecutionError extends Error {
  readonly costUsd: number;

  constructor(message: string, costUsd = 0) {
    super(message);
    this.name = "VerificationExecutionError";
    this.costUsd = normalizeCostUsd(costUsd);
  }
}

export function verificationSystemPromptPrefix(
  repoContext?: RepoContext,
  enrichedContext?: EnrichedRepoContext["enrichment"],
  extraPromptContext?: string,
): string {
  const repoSection = formatRepoContext(repoContext);
  const enrichedSection = formatEnrichedRepoContext(enrichedContext);
  const repoBlock = repoSection.length > 0
    ? "## Repository Context\n" + repoSection.join("\n") + "\n\n"
    : "";
  const enrichedBlock = enrichedSection.length > 0
    ? "## Enriched Repository Context\n" + enrichedSection.join("\n") + "\n\n"
    : "";
  const extraBlock = extraPromptContext
    ? "\n\n" + extraPromptContext
    : "";
  return repoBlock + enrichedBlock + composePromptModules(
    frameworkAwarenessModule(repoContext),
    proofLevelModule(),
    bypassExhaustionModule(),
    confidenceEscalationModule("verification"),
  ) + extraBlock;
}

export async function verifyFindingWithAgent(
  finding: Finding,
  triageResult: TriageResult,
  repoRoot: string,
  repoName: string,
  model: string,
  maxTurns: number | undefined,
  repoContextOrRuntimeOptions?: RepoContext | VerificationRuntimeOptions,
  maybeRuntimeOptions: VerificationRuntimeOptions = {},
  /** Optional custom verify template override (loaded from config). */
  verifyTemplate?: string,
): Promise<VerificationOutput> {
  const { repoContext, runtimeOptions } = resolveRepoContextAndRuntimeOptions(
    repoContextOrRuntimeOptions,
    maybeRuntimeOptions,
  );
  const prompt = buildVerificationPrompt(finding, triageResult, repoName, verifyTemplate);
  const effectiveMaxTurns = normalizeTurns(maxTurns);
  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    maxTurns: effectiveMaxTurns,
    allowedTools: resolveDefaultVerificationTools(runtimeOptions.runtime),
    runtimeOptions,
    systemPromptPrefix: verificationSystemPromptPrefix(repoContext, runtimeOptions.enrichedContext, runtimeOptions.extraPromptContext),
    schema: VERIFICATION_RESULT_SCHEMA,
  });

  if (executionError) {
    throw new VerificationExecutionError(`verification agent failed: ${executionError}`, costUsd);
  }

  let parsedResult: VerificationResult;
  try {
    parsedResult = parseVerificationOutput(structuredOutput ?? resultText, finding.fingerprint);
  } catch (error) {
    throw new VerificationExecutionError(
      `verification output parse failed: ${toErrorMessage(error)}`,
      costUsd,
    );
  }

  return {
    result: parsedResult,
    costUsd,
  };
}

export function buildVerificationPrompt(
  finding: Finding,
  triageResult: TriageResult,
  repoName: string,
  template?: string,
): string {
  const bypassEntry = getBypassKnowledge(finding.cwe, finding.ruleId);
  const context = buildVerifyContext(finding, triageResult, repoName, bypassEntry);
  return renderTemplate(template ?? VERIFY_UNIFIED_TEMPLATE, context as any);
}

export function parseVerificationOutput(raw: unknown, fingerprint: string): VerificationResult {
  if (isRecord(raw)) {
    // Validate raw LLM output against schema; log warnings but proceed
    // with lenient parsing to handle partial/non-conforming outputs gracefully.
    const validation = RawVerificationOutputSchema.safeParse(raw);
    if (!validation.success) {
      const errors = formatZodErrors(validation.error.issues);
      console.warn(
        `[verify] LLM output for ${fingerprint} has schema issues: ${errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
      );
    }

    return {
      fingerprint: asString(raw["fingerprint"], fingerprint),
      exploitable: asBoolean(raw["exploitable"], false),
      pocPayload: normalizeNullableString(raw["poc_payload"]),
      pocDescription: asString(raw["poc_description"], ""),
      attackVector: normalizeNullableString(raw["attack_vector"]),
      preconditions: normalizeStringArray(raw["preconditions"]),
      confidence: clampConfidence(raw["confidence"]),
      proofLevel: parseProofLevel(raw["proof_level"]),
      proofVerdict: parseProofVerdict(raw["proof_verdict"]),
      bypassAttempts: parseOptionalStringArray(raw["bypass_attempts"]),
    };
  }

  if (typeof raw === "string") {
    return parseVerificationResponse(raw, fingerprint);
  }

  return parseVerificationResponse(String(raw ?? ""), fingerprint);
}

function parseVerificationResponse(text: string, fingerprint: string): VerificationResult {
  try {
    const jsonStr = extractJson(text);
    const parsed = JSON.parse(jsonStr);

    // Validate parsed JSON against schema; log warnings but proceed leniently
    const validation = RawVerificationOutputSchema.safeParse(parsed);
    if (!validation.success) {
      const errors = formatZodErrors(validation.error.issues);
      console.warn(
        `[verify] LLM text output for ${fingerprint} has schema issues: ${errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
      );
    }

    return {
      fingerprint: asString(parsed.fingerprint, fingerprint),
      exploitable: asBoolean(parsed.exploitable, false),
      pocPayload: normalizeNullableString(parsed.poc_payload),
      pocDescription: asString(parsed.poc_description, ""),
      attackVector: normalizeNullableString(parsed.attack_vector),
      preconditions: normalizeStringArray(parsed.preconditions),
      confidence: clampConfidence(parsed.confidence),
      proofLevel: parseProofLevel(parsed.proof_level),
      proofVerdict: parseProofVerdict(parsed.proof_verdict),
      bypassAttempts: parseOptionalStringArray(parsed.bypass_attempts),
    };
  } catch (error) {
    throw new Error(`Invalid verification JSON response: ${toErrorMessage(error)}`);
  }
}

function normalizeTurns(value: number | undefined): number | undefined {
  if (value == null) return undefined;
  if (!Number.isFinite(value) || value < 1) {
    return DEFAULT_MAX_TURNS;
  }

  return Math.floor(value);
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.map((item) => String(item).trim()).filter(Boolean);
}

function normalizeNullableString(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value !== "string") return null;
  return value;
}

function clampConfidence(value: unknown): number {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 0;
  return Math.max(0, Math.min(1, numeric));
}

function asString(value: unknown, fallback: string): string {
  if (typeof value === "string") return value;
  if (value == null) return fallback;
  return String(value);
}

function asBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value !== "boolean") {
    return fallback;
  }

  return value;
}

const VALID_PROOF_VERDICTS = new Set<ProofVerdict>([
  "exploited",
  "blocked_by_security",
  "out_of_scope",
  "false_positive",
]);

function parseProofLevel(value: unknown): VerificationResult["proofLevel"] {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 1 || n > 4) return undefined;
  return Math.floor(n) as 1 | 2 | 3 | 4;
}

function parseProofVerdict(value: unknown): ProofVerdict | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim().toLowerCase() as ProofVerdict;
  return VALID_PROOF_VERDICTS.has(normalized) ? normalized : undefined;
}

function parseOptionalStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const result = value.map((item) => String(item).trim()).filter(Boolean);
  return result.length > 0 ? result : undefined;
}

// ---------------------------------------------------------------------------
// Batch verification
// ---------------------------------------------------------------------------

export const BATCH_VERIFICATION_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["results"],
  properties: {
    results: {
      type: "array",
      items: VERIFICATION_RESULT_SCHEMA,
    },
  },
} as const;

export const DEFAULT_VERIFY_BATCH_SIZE = 5;

export const BATCH_VERIFICATION_FALLBACK_DESCRIPTION = "Finding was not included in batch verification agent response.";

export interface BatchVerificationOutput {
  results: Map<string, VerificationResult>;
  costUsd: number;
}

export async function verifyFindingsBatch(
  items: Array<{ finding: Finding; triageResult: TriageResult }>,
  repoRoot: string,
  repoName: string,
  model: string,
  repoContext?: RepoContext,
  runtimeOptions: VerificationRuntimeOptions = {},
  maxBatchSize: number = DEFAULT_VERIFY_BATCH_SIZE,
  maxTurns: number | undefined = undefined,
  verifyTemplate?: string,
): Promise<BatchVerificationOutput> {
  if (items.length === 0) {
    return { results: new Map(), costUsd: 0 };
  }

  const effectiveBatchSize = Math.max(1, Math.floor(maxBatchSize));

  if (items.length <= effectiveBatchSize) {
    return verifySingleBatch(items, repoRoot, repoName, model, repoContext, runtimeOptions, maxTurns, verifyTemplate);
  }

  const allResults = new Map<string, VerificationResult>();
  let totalCost = 0;

  for (let i = 0; i < items.length; i += effectiveBatchSize) {
    const chunk = items.slice(i, i + effectiveBatchSize);
    const { results, costUsd } = await verifySingleBatch(
      chunk,
      repoRoot,
      repoName,
      model,
      repoContext,
      runtimeOptions,
      maxTurns,
      verifyTemplate,
    );

    for (const [fp, result] of results) {
      allResults.set(fp, result);
    }
    totalCost += costUsd;
  }

  return { results: allResults, costUsd: totalCost };
}

async function verifySingleBatch(
  items: Array<{ finding: Finding; triageResult: TriageResult }>,
  repoRoot: string,
  repoName: string,
  model: string,
  repoContext: RepoContext | undefined,
  runtimeOptions: VerificationRuntimeOptions,
  maxTurns: number | undefined,
  verifyTemplate?: string,
): Promise<BatchVerificationOutput> {
  const prompt = buildBatchVerificationPrompt(items, repoName, verifyTemplate);
  const effectiveMaxTurns = normalizeTurns(maxTurns);
  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    maxTurns: effectiveMaxTurns,
    allowedTools: resolveDefaultVerificationTools(runtimeOptions.runtime),
    runtimeOptions,
    systemPromptPrefix: verificationSystemPromptPrefix(repoContext, runtimeOptions.enrichedContext, runtimeOptions.extraPromptContext),
    schema: BATCH_VERIFICATION_SCHEMA,
    strict: true,
    retryInvalidStructuredOutput: 2,
  });

  if (executionError) {
    throw new VerificationExecutionError(`batch verification agent failed: ${executionError}`, costUsd);
  }

  const results = parseBatchVerificationOutput(structuredOutput ?? resultText, items);
  return { results, costUsd };
}

function buildBatchVerificationPrompt(
  items: Array<{ finding: Finding; triageResult: TriageResult }>,
  repoName: string,
  template?: string,
): string {
  const context = buildBatchVerifyContext(items, repoName);
  return renderTemplate(template ?? BATCH_VERIFY_TEMPLATE, context as any);
}

function parseBatchVerificationOutput(
  raw: unknown,
  items: Array<{ finding: Finding; triageResult: TriageResult }>,
): Map<string, VerificationResult> {
  const results = new Map<string, VerificationResult>();
  const fingerprintSet = new Set(items.map((item) => item.finding.fingerprint));

  let rawItems: unknown[] = [];

  // First try structured Zod validation for the batch envelope
  if (isRecord(raw)) {
    const batchValidation = RawBatchVerificationOutputSchema.safeParse(raw);
    if (batchValidation.success) {
      rawItems = batchValidation.data.results;
    } else {
      // Fall back to lenient extraction
      if (Array.isArray((raw as Record<string, unknown>)["results"])) {
        rawItems = (raw as Record<string, unknown>)["results"] as unknown[];
      }
      const errors = formatZodErrors(batchValidation.error.issues);
      console.warn(
        `[verify] Batch verification output has schema issues: ${errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
      );
    }
  } else if (Array.isArray(raw)) {
    rawItems = raw;
  } else if (typeof raw === "string") {
    try {
      const jsonStr = extractJson(raw);
      const parsed = JSON.parse(jsonStr);
      if (isRecord(parsed) && Array.isArray(parsed["results"])) {
        rawItems = parsed["results"] as unknown[];
      } else if (Array.isArray(parsed)) {
        rawItems = parsed;
      }
    } catch {
      // Fall through — missing findings will get fallback below
    }
  }

  for (const item of rawItems) {
    if (!isRecord(item)) continue;
    const fp = asString((item as Record<string, unknown>)["fingerprint"], "");
    if (!fp || !fingerprintSet.has(fp)) continue;

    results.set(fp, {
      fingerprint: fp,
      exploitable: asBoolean((item as Record<string, unknown>)["exploitable"], false),
      pocPayload: normalizeNullableString((item as Record<string, unknown>)["poc_payload"]),
      pocDescription: asString((item as Record<string, unknown>)["poc_description"], ""),
      attackVector: normalizeNullableString((item as Record<string, unknown>)["attack_vector"]),
      preconditions: normalizeStringArray((item as Record<string, unknown>)["preconditions"]),
      confidence: clampConfidence((item as Record<string, unknown>)["confidence"]),
      proofLevel: parseProofLevel((item as Record<string, unknown>)["proof_level"]),
      proofVerdict: parseProofVerdict((item as Record<string, unknown>)["proof_verdict"]),
      bypassAttempts: parseOptionalStringArray((item as Record<string, unknown>)["bypass_attempts"]),
    });
  }

  // Fill in any missing findings with not-exploitable fallback
  for (const item of items) {
    if (!results.has(item.finding.fingerprint)) {
      results.set(item.finding.fingerprint, {
        fingerprint: item.finding.fingerprint,
        exploitable: false,
        pocPayload: null,
        pocDescription: BATCH_VERIFICATION_FALLBACK_DESCRIPTION,
        attackVector: null,
        preconditions: [],
        confidence: 0,
        proofLevel: undefined,
        proofVerdict: undefined,
        bypassAttempts: undefined,
      });
    }
  }

  return results;
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
