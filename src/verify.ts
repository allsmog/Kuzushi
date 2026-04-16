import {
  extractJson,
  resolveDefaultReadOnlyTools,
  resolveRepoContextAndRuntimeOptions,
  runStructuredAgentQuery,
  runStructuredSessionQuery,
  type AgentActivityCallback,
  type AgentRuntimeOptions,
} from "./agent-runtime/execution.js";
import type { AgentSession } from "./agent-runtime/types.js";
import { writeBatchFile, cleanupBatchFiles } from "./agent-runtime/batch-files.js";
import type { AllowedTriageTool, Finding } from "./scanners/types.js";
import type {
  CodeCitation,
  AttackPathAnalysis,
  SecurityControl,
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
import { getLogger } from "./logger.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "./utils.js";
import { RawVerificationOutputSchema, RawBatchVerificationOutputSchema, formatZodErrors } from "./schemas.js";
import { renderTemplate } from "./prompts/template.js";
import { VERIFY_UNIFIED_TEMPLATE } from "./prompts/templates/verify.js";
import { BATCH_VERIFY_TEMPLATE } from "./prompts/templates/verify.js";
import { buildVerifyContext, buildBatchVerifyContext } from "./prompts/context.js";

const log = getLogger("verify");

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
    code_citations: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["file_path", "start_line", "end_line", "snippet", "description"],
        properties: {
          file_path: { type: "string" },
          start_line: { type: "integer" },
          end_line: { type: "integer" },
          snippet: { type: "string" },
          description: { type: "string" },
        },
      },
    },
    attack_path: {
      type: "object",
      additionalProperties: false,
      required: ["chain", "narrative", "likelihood_reasoning", "impact_reasoning"],
      properties: {
        chain: { type: "array", items: { type: "string" } },
        narrative: { type: "string" },
        likelihood_reasoning: { type: "string" },
        impact_reasoning: { type: "string" },
      },
    },
    assumptions: { type: "array", items: { type: "string" } },
    controls: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name", "description"],
        properties: {
          name: { type: "string" },
          description: { type: "string" },
          file_path: { type: "string" },
        },
      },
    },
    blindspots: { type: "array", items: { type: "string" } },
  },
} as const;

export const DEFAULT_MAX_TURNS = 15;

export interface VerificationRuntimeOptions extends AgentRuntimeOptions {
  enrichedContext?: EnrichedRepoContext["enrichment"];
  /** Extra prompt context injected by knowledge registry, precedents, etc. */
  extraPromptContext?: string;
  /** Enable Write/Bash/Edit tools for runtime instrumentation (runs in worktree sandbox). */
  enableInstrumentation?: boolean;
}

export interface VerificationOutput {
  result: VerificationResult;
  costUsd: number;
}

export function resolveDefaultVerificationTools(
  runtime: AgentRuntimeOptions["runtime"] | undefined,
  enableInstrumentation = false,
): AllowedTriageTool[] {
  const tools = normalizeAllowedTriageToolNames(resolveDefaultReadOnlyTools(runtime));
  if (enableInstrumentation) {
    tools.push("Write" as AllowedTriageTool, "Bash" as AllowedTriageTool, "Edit" as AllowedTriageTool);
  }
  return tools;
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
  enableInstrumentation?: boolean,
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
  const instrumentationBlock = enableInstrumentation
    ? "\n\n## Runtime Instrumentation\n"
      + "You have Write, Edit, and Bash tools available for runtime instrumentation.\n"
      + "When exploitability is unclear from static analysis alone:\n"
      + "1. Insert trace/debug statements (print, log, assert) at key points in the code path\n"
      + "2. Use Bash to run tests, compile, or execute the modified code\n"
      + "3. Read the output to observe actual data flow and behavior\n"
      + "4. Iterate: refine instrumentation based on what you observe\n"
      + "5. Determine exploitability from runtime evidence, not just code review\n"
      + "All changes are in a disposable sandbox — do not worry about breaking things.\n"
    : "";
  return repoBlock + enrichedBlock + instrumentationBlock + composePromptModules(
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
  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    allowedTools: resolveDefaultVerificationTools(runtimeOptions.runtime, runtimeOptions.enableInstrumentation),
    runtimeOptions,
    systemPromptPrefix: verificationSystemPromptPrefix(repoContext, runtimeOptions.enrichedContext, runtimeOptions.extraPromptContext, runtimeOptions.enableInstrumentation),
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
    const validation = RawVerificationOutputSchema.safeParse(raw);
    if (!validation.success) {
      const errors = formatZodErrors(validation.error.issues);
      log.warn(
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
      codeCitations: parseCodeCitations(raw["code_citations"]),
      attackPath: parseAttackPath(raw["attack_path"]),
      assumptions: parseOptionalStringArray(raw["assumptions"]),
      controls: parseControls(raw["controls"]),
      blindspots: parseOptionalStringArray(raw["blindspots"]),
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

    const validation = RawVerificationOutputSchema.safeParse(parsed);
    if (!validation.success) {
      const errors = formatZodErrors(validation.error.issues);
      log.warn(
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
      codeCitations: parseCodeCitations(parsed.code_citations),
      attackPath: parseAttackPath(parsed.attack_path),
      assumptions: parseOptionalStringArray(parsed.assumptions),
      controls: parseControls(parsed.controls),
      blindspots: parseOptionalStringArray(parsed.blindspots),
    };
  } catch (error) {
    throw new Error(`Invalid verification JSON response: ${toErrorMessage(error)}`);
  }
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

function parseCodeCitations(value: unknown): CodeCitation[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const citations: CodeCitation[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") continue;
    const rec = item as Record<string, unknown>;
    const filePath = typeof rec["file_path"] === "string" ? rec["file_path"].trim() : "";
    const startLine = Number(rec["start_line"]);
    const endLine = Number(rec["end_line"]);
    let snippet = typeof rec["snippet"] === "string" ? rec["snippet"] : "";
    const description = typeof rec["description"] === "string" ? rec["description"].trim() : "";
    if (!filePath || !Number.isFinite(startLine) || !description) continue;
    if (snippet.length > 2000) snippet = snippet.slice(0, 2000) + "\n...truncated";
    citations.push({
      filePath,
      startLine,
      endLine: Number.isFinite(endLine) ? endLine : startLine,
      snippet,
      description,
    });
  }
  return citations.length > 0 ? citations : undefined;
}

function parseAttackPath(value: unknown): AttackPathAnalysis | undefined {
  if (!value || typeof value !== "object") return undefined;
  const rec = value as Record<string, unknown>;
  const chain = Array.isArray(rec["chain"])
    ? rec["chain"].map((s: unknown) => String(s).trim()).filter(Boolean)
    : [];
  const narrative = typeof rec["narrative"] === "string" ? rec["narrative"].trim() : "";
  const likelihoodReasoning = typeof rec["likelihood_reasoning"] === "string"
    ? rec["likelihood_reasoning"].trim() : "";
  const impactReasoning = typeof rec["impact_reasoning"] === "string"
    ? rec["impact_reasoning"].trim() : "";
  if (chain.length === 0 && !narrative) return undefined;
  return { chain, narrative, likelihoodReasoning, impactReasoning };
}

function parseControls(value: unknown): SecurityControl[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const controls: SecurityControl[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") continue;
    const rec = item as Record<string, unknown>;
    const name = typeof rec["name"] === "string" ? rec["name"].trim() : "";
    const description = typeof rec["description"] === "string" ? rec["description"].trim() : "";
    const filePath = typeof rec["file_path"] === "string" ? rec["file_path"].trim() : undefined;
    if (!name || !description) continue;
    controls.push({ name, description, filePath: filePath || undefined });
  }
  return controls.length > 0 ? controls : undefined;
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
  missingFingerprints: string[];
  incomplete: boolean;
  recoveredByRetry: string[];
}

export async function verifyFindingsBatch(
  items: Array<{ finding: Finding; triageResult: TriageResult }>,
  repoRoot: string,
  repoName: string,
  model: string,
  repoContext?: RepoContext,
  runtimeOptions: VerificationRuntimeOptions = {},
  maxBatchSize: number = DEFAULT_VERIFY_BATCH_SIZE,
  verifyTemplate?: string,
): Promise<BatchVerificationOutput> {
  if (items.length === 0) {
    return {
      results: new Map(),
      costUsd: 0,
      missingFingerprints: [],
      incomplete: false,
      recoveredByRetry: [],
    };
  }

  const effectiveBatchSize = Math.max(1, Math.floor(maxBatchSize));

  if (items.length <= effectiveBatchSize) {
    return verifySingleBatch(items, repoRoot, repoName, model, repoContext, runtimeOptions, verifyTemplate);
  }

  const allResults = new Map<string, VerificationResult>();
  let totalCost = 0;
  const missingFingerprints = new Set<string>();

  // Try to create a reusable session for subprocess reuse across batches
  const runtime = runtimeOptions.runtime;
  const session = runtime?.createSession?.({
    cwd: repoRoot,
    model,
    allowedTools: [...resolveDefaultVerificationTools(runtime, runtimeOptions.enableInstrumentation)],
    permissionMode: "dontAsk",
    outputFormat: {
      type: "json_schema",
      schema: BATCH_VERIFICATION_SCHEMA,
      strict: true,
    },
    systemPromptPrefix: verificationSystemPromptPrefix(repoContext, runtimeOptions.enrichedContext, runtimeOptions.extraPromptContext, runtimeOptions.enableInstrumentation),
  });

  const runId = session ? crypto.randomUUID() : "";

  try {
    let batchIdx = 0;
    for (let i = 0; i < items.length; i += effectiveBatchSize) {
      const chunk = items.slice(i, i + effectiveBatchSize);

      const chunkResult = session
        ? await verifySingleBatchSession(
            chunk,
            repoRoot,
            repoName,
            session,
            runId,
            batchIdx,
            verifyTemplate,
          )
        : await verifySingleBatch(
            chunk,
            repoRoot,
            repoName,
            model,
            repoContext,
            runtimeOptions,
            verifyTemplate,
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

async function verifySingleBatchSession(
  items: Array<{ finding: Finding; triageResult: TriageResult }>,
  repoRoot: string,
  repoName: string,
  session: AgentSession,
  runId: string,
  batchIdx: number,
  _verifyTemplate?: string,
): Promise<BatchVerificationOutput> {
  const batchData = {
    repoName,
    findingCount: items.length,
    items: items.map(({ finding, triageResult }) => ({
      finding: {
        fingerprint: finding.fingerprint,
        taskId: finding.taskId,
        ruleId: finding.ruleId,
        filePath: finding.filePath,
        startLine: finding.startLine,
        severity: finding.severity,
        scannerConfidence: finding.scannerConfidence,
        likelihood: finding.likelihood,
        impact: finding.impact,
        cwe: finding.cwe,
        message: finding.message,
        evidence: finding.evidence || null,
      },
      triage: {
        verdict: triageResult.verdict,
        confidence: triageResult.confidence,
        rationale: triageResult.rationale,
        verificationSteps: triageResult.verificationSteps,
      },
    })),
  };

  const filePath = writeBatchFile(repoRoot, runId, "verify", batchIdx, batchData);
  const prompt = `Read ${filePath} and verify each finding. For each, determine exploitability, craft a PoC payload if possible, identify attack vector, preconditions, and confidence.`;

  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredSessionQuery(
    session,
    prompt,
  );

  if (executionError) {
    throw new VerificationExecutionError(`batch verification agent failed: ${executionError}`, costUsd);
  }

  const parsed = parseBatchVerificationOutput(structuredOutput ?? resultText, items);
  return {
    ...parsed,
    costUsd,
    recoveredByRetry: [],
  };
}

async function verifySingleBatch(
  items: Array<{ finding: Finding; triageResult: TriageResult }>,
  repoRoot: string,
  repoName: string,
  model: string,
  repoContext: RepoContext | undefined,
  runtimeOptions: VerificationRuntimeOptions,
  verifyTemplate?: string,
): Promise<BatchVerificationOutput> {
  const prompt = buildBatchVerificationPrompt(items, repoName, verifyTemplate);
  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    allowedTools: resolveDefaultVerificationTools(runtimeOptions.runtime, runtimeOptions.enableInstrumentation),
    runtimeOptions,
    systemPromptPrefix: verificationSystemPromptPrefix(repoContext, runtimeOptions.enrichedContext, runtimeOptions.extraPromptContext, runtimeOptions.enableInstrumentation),
    schema: BATCH_VERIFICATION_SCHEMA,
    strict: true,
    retryInvalidStructuredOutput: 2,
  });

  if (executionError) {
    throw new VerificationExecutionError(`batch verification agent failed: ${executionError}`, costUsd);
  }

  const parsed = parseBatchVerificationOutput(structuredOutput ?? resultText, items);
  return {
    ...parsed,
    costUsd,
    recoveredByRetry: [],
  };
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
): Omit<BatchVerificationOutput, "costUsd" | "recoveredByRetry"> {
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
      log.warn(
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
      // Fall through — missing findings will be reported via missingFingerprints.
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
      codeCitations: parseCodeCitations((item as Record<string, unknown>)["code_citations"]),
      attackPath: parseAttackPath((item as Record<string, unknown>)["attack_path"]),
      assumptions: parseOptionalStringArray((item as Record<string, unknown>)["assumptions"]),
      controls: parseControls((item as Record<string, unknown>)["controls"]),
      blindspots: parseOptionalStringArray((item as Record<string, unknown>)["blindspots"]),
    });
  }

  const missingFingerprints = items
    .map((item) => item.finding.fingerprint)
    .filter((fingerprint) => !results.has(fingerprint));

  return {
    results,
    missingFingerprints,
    incomplete: missingFingerprints.length > 0,
  };
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
