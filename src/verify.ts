import {
  DEFAULT_READ_ONLY_TOOLS,
  extractJson,
  resolveRepoContextAndRuntimeOptions,
  runStructuredAgentQuery,
  type AgentActivityCallback,
  type AgentRuntimeOptions,
} from "./agent-runtime/execution.js";
import type { AllowedTriageTool, Finding } from "./scanners/types.js";
import type { ProofVerdict, RepoContext, TriageResult, VerificationResult } from "./types.js";
import { getBypassKnowledge, formatBypassForPrompt } from "./bypass-knowledge.js";
import { formatRepoContext } from "./repo-context.js";
import {
  bypassExhaustionModule,
  composePromptModules,
  confidenceEscalationModule,
  proofLevelModule,
} from "./prompts/modules.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "./utils.js";

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

export const DEFAULT_TOOLS: AllowedTriageTool[] = [...DEFAULT_READ_ONLY_TOOLS];
export const DEFAULT_MAX_TURNS = 15;

export interface VerificationRuntimeOptions extends AgentRuntimeOptions {}

export interface VerificationOutput {
  result: VerificationResult;
  costUsd: number;
}

export class VerificationExecutionError extends Error {
  readonly costUsd: number;

  constructor(message: string, costUsd = 0) {
    super(message);
    this.name = "VerificationExecutionError";
    this.costUsd = normalizeCostUsd(costUsd);
  }
}

export function verificationSystemPromptPrefix(repoContext?: RepoContext): string {
  const repoSection = formatRepoContext(repoContext);
  const repoBlock = repoSection.length > 0
    ? "## Repository Context\n" + repoSection.join("\n") + "\n\n"
    : "";
  return repoBlock + composePromptModules(
    proofLevelModule(),
    bypassExhaustionModule(),
    confidenceEscalationModule("verification"),
  );
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
): Promise<VerificationOutput> {
  const { repoContext, runtimeOptions } = resolveRepoContextAndRuntimeOptions(
    repoContextOrRuntimeOptions,
    maybeRuntimeOptions,
  );
  const prompt = buildVerificationPrompt(finding, triageResult, repoName);
  const effectiveMaxTurns = normalizeTurns(maxTurns);
  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    maxTurns: effectiveMaxTurns,
    allowedTools: DEFAULT_TOOLS,
    runtimeOptions,
    systemPromptPrefix: verificationSystemPromptPrefix(repoContext),
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
): string {
  // Inject category-specific bypass techniques if available
  const bypassEntry = getBypassKnowledge(finding.cwe, finding.ruleId);
  const bypassSection = bypassEntry ? formatBypassForPrompt(bypassEntry) : [];

  return [
    "You are a senior exploit engineer and penetration tester. Your job is to determine if a",
    "reported vulnerability is concretely exploitable in practice — not just theoretically possible.",
    "You think like an attacker: you craft payloads, trace execution paths, and identify the exact",
    "conditions needed for exploitation.",
    ...(bypassSection.length > 0 ? ["", ...bypassSection] : []),
    "",
    "## Finding",
    `Repo: ${repoName}`,
    `Scanner: ${finding.scanner}`,
    `Rule: ${finding.ruleId}`,
    `File: ${finding.filePath}:${finding.startLine}`,
    `Severity: ${finding.severity}`,
    `CWE: ${finding.cwe.join(", ") || "none"}`,
    `Message: ${finding.message}`,
    `Fingerprint: ${finding.fingerprint}`,
    "",
    "## Prior triage assessment",
    `Verdict: ${triageResult.verdict}`,
    `Confidence: ${triageResult.confidence}`,
    `Rationale: ${triageResult.rationale}`,
    `Verification steps: ${triageResult.verificationSteps.join(" | ") || "none"}`,
    "",
    "## Verification instructions",
    ...(finding.filePath !== "."
      ? [
          "1. Trace attacker-controlled input sources to vulnerable sinks through real call paths.",
          "2. Identify sanitization, encoding, validation, authz, feature flags, and reachability constraints.",
          "3. Decide whether the issue is exploitable with a concrete input payload under realistic conditions.",
          "4. If exploitable, provide a concise PoC payload and attack vector.",
          "5. If not exploitable, explain precisely why (for example: sanitization, validation, unreachable path).",
          "6. List any preconditions required to reproduce impact.",
        ]
      : [
          "This is an architectural/threat-model finding without a specific file. Use Glob and Grep to identify relevant source files.",
          "1. Verify the described threat is realistic given the actual system architecture and code.",
          "2. Check whether existing mitigations (auth, validation, rate limiting, encryption) address the threat.",
          "3. Decide whether the issue is concretely exploitable under realistic conditions.",
          "4. If exploitable, describe a concrete attack vector and payload.",
          "5. If not exploitable, explain precisely which mitigations prevent it.",
          "6. List any preconditions required to reproduce impact.",
        ]),
    "",
    "## Output requirements",
    "Return ONLY a JSON object with keys:",
    "fingerprint, exploitable(boolean), poc_payload(string|null), poc_description(string),",
    "attack_vector(string|null), preconditions(string[]), confidence(0..1),",
    "proof_level(1-4, optional), proof_verdict(exploited|blocked_by_security|out_of_scope|false_positive, optional),",
    "bypass_attempts(string[], optional)",
  ].join("\n");
}

export function parseVerificationOutput(raw: unknown, fingerprint: string): VerificationResult {
  if (isRecord(raw)) {
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
): Promise<BatchVerificationOutput> {
  if (items.length === 0) {
    return { results: new Map(), costUsd: 0 };
  }

  const effectiveBatchSize = Math.max(1, Math.floor(maxBatchSize));

  if (items.length <= effectiveBatchSize) {
    return verifySingleBatch(items, repoRoot, repoName, model, repoContext, runtimeOptions, maxTurns);
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
): Promise<BatchVerificationOutput> {
  const prompt = buildBatchVerificationPrompt(items, repoName);
  const effectiveMaxTurns = normalizeTurns(maxTurns);
  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    maxTurns: effectiveMaxTurns,
    allowedTools: DEFAULT_TOOLS,
    runtimeOptions,
    systemPromptPrefix: verificationSystemPromptPrefix(repoContext),
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
): string {
  const findingSections = items.map((item, idx) => {
    const { finding, triageResult } = item;
    return [
      `### Finding ${idx + 1}`,
      `Scanner: ${finding.scanner}`,
      `Rule: ${finding.ruleId}`,
      `File: ${finding.filePath}:${finding.startLine}`,
      `Severity: ${finding.severity}`,
      `CWE: ${finding.cwe.join(", ") || "none"}`,
      `Message: ${finding.message}`,
      `Fingerprint: ${finding.fingerprint}`,
      `Triage verdict: ${triageResult.verdict}`,
      `Triage confidence: ${triageResult.confidence}`,
      `Triage rationale: ${triageResult.rationale}`,
      `Triage verification steps: ${triageResult.verificationSteps.join(" | ") || "none"}`,
    ].join("\n");
  });

  return [
    "You are a senior exploit engineer and penetration tester. Your job is to determine if",
    "reported vulnerabilities are concretely exploitable in practice — not just theoretically possible.",
    "You think like an attacker: you craft payloads, trace execution paths, and identify the exact",
    "conditions needed for exploitation.",
    "",
    "Investigate ALL of the following findings and determine exploitability for each.",
    "",
    `Repo: ${repoName}`,
    "",
    `## Findings (${items.length} total)`,
    "",
    ...findingSections.flatMap((s) => [s, ""]),
    "## Verification instructions",
    "For each finding:",
    "1. Trace attacker-controlled input sources to vulnerable sinks through real call paths.",
    "2. Identify sanitization, encoding, validation, authz, feature flags, and reachability constraints.",
    "3. Decide whether the issue is exploitable with a concrete input payload under realistic conditions.",
    "4. If exploitable, provide a concise PoC payload and attack vector.",
    "5. If not exploitable, explain precisely why.",
    "6. List any preconditions required to reproduce impact.",
    "",
    "## Output requirements",
    'Return ONLY a JSON object with a "results" array. Each element MUST have:',
    "fingerprint, exploitable(boolean), poc_payload(string|null), poc_description(string),",
    "attack_vector(string|null), preconditions(string[]), confidence(0..1),",
    "proof_level(1-4, optional), proof_verdict(optional), bypass_attempts(string[], optional)",
    "",
    `You must return exactly ${items.length} results, one per finding, using the exact fingerprints listed above.`,
  ].join("\n");
}

function parseBatchVerificationOutput(
  raw: unknown,
  items: Array<{ finding: Finding; triageResult: TriageResult }>,
): Map<string, VerificationResult> {
  const results = new Map<string, VerificationResult>();
  const fingerprintSet = new Set(items.map((item) => item.finding.fingerprint));

  let rawItems: unknown[] = [];

  if (isRecord(raw) && Array.isArray((raw as Record<string, unknown>)["results"])) {
    rawItems = (raw as Record<string, unknown>)["results"] as unknown[];
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
