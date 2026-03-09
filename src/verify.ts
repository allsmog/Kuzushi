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

export async function verifyFindingWithAgent(
  finding: Finding,
  triageResult: TriageResult,
  repoRoot: string,
  repoName: string,
  model: string,
  maxTurns: number,
  repoContextOrRuntimeOptions?: RepoContext | VerificationRuntimeOptions,
  maybeRuntimeOptions: VerificationRuntimeOptions = {},
): Promise<VerificationOutput> {
  const { repoContext, runtimeOptions } = resolveRepoContextAndRuntimeOptions(
    repoContextOrRuntimeOptions,
    maybeRuntimeOptions,
  );
  const prompt = buildVerificationPrompt(finding, triageResult, repoName, repoContext);
  const effectiveMaxTurns = normalizeTurns(maxTurns);
  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    maxTurns: effectiveMaxTurns,
    allowedTools: DEFAULT_TOOLS,
    runtimeOptions,
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
  repoContext?: RepoContext,
): string {
  const contextSection = formatRepoContext(repoContext);

  // Inject category-specific bypass techniques if available
  const bypassEntry = getBypassKnowledge(finding.cwe, finding.ruleId);
  const bypassSection = bypassEntry ? formatBypassForPrompt(bypassEntry) : [];

  return [
    "You are a senior exploit engineer and penetration tester. Your job is to determine if a",
    "reported vulnerability is concretely exploitable in practice — not just theoretically possible.",
    "You think like an attacker: you craft payloads, trace execution paths, and identify the exact",
    "conditions needed for exploitation.",
    ...(contextSection.length > 0 ? ["", "## Repository Context", ...contextSection] : []),
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
    "## Proof Level Framework",
    "Classify your findings using these proof levels:",
    "Level 1: Theoretical weakness identified",
    "Level 2: Partial bypass achieved (e.g., UI access without function)",
    "Level 3: Full bypass confirmed (unauthorized protected functionality)",
    "Level 4: Account takeover demonstrated",
    "",
    "## Bypass Exhaustion Protocol",
    "Before classifying as not-exploitable, you MUST try:",
    "- Direct exploitation with obvious payload",
    "- Parameter pollution / type juggling",
    "- Encoding bypass (URL, Unicode, double-encoding)",
    "- Race condition / timing attack",
    "- Chained exploitation with another weakness",
    "Document each attempt and its result in bypass_attempts.",
    "",
    "## Verdicts",
    "EXPLOITED: Level 3+ with concrete evidence",
    "BLOCKED_BY_SECURITY: Valid vuln but blocked by WAF/defense (document what blocks it)",
    "OUT_OF_SCOPE: Requires internal/physical access",
    "FALSE_POSITIVE: Exhausted all bypass techniques, confirmed safe",
    "",
    "## Confidence Escalation Protocol",
    "Start at 0.1. Escalate only with evidence:",
    "- 0.1-0.3: Identified theoretical weakness only",
    "- 0.3-0.5: Partial bypass achieved but blocked by defense",
    "- 0.5-0.7: Defense bypass feasible with specific technique",
    "- 0.7-0.9: Full bypass confirmed with concrete payload",
    "- 0.9-1.0: Complete exploitation demonstrated with account takeover",
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

function normalizeTurns(value: number): number {
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
