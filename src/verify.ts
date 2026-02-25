import { getAgentRuntime, type AgentRuntime } from "./agent-runtime/index.js";
import type { AllowedTriageTool, Finding } from "./scanners/types.js";
import type { RepoContext, TriageResult, VerificationResult } from "./types.js";
import type { AgentActivityCallback } from "./triage.js";

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
  },
} as const;

export const DEFAULT_TOOLS: AllowedTriageTool[] = ["Read", "Glob", "Grep"];
export const DEFAULT_MAX_TURNS = 15;

export interface VerificationRuntimeOptions {
  runtime?: AgentRuntime;
  abortController?: AbortController;
  maxBudgetUsd?: number;
  activityCallback?: AgentActivityCallback;
}

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
  const { repoContext, runtimeOptions } = resolveVerificationArgs(
    repoContextOrRuntimeOptions,
    maybeRuntimeOptions,
  );
  const runtime = runtimeOptions.runtime ?? getAgentRuntime();
  const prompt = buildVerificationPrompt(finding, triageResult, repoName, repoContext);
  const effectiveMaxTurns = normalizeTurns(maxTurns);

  let resultText = "";
  let structuredOutput: unknown = undefined;
  let executionError: string | null = null;
  let costUsd = 0;

  for await (const message of runtime.query({
    prompt,
    options: {
      cwd: repoRoot,
      model,
      maxTurns: effectiveMaxTurns,
      allowedTools: [...DEFAULT_TOOLS],
      permissionMode: "dontAsk",
      maxBudgetUsd: runtimeOptions.maxBudgetUsd,
      abortController: runtimeOptions.abortController,
      outputFormat: {
        type: "json_schema",
        schema: VERIFICATION_RESULT_SCHEMA,
      },
    },
  })) {
    if (message.type === "assistant") {
      await emitAssistantActivity(message.content, runtimeOptions.activityCallback);
      continue;
    }

    if (message.type === "tool-progress") {
      await runtimeOptions.activityCallback?.({
        kind: "tool-progress",
        toolName: message.toolName,
        elapsedSeconds: message.elapsedSeconds,
      });
      continue;
    }

    if (message.type === "tool-summary") {
      await runtimeOptions.activityCallback?.({
        kind: "tool-complete",
        summary: message.summary,
      });
      continue;
    }

    if (message.type !== "result") continue;
    if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
      costUsd = message.totalCostUsd;
    }

    if ("result" in message) {
      resultText = message.result;
      structuredOutput = message.structuredOutput;
      continue;
    }

    executionError = message.errors.join("; ") || message.subtype;
  }

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

  return [
    "You are an application security verification agent.",
    "Determine if the reported issue is concretely exploitable in practice.",
    ...(contextSection.length > 0 ? ["", "## Repository Context", ...contextSection] : []),
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
    "1. Trace attacker-controlled input sources to vulnerable sinks through real call paths.",
    "2. Identify sanitization, encoding, validation, authz, feature flags, and reachability constraints.",
    "3. Decide whether the issue is exploitable with a concrete input payload under realistic conditions.",
    "4. If exploitable, provide a concise PoC payload and attack vector.",
    "5. If not exploitable, explain precisely why (for example: sanitization, validation, unreachable path).",
    "6. List any preconditions required to reproduce impact.",
    "",
    "## Output requirements",
    "Return ONLY a JSON object with keys:",
    "fingerprint, exploitable(boolean), poc_payload(string|null), poc_description(string), attack_vector(string|null), preconditions(string[]), confidence(0..1)",
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

function resolveVerificationArgs(
  repoContextOrRuntimeOptions: RepoContext | VerificationRuntimeOptions | undefined,
  maybeRuntimeOptions: VerificationRuntimeOptions,
): { repoContext?: RepoContext; runtimeOptions: VerificationRuntimeOptions } {
  if (!repoContextOrRuntimeOptions) {
    return { runtimeOptions: maybeRuntimeOptions };
  }

  if (looksLikeRuntimeOptions(repoContextOrRuntimeOptions)) {
    return {
      runtimeOptions: repoContextOrRuntimeOptions,
    };
  }

  return {
    repoContext: repoContextOrRuntimeOptions,
    runtimeOptions: maybeRuntimeOptions,
  };
}

function looksLikeRuntimeOptions(
  value: RepoContext | VerificationRuntimeOptions,
): value is VerificationRuntimeOptions {
  const runtimeOptions = value as VerificationRuntimeOptions;
  return (
    "runtime" in runtimeOptions
    || "abortController" in runtimeOptions
    || "maxBudgetUsd" in runtimeOptions
    || "activityCallback" in runtimeOptions
  );
}

function normalizeCostUsd(value: number): number {
  if (!Number.isFinite(value) || value < 0) {
    return 0;
  }

  return value;
}

function extractJson(text: string): string {
  const fenceMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenceMatch) return fenceMatch[1].trim();

  const braceStart = text.indexOf("{");
  const braceEnd = text.lastIndexOf("}");
  if (braceStart !== -1 && braceEnd > braceStart) {
    return text.slice(braceStart, braceEnd + 1);
  }

  return text.trim();
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

function formatRepoContext(repoContext: RepoContext | undefined): string[] {
  if (!repoContext) {
    return [];
  }

  const lines: string[] = [];
  if (repoContext.languages.length > 0) {
    lines.push(`Languages: ${repoContext.languages.join(", ")}`);
  }
  if (repoContext.frameworks.length > 0) {
    lines.push(`Frameworks: ${repoContext.frameworks.join(", ")}`);
  }
  if (repoContext.authPatterns.length > 0) {
    lines.push(`Auth: ${repoContext.authPatterns.join(", ")}`);
  }
  if (repoContext.ormOrDb.length > 0) {
    lines.push(`ORM/DB: ${repoContext.ormOrDb.join(", ")}`);
  }
  if (repoContext.sanitizationLibs.length > 0) {
    lines.push(`Sanitization: ${repoContext.sanitizationLibs.join(", ")}`);
  }
  if (repoContext.entryPoints.length > 0) {
    lines.push(`Entry points: ${repoContext.entryPoints.join(", ")}`);
  }

  return lines;
}

async function emitAssistantActivity(
  blocks: Array<Record<string, unknown>>,
  callback: AgentActivityCallback | undefined,
): Promise<void> {
  if (!callback) {
    return;
  }

  for (const block of blocks) {
    const blockType = asString(block["type"], "");

    if (blockType === "tool_use") {
      const toolName = asString(block["name"], "");
      const input = isRecord(block["input"]) ? block["input"] : undefined;
      await callback({
        kind: "tool-start",
        toolName: toolName || undefined,
        toolInput: input,
      });
      continue;
    }

    if (blockType === "text") {
      const text = asString(block["text"], "").trim();
      if (!text) continue;
      await callback({
        kind: "reasoning",
        summary: text,
      });
    }
  }
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}
