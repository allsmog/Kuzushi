import { getAgentRuntime, type AgentRuntime } from "./agent-runtime/index.js";
import type {
  AllowedTriageTool,
  Finding,
  TriageAgentConfig,
} from "./scanners/types.js";
import type { RepoContext, TriageResult, Verdict } from "./types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "./utils.js";

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
  },
} as const;

export const DEFAULT_TOOLS: AllowedTriageTool[] = ["Read", "Glob", "Grep"];
export const DEFAULT_MAX_TURNS = 10;

export interface TriageRuntimeOptions {
  runtime?: AgentRuntime;
  abortController?: AbortController;
  maxBudgetUsd?: number;
  activityCallback?: AgentActivityCallback;
}

export interface TriageConfigProvider {
  has(id: string): boolean;
  get(id: string): {
    triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig;
  };
}

export interface AgentActivity {
  kind: "tool-start" | "tool-progress" | "tool-complete" | "reasoning";
  toolName?: string;
  toolInput?: Record<string, unknown>;
  summary?: string;
  elapsedSeconds?: number;
}

export type AgentActivityCallback = (
  activity: AgentActivity,
) => Promise<void> | void;

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

export async function triageFindingWithAgent(
  registry: TriageConfigProvider,
  finding: Finding,
  repoRoot: string,
  repoName: string,
  model: string,
  maxTurns: number,
  repoContextOrRuntimeOptions?: RepoContext | TriageRuntimeOptions,
  maybeRuntimeOptions: TriageRuntimeOptions = {},
): Promise<TriageOutput> {
  const { repoContext, runtimeOptions } = resolveTriageArgs(
    repoContextOrRuntimeOptions,
    maybeRuntimeOptions,
  );
  const agentConfig = resolveAgentConfig(registry, finding, repoName, repoContext);
  const allowedTools = normalizeAllowedTools(agentConfig.allowedTools);
  const effectiveMaxTurns = normalizeTurns(agentConfig.maxTurns ?? maxTurns);
  const runtime = runtimeOptions.runtime ?? getAgentRuntime();

  let resultText = "";
  let structuredOutput: unknown = undefined;
  let executionError: string | null = null;
  let costUsd = 0;

  for await (const message of runtime.query({
    prompt: agentConfig.prompt,
    options: {
      cwd: repoRoot,
      model,
      maxTurns: effectiveMaxTurns,
      allowedTools,
      permissionMode: "dontAsk",
      maxBudgetUsd: runtimeOptions.maxBudgetUsd,
      abortController: runtimeOptions.abortController,
      outputFormat: {
        type: "json_schema",
        schema: TRIAGE_RESULT_SCHEMA,
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

    executionError = (Array.isArray(message.errors) ? message.errors.join("; ") : "") || message.subtype || "unknown error";
  }

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
  maxTurns: number = DEFAULT_MAX_TURNS,
): Promise<BatchTriageOutput> {
  if (findings.length === 0) {
    return { results: new Map(), costUsd: 0 };
  }

  const effectiveBatchSize = Math.max(1, Math.floor(maxBatchSize));

  if (findings.length <= effectiveBatchSize) {
    return triageSingleBatch(findings, repoRoot, repoName, model, repoContext, runtimeOptions, maxTurns);
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
  maxTurns: number = DEFAULT_MAX_TURNS,
): Promise<BatchTriageOutput> {
  const prompt = buildBatchTriagePrompt(findings, repoName, repoContext);
  const runtime = runtimeOptions.runtime ?? getAgentRuntime();
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
        schema: BATCH_TRIAGE_SCHEMA,
        strict: true,
        retryInvalidStructuredOutput: 2,
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

    executionError = (Array.isArray(message.errors) ? message.errors.join("; ") : "") || message.subtype || "unknown error";
  }

  if (executionError) {
    throw new TriageExecutionError(`batch triage agent failed: ${executionError}`, costUsd);
  }

  const results = parseBatchTriageOutput(structuredOutput ?? resultText, findings);
  return { results, costUsd };
}

function buildBatchTriagePrompt(
  findings: Finding[],
  repoName: string,
  repoContext?: RepoContext,
): string {
  const contextSection = formatRepoContext(repoContext);
  const findingSections = findings.map((f, idx) => [
    `### Finding ${idx + 1}`,
    `Scanner: ${f.scanner}`,
    `Rule: ${f.ruleId}`,
    `File: ${f.filePath}:${f.startLine}`,
    `Severity: ${f.severity}`,
    `Scanner Confidence: ${f.scannerConfidence}`,
    `Likelihood: ${f.likelihood}`,
    `Impact: ${f.impact}`,
    `CWE: ${f.cwe.join(", ") || "none"}`,
    `Message: ${f.message}`,
    `Evidence: ${f.evidence || "none"}`,
    `Fingerprint: ${f.fingerprint}`,
  ].join("\n"));

  return [
    "You are a security triage agent. Investigate ALL of the following findings and determine if each is a true positive, false positive, or needs review.",
    "",
    `Repo: ${repoName}`,
    ...(contextSection.length > 0 ? ["", "## Repository Context", ...contextSection] : []),
    "",
    `## Findings (${findings.length} total)`,
    "",
    ...findingSections.flatMap((s) => [s, ""]),
    "## Investigation instructions",
    "1. Read the flagged files and surrounding code.",
    "2. Trace dataflow from source to sink across call boundaries.",
    "3. Use Grep/Glob to locate sanitization, validation, and guards.",
    "4. Validate reachability and realistic attacker control.",
    "5. Decide tp/fp/needs_review per finding with conservative confidence.",
    "",
    "## Output requirements",
    'Return ONLY a JSON object with a "results" array. Each element MUST have:',
    "fingerprint, verdict(tp|fp|needs_review), confidence(0..1), rationale, verification_steps(array of strings), fix_patch(string|null)",
    "",
    `You must return exactly ${findings.length} results, one per finding, using the exact fingerprints listed above.`,
  ].join("\n");
}

function parseBatchTriageOutput(
  raw: unknown,
  findings: Finding[],
): Map<string, TriageResult> {
  const results = new Map<string, TriageResult>();
  const fingerprintSet = new Set(findings.map((f) => f.fingerprint));

  let items: unknown[] = [];

  if (isRecord(raw) && Array.isArray((raw as Record<string, unknown>)["results"])) {
    items = (raw as Record<string, unknown>)["results"] as unknown[];
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
  repoContext?: RepoContext,
): TriageAgentConfig {
  const contextSection = formatRepoContext(repoContext);

  return {
    prompt: [
      "You are a security triage agent.",
      "Use available repo tools to investigate whether this finding is a true or false positive.",
      ...(contextSection.length > 0 ? ["", "## Repository Context", ...contextSection] : []),
      "",
      "## Finding",
      `Repo: ${repoName}`,
      `Scanner: ${finding.scanner}`,
      `Rule: ${finding.ruleId}`,
      `File: ${finding.filePath}:${finding.startLine}`,
      `Severity: ${finding.severity}`,
      `Scanner Confidence: ${finding.scannerConfidence}`,
      `Likelihood: ${finding.likelihood}`,
      `Impact: ${finding.impact}`,
      `CWE: ${finding.cwe.join(", ") || "none"}`,
      `Message: ${finding.message}`,
      `Evidence: ${finding.evidence || "none"}`,
      `Fingerprint: ${finding.fingerprint}`,
      "",
      "## Investigation instructions",
      "1. Read the flagged file and surrounding code.",
      "2. Trace dataflow to source/sink across call boundaries.",
      "3. Use Grep/Glob to locate sanitization, validation, and guards.",
      "4. Validate reachability and realistic attacker control.",
      "5. Decide tp/fp/needs_review with conservative confidence.",
      "",
      "## Output requirements",
      "Return ONLY a JSON object with:",
      "fingerprint, verdict(tp|fp|needs_review), confidence(0..1), rationale, verification_steps(array), fix_patch(string|null)",
    ].join("\n"),
  };
}

function resolveAgentConfig(
  registry: TriageConfigProvider,
  finding: Finding,
  repoName: string,
  repoContext?: RepoContext,
): TriageAgentConfig {
  if (!registry.has(finding.scanner)) {
    return buildDefaultTriageAgentConfig(finding, repoName, repoContext);
  }

  try {
    const config = registry.get(finding.scanner).triageAgentConfig(finding, repoName);
    if (!config.prompt || !config.prompt.trim()) {
      return buildDefaultTriageAgentConfig(finding, repoName, repoContext);
    }
    return config;
  } catch {
    return buildDefaultTriageAgentConfig(finding, repoName, repoContext);
  }
}

function resolveTriageArgs(
  repoContextOrRuntimeOptions: RepoContext | TriageRuntimeOptions | undefined,
  maybeRuntimeOptions: TriageRuntimeOptions,
): { repoContext?: RepoContext; runtimeOptions: TriageRuntimeOptions } {
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

function looksLikeRuntimeOptions(value: RepoContext | TriageRuntimeOptions): value is TriageRuntimeOptions {
  const runtimeOptions = value as TriageRuntimeOptions;
  return (
    "runtime" in runtimeOptions
    || "abortController" in runtimeOptions
    || "maxBudgetUsd" in runtimeOptions
    || "activityCallback" in runtimeOptions
  );
}

function normalizeAllowedTools(tools: AllowedTriageTool[] | undefined): AllowedTriageTool[] {
  if (!Array.isArray(tools) || tools.length === 0) {
    return [...DEFAULT_TOOLS];
  }

  const normalized = tools
    .filter((tool): tool is AllowedTriageTool => (
      tool === "Read" || tool === "Glob" || tool === "Grep"
    ));

  return normalized.length > 0 ? normalized : [...DEFAULT_TOOLS];
}

function normalizeTurns(value: number): number {
  if (!Number.isFinite(value) || value < 1) {
    return DEFAULT_MAX_TURNS;
  }

  return Math.floor(value);
}

/** Parse a verdict string, defaulting to needs_review for unknown values. */
export function parseVerdict(v: string): Verdict {
  const normalized = v.trim().toLowerCase();
  if (normalized === "tp" || normalized === "fp" || normalized === "needs_review") return normalized;
  return "needs_review";
}

/** Extract JSON from LLM response, handling markdown fences and preamble. */
export function extractJson(text: string): string {
  // Use a greedy match that requires the closing fence at the start of a line
  // to avoid breaking on nested code fences inside JSON string values.
  const fenceMatch = text.match(/```(?:json)?\s*\n([\s\S]*?)\n\s*```/);
  if (fenceMatch) return fenceMatch[1].trim();

  const braceStart = text.indexOf("{");
  const braceEnd = text.lastIndexOf("}");
  if (braceStart !== -1 && braceEnd > braceStart) {
    return text.slice(braceStart, braceEnd + 1);
  }

  return text.trim();
}

/** Parse raw LLM text into a TriageResult. */
export function parseTriageResponse(
  text: string,
  fingerprint: string,
): TriageResult {
  try {
    const jsonStr = extractJson(text);
    const parsed = JSON.parse(jsonStr);

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
