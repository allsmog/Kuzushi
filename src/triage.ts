import { getAgentRuntime, type AgentRuntime } from "./agent-runtime/index.js";
import type {
  AllowedTriageTool,
  Finding,
  TriageAgentConfig,
} from "./scanners/types.js";
import type { RepoContext, TriageResult, Verdict } from "./types.js";

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

    executionError = message.errors.join("; ") || message.subtype;
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

export function parseAgentOutput(raw: unknown, fingerprint: string): TriageResult {
  if (isRecord(raw)) {
    return {
      fingerprint: asString(raw["fingerprint"], fingerprint),
      verdict: parseVerdict(asString(raw["verdict"], "needs_review")),
      confidence: clampConfidence(raw["confidence"]),
      rationale: asString(raw["rationale"], ""),
      verificationSteps: normalizeVerificationSteps(raw["verification_steps"]),
      fixPatch: normalizeFixPatch(raw["fix_patch"]),
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

function normalizeCostUsd(value: number): number {
  if (!Number.isFinite(value) || value < 0) {
    return 0;
  }

  return value;
}

/** Parse a verdict string, defaulting to needs_review for unknown values. */
export function parseVerdict(v: string): Verdict {
  if (v === "tp" || v === "fp" || v === "needs_review") return v;
  return "needs_review";
}

/** Extract JSON from LLM response, handling markdown fences and preamble. */
export function extractJson(text: string): string {
  const fenceMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}
