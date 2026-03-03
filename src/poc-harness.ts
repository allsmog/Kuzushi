import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { getAgentRuntime, type AgentRuntime } from "./agent-runtime/index.js";
import type { AllowedTriageTool, Finding } from "./scanners/types.js";
import type {
  PocHarnessResult,
  RepoContext,
  TriageResult,
  VerificationResult,
} from "./types.js";
import type { AgentActivityCallback } from "./triage.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "./utils.js";

export const POC_HARNESS_RESULT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["fingerprint", "script_content", "language", "skipped", "skip_reason"],
  properties: {
    fingerprint: { type: "string" },
    script_content: { type: ["string", "null"] },
    language: { type: ["string", "null"] },
    skipped: { type: "boolean" },
    skip_reason: { type: ["string", "null"] },
  },
} as const;

export const DEFAULT_TOOLS: AllowedTriageTool[] = ["Read", "Glob", "Grep"];
export const DEFAULT_MAX_TURNS = 20;

export interface PocHarnessRuntimeOptions {
  runtime?: AgentRuntime;
  abortController?: AbortController;
  maxBudgetUsd?: number;
  activityCallback?: AgentActivityCallback;
}

export interface PocHarnessOutput {
  result: PocHarnessResult;
  costUsd: number;
}

export class PocHarnessExecutionError extends Error {
  readonly costUsd: number;

  constructor(message: string, costUsd = 0) {
    super(message);
    this.name = "PocHarnessExecutionError";
    this.costUsd = normalizeCostUsd(costUsd);
  }
}

export async function generatePocHarness(
  finding: Finding,
  triageResult: TriageResult,
  verificationResult: VerificationResult,
  repoRoot: string,
  repoName: string,
  model: string,
  maxTurns: number,
  repoContextOrRuntimeOptions?: RepoContext | PocHarnessRuntimeOptions,
  maybeRuntimeOptions: PocHarnessRuntimeOptions = {},
): Promise<PocHarnessOutput> {
  const { repoContext, runtimeOptions } = resolvePocHarnessArgs(
    repoContextOrRuntimeOptions,
    maybeRuntimeOptions,
  );
  const runtime = runtimeOptions.runtime ?? getAgentRuntime();
  const prompt = buildPocHarnessPrompt(
    finding,
    triageResult,
    verificationResult,
    repoName,
    repoContext,
  );
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
        schema: POC_HARNESS_RESULT_SCHEMA,
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
    throw new PocHarnessExecutionError(`poc harness agent failed: ${executionError}`, costUsd);
  }

  let parsedResult: PocHarnessResult;
  try {
    parsedResult = parsePocHarnessOutput(structuredOutput ?? resultText, finding.fingerprint);
  } catch (error) {
    throw new PocHarnessExecutionError(
      `poc harness output parse failed: ${toErrorMessage(error)}`,
      costUsd,
    );
  }

  parsedResult.costUsd = costUsd;

  if (parsedResult.skipped) {
    parsedResult.scriptPath = null;
    parsedResult.language = parsedResult.language ?? null;
    parsedResult.scriptContent = null;
    parsedResult.parsed = false;
    parsedResult.parseError = null;

    if (!parsedResult.skipReason || parsedResult.skipReason.trim().length === 0) {
      parsedResult.skipReason = "Agent skipped PoC harness generation without a reason.";
    }

    return {
      result: parsedResult,
      costUsd,
    };
  }

  if (!parsedResult.scriptContent || parsedResult.scriptContent.trim().length === 0) {
    throw new PocHarnessExecutionError(
      "poc harness output parse failed: script_content is required when skipped=false",
      costUsd,
    );
  }

  const outputDir = path.join(repoRoot, ".kuzushi", "poc");
  mkdirSync(outputDir, { recursive: true });

  const fileExt = resolveScriptExtension(parsedResult.language);
  const fileName = buildHarnessFileName(finding.fingerprint, finding.cwe, fileExt);
  const scriptPath = path.join(outputDir, fileName);
  writeFileSync(scriptPath, parsedResult.scriptContent, "utf-8");

  const syntaxValidation = validateScriptSyntax(scriptPath, parsedResult.language);
  parsedResult.scriptPath = scriptPath;
  parsedResult.parsed = syntaxValidation.parsed;
  parsedResult.parseError = syntaxValidation.parseError;

  return {
    result: parsedResult,
    costUsd,
  };
}

export function buildPocHarnessPrompt(
  finding: Finding,
  triageResult: TriageResult,
  verificationResult: VerificationResult,
  repoName: string,
  repoContext?: RepoContext,
): string {
  const contextSection = formatRepoContext(repoContext);
  const cweList = finding.cwe.join(", ") || "none";

  return [
    "You are a security PoC harness generator.",
    "Generate a runnable exploit harness that imports and executes REAL repository code.",
    ...(contextSection.length > 0 ? ["", "## Repository Context", ...contextSection] : []),
    "",
    "## Mandatory code-reading gate",
    ...(finding.filePath !== "."
      ? [
          `BEFORE generating code, use Read on ${finding.filePath}:${finding.startLine} with at least 50 lines of context.`,
          "Verify the vulnerable function signature and import path exist in the repository.",
        ]
      : [
          "This finding is an architectural/threat-model finding without a specific file. Use Glob and Grep to identify the most relevant source files before generating code.",
        ]),
    "",
    "## Finding",
    `Repo: ${repoName}`,
    `Scanner: ${finding.scanner}`,
    `Rule: ${finding.ruleId}`,
    `File: ${finding.filePath}:${finding.startLine}`,
    `Severity: ${finding.severity}`,
    `CWE: ${cweList}`,
    `Message: ${finding.message}`,
    `Fingerprint: ${finding.fingerprint}`,
    "",
    "## Triage context",
    `Verdict: ${triageResult.verdict}`,
    `Confidence: ${triageResult.confidence}`,
    `Rationale: ${triageResult.rationale}`,
    `Verification steps: ${triageResult.verificationSteps.join(" | ") || "none"}`,
    "",
    "## Static verification context",
    `Exploitable: ${verificationResult.exploitable}`,
    `PoC payload: ${verificationResult.pocPayload ?? "none"}`,
    `PoC description: ${verificationResult.pocDescription}`,
    `Attack vector: ${verificationResult.attackVector ?? "unknown"}`,
    `Preconditions: ${verificationResult.preconditions.join(" | ") || "none"}`,
    "",
    "## Harness strategy templates (pick the best matching CWE)",
    "- SQL injection (CWE-89): call real query builder/data-access function and assert injected SQL fragment reaches DB adapter mock capture.",
    "- Command injection (CWE-78): call real command-construction path and assert mocked exec/spawn receives attacker-controlled command.",
    "- Path traversal (CWE-22): call real file/path handler and assert normalized path escapes intended base directory in captured filesystem access.",
    "- XSS (CWE-79): call real render/template function and assert unescaped payload appears in output.",
    "",
    "## Anti-hallucination constraints",
    "- Do NOT simulate the vulnerable function.",
    "- Import the REAL function from the repository.",
    "- If the function cannot be isolated with simple mocks, set skipped=true and explain why.",
    "- Do not invent files, exports, or APIs.",
    "",
    "## Script requirements",
    "- Include a header comment with CWE and run instructions.",
    "- Print PASS or FAIL.",
    "- Exit with code 0 on PASS and 1 on FAIL.",
    "",
    "## Output requirements",
    "Return ONLY a JSON object with keys:",
    "fingerprint, script_content(string|null), language(string|null), skipped(boolean), skip_reason(string|null)",
  ].join("\n");
}

export function parsePocHarnessOutput(raw: unknown, fingerprint: string): PocHarnessResult {
  if (isRecord(raw)) {
    return parsePocHarnessObject(raw, fingerprint);
  }

  if (typeof raw === "string") {
    return parsePocHarnessResponse(raw, fingerprint);
  }

  return parsePocHarnessResponse(String(raw ?? ""), fingerprint);
}

export function validateScriptSyntax(
  scriptPath: string,
  language: string | null,
): { parsed: boolean; parseError: string | null } {
  const normalizedLanguage = normalizeLanguage(language);
  const extension = path.extname(scriptPath).toLowerCase();

  const validators: Array<{ cmd: string; args: string[]; applies: boolean }> = [
    {
      cmd: "node",
      args: ["--check", scriptPath],
      applies: extension === ".js" || extension === ".mjs" || extension === ".cjs"
        || normalizedLanguage === "javascript"
        || normalizedLanguage === "node",
    },
    {
      cmd: "npx",
      args: ["tsc", "--noEmit", "--skipLibCheck", scriptPath],
      applies: extension === ".ts" || extension === ".tsx"
        || normalizedLanguage === "typescript",
    },
    {
      cmd: "python3",
      args: [
        "-c",
        "import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())",
        scriptPath,
      ],
      applies: extension === ".py" || normalizedLanguage === "python",
    },
    {
      cmd: "sh",
      args: ["-n", scriptPath],
      applies: extension === ".sh" || normalizedLanguage === "shell" || normalizedLanguage === "bash",
    },
  ];

  const validator = validators.find((candidate) => candidate.applies);
  if (!validator) {
    return {
      parsed: false,
      parseError: `No syntax validator configured for language "${language ?? "unknown"}".`,
    };
  }

  try {
    execFileSync(validator.cmd, validator.args, { stdio: "pipe" });
    return {
      parsed: true,
      parseError: null,
    };
  } catch (error) {
    return {
      parsed: false,
      parseError: toErrorMessage(error),
    };
  }
}

function parsePocHarnessObject(raw: Record<string, unknown>, fingerprint: string): PocHarnessResult {
  const skipped = asBoolean(raw["skipped"], false);
  const scriptContent = normalizeNullableString(raw["script_content"]);

  if (!skipped && (!scriptContent || scriptContent.trim().length === 0)) {
    throw new Error("script_content is required when skipped=false");
  }

  return {
    fingerprint: asString(raw["fingerprint"], fingerprint),
    scriptPath: null,
    language: normalizeLanguage(raw["language"]),
    scriptContent,
    parsed: false,
    parseError: null,
    skipped,
    skipReason: normalizeNullableString(raw["skip_reason"]),
  };
}

function parsePocHarnessResponse(text: string, fingerprint: string): PocHarnessResult {
  try {
    const jsonStr = extractJson(text);
    const parsed = JSON.parse(jsonStr);
    if (!isRecord(parsed)) {
      throw new Error("PoC harness JSON response is not an object");
    }

    return parsePocHarnessObject(parsed, fingerprint);
  } catch (error) {
    throw new Error(`Invalid PoC harness JSON response: ${toErrorMessage(error)}`);
  }
}

function normalizeTurns(value: number): number {
  if (!Number.isFinite(value) || value < 1) {
    return DEFAULT_MAX_TURNS;
  }

  return Math.floor(value);
}

function resolvePocHarnessArgs(
  repoContextOrRuntimeOptions: RepoContext | PocHarnessRuntimeOptions | undefined,
  maybeRuntimeOptions: PocHarnessRuntimeOptions,
): { repoContext?: RepoContext; runtimeOptions: PocHarnessRuntimeOptions } {
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
  value: RepoContext | PocHarnessRuntimeOptions,
): value is PocHarnessRuntimeOptions {
  const runtimeOptions = value as PocHarnessRuntimeOptions;
  return (
    "runtime" in runtimeOptions
    || "abortController" in runtimeOptions
    || "maxBudgetUsd" in runtimeOptions
    || "activityCallback" in runtimeOptions
  );
}

function buildHarnessFileName(fingerprint: string, cwes: string[], extension: string): string {
  const prefix = fingerprint.slice(0, 16).toLowerCase();
  const cwe = firstCwe(cwes);
  return `${prefix}-${cwe}.${extension}`;
}

function firstCwe(cwes: string[]): string {
  for (const cwe of cwes) {
    const normalized = cwe.trim().toLowerCase().replace(/[^a-z0-9]+/g, "");
    if (normalized.length > 0) {
      return normalized;
    }
  }

  return "cwe";
}

function resolveScriptExtension(language: string | null): string {
  const normalized = normalizeLanguage(language);
  if (normalized === "python" || normalized === "py") {
    return "py";
  }
  if (normalized === "javascript" || normalized === "node" || normalized === "js") {
    return "mjs";
  }
  if (normalized === "shell" || normalized === "bash" || normalized === "sh") {
    return "sh";
  }
  return "ts";
}

function normalizeLanguage(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.trim().toLowerCase();
  return normalized.length > 0 ? normalized : null;
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

function normalizeNullableString(value: unknown): string | null {
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

function asBoolean(value: unknown, fallback: boolean): boolean {
  if (typeof value !== "boolean") {
    return fallback;
  }

  return value;
}
