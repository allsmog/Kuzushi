import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { cleanupBatchFiles, writeBatchFile } from "./agent-runtime/batch-files.js";
import {
  type AgentRuntimeOptions,
  extractJson,
  resolveDefaultReadOnlyTools,
  resolveRepoContextAndRuntimeOptions,
  runStructuredAgentQuery,
  runStructuredSessionQuery,
} from "./agent-runtime/execution.js";
import { formatRepoContext } from "./repo-context.js";
import type { AllowedTriageTool, Finding } from "./scanners/types.js";
import { formatZodErrors, RawPocHarnessOutputSchema } from "./schemas.js";
import type { PocHarnessResult, RepoContext, TriageResult, VerificationResult } from "./types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "./utils.js";

export function pocHarnessSystemPromptPrefix(repoContext?: RepoContext): string {
  const repoSection = formatRepoContext(repoContext);
  const repoBlock =
    repoSection.length > 0 ? `## Repository Context\n${repoSection.join("\n")}\n\n` : "";
  return (
    repoBlock +
    [
      "## Harness strategy templates (pick the best matching CWE)",
      "- SQL injection (CWE-89): call real query builder/data-access function and assert injected SQL fragment reaches DB adapter mock capture.",
      "- Command injection (CWE-78): call real command-construction path and assert mocked exec/spawn receives attacker-controlled command.",
      "- Path traversal (CWE-22): call real file/path handler and assert normalized path escapes intended base directory in captured filesystem access.",
      "- XSS (CWE-79): call real render/template function and assert unescaped payload appears in output.",
      "- Race condition (CWE-362): invoke the real concurrent code path with parallel requests and assert shared state corruption or TOCTOU violation is observable.",
      "- Weak crypto (CWE-327/328/330): call the real crypto initialization or usage path and assert weak algorithm or insufficient entropy is used.",
      "- Missing auth/authz (CWE-862/863): call the real endpoint handler with unauthenticated or unauthorized context and assert access is not denied.",
      "- For other CWEs: identify the vulnerable function, call it with crafted inputs, and assert the vulnerability is observable.",
      "",
      "## Anti-hallucination constraints",
      "- Do NOT simulate the vulnerable function.",
      "- Import the REAL function from the repository.",
      "- If the function cannot be isolated with simple mocks, set skipped=true and explain why.",
      "- Do not invent files, exports, or APIs.",
    ].join("\n")
  );
}

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

export const DEFAULT_MAX_TURNS = 20;

export interface PocHarnessRuntimeOptions extends AgentRuntimeOptions {}

export interface PocHarnessOutput {
  result: PocHarnessResult;
  costUsd: number;
}

export function resolveDefaultPocHarnessTools(
  runtime: AgentRuntimeOptions["runtime"] | undefined,
): AllowedTriageTool[] {
  return normalizeAllowedTriageToolNames(resolveDefaultReadOnlyTools(runtime));
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
  repoContextOrRuntimeOptions?: RepoContext | PocHarnessRuntimeOptions,
  maybeRuntimeOptions: PocHarnessRuntimeOptions = {},
): Promise<PocHarnessOutput> {
  const { repoContext, runtimeOptions } = resolveRepoContextAndRuntimeOptions(
    repoContextOrRuntimeOptions,
    maybeRuntimeOptions,
  );

  const prompt = buildPocHarnessPrompt(finding, triageResult, verificationResult, repoName);

  // ── Session-based path: reuse subprocess if runtime supports sessions ──
  const runtime = runtimeOptions.runtime;
  const canUseSession = runtime?.createSession != null;

  let resultText: string;
  let structuredOutput: unknown;
  let executionError: string | null;
  let costUsd: number;

  if (canUseSession) {
    const runId = randomUUID();
    const session = runtime.createSession!({
      cwd: repoRoot,
      model,
      allowedTools: resolveDefaultPocHarnessTools(runtime),
      permissionMode: "dontAsk",
      systemPromptPrefix: pocHarnessSystemPromptPrefix(repoContext),
      outputFormat: {
        type: "json_schema",
        schema: POC_HARNESS_RESULT_SCHEMA,
      },
    });

    try {
      const batchFile = writeBatchFile(repoRoot, runId, "poc-harness", 0, {
        fingerprint: finding.fingerprint,
        finding: {
          taskId: finding.taskId,
          ruleId: finding.ruleId,
          filePath: finding.filePath,
          startLine: finding.startLine,
          severity: finding.severity,
          cwe: finding.cwe,
          message: finding.message,
        },
        triage: {
          verdict: triageResult.verdict,
          confidence: triageResult.confidence,
          rationale: triageResult.rationale,
        },
        verification: {
          exploitable: verificationResult.exploitable,
          pocPayload: verificationResult.pocPayload,
          attackVector: verificationResult.attackVector,
        },
      });

      const sessionPrompt = [
        prompt,
        "",
        `Finding context has been written to ${batchFile} — use Read to load it if needed.`,
      ].join("\n");

      const sessionResult = await runStructuredSessionQuery(session, sessionPrompt);
      resultText = sessionResult.resultText;
      structuredOutput = sessionResult.structuredOutput;
      executionError = sessionResult.executionError;
      costUsd = sessionResult.costUsd;
    } finally {
      await session.close();
      cleanupBatchFiles(repoRoot, runId);
    }
  } else {
    // ── Fallback: original subprocess-per-call path ──
    const queryResult = await runStructuredAgentQuery({
      prompt,
      cwd: repoRoot,
      model,
      allowedTools: resolveDefaultPocHarnessTools(runtimeOptions.runtime),
      runtimeOptions,
      systemPromptPrefix: pocHarnessSystemPromptPrefix(repoContext),
      schema: POC_HARNESS_RESULT_SCHEMA,
    });
    resultText = queryResult.resultText;
    structuredOutput = queryResult.structuredOutput;
    executionError = queryResult.executionError;
    costUsd = queryResult.costUsd;
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
): string {
  const cweList = finding.cwe.join(", ") || "none";

  return [
    "You are a security PoC harness generator.",
    "Generate a runnable exploit harness that imports and executes REAL repository code.",
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
    `Scanner: ${finding.taskId}`,
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
    const validation = RawPocHarnessOutputSchema.safeParse(raw);
    if (!validation.success) {
      const errors = formatZodErrors(validation.error.issues);
      console.warn(
        `[poc-harness] LLM output for ${fingerprint} has schema issues: ${errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
      );
    }

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
      applies:
        extension === ".js" ||
        extension === ".mjs" ||
        extension === ".cjs" ||
        normalizedLanguage === "javascript" ||
        normalizedLanguage === "node",
    },
    {
      cmd: "npx",
      args: ["tsc", "--noEmit", "--skipLibCheck", scriptPath],
      applies: extension === ".ts" || extension === ".tsx" || normalizedLanguage === "typescript",
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
      applies:
        extension === ".sh" || normalizedLanguage === "shell" || normalizedLanguage === "bash",
    },
    {
      cmd: "go",
      args: ["build", "-o", os.devNull, scriptPath],
      applies: extension === ".go" || normalizedLanguage === "go",
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

function parsePocHarnessObject(
  raw: Record<string, unknown>,
  fingerprint: string,
): PocHarnessResult {
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

function buildHarnessFileName(fingerprint: string, cwes: string[], extension: string): string {
  const prefix = fingerprint.slice(0, 16).toLowerCase();
  const cwe = firstCwe(cwes);
  return `${prefix}-${cwe}.${extension}`;
}

function firstCwe(cwes: string[]): string {
  for (const cwe of cwes) {
    const normalized = cwe
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "");
    if (normalized.length > 0) {
      return normalized;
    }
  }

  return "cwe";
}

export function resolveScriptExtension(language: string | null): string {
  const normalized = normalizeLanguage(language);
  if (normalized === "python" || normalized === "py") {
    return "py";
  }
  if (normalized === "go") {
    return "go";
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

function normalizeNullableString(value: unknown): string | null {
  if (value == null) return null;
  if (typeof value !== "string") return null;
  return value;
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

function normalizeAllowedTriageToolNames(tools: readonly string[]): AllowedTriageTool[] {
  return tools.filter(
    (tool): tool is AllowedTriageTool =>
      tool === "Read" ||
      tool === "Glob" ||
      tool === "Grep" ||
      tool === "GetCallers" ||
      tool === "GetCallees" ||
      tool === "GetFunctionBody" ||
      tool === "GoToDefinition" ||
      tool === "FindReferences" ||
      tool === "TypeAtPosition",
  );
}
