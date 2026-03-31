import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  extractJson,
  runStructuredAgentQuery,
  type AgentRuntimeOptions,
} from "../agent-runtime/execution.js";
import type { Finding } from "../scanners/types.js";
import {
  resolveDefaultPocHarnessTools,
  resolveScriptExtension,
  validateScriptSyntax,
} from "../poc-harness.js";
import { normalizeCostUsd, toErrorMessage } from "../utils.js";
import {
  buildCryptoBehavioralSystemPrompt,
  buildPromptForTestType,
  type CryptoBehavioralPromptOptions,
} from "./harness-prompts.js";
import type {
  CryptoBehavioralHarnessOutput,
  CryptoBehavioralHarnessResult,
  CryptoBehavioralTestType,
} from "./types.js";

export const CRYPTO_BEHAVIORAL_HARNESS_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["fingerprint", "test_type", "script_content", "language", "skipped", "skip_reason"],
  properties: {
    fingerprint: { type: "string" },
    test_type: {
      type: "string",
      enum: ["timing", "ecb-mode", "weak-hash", "weak-prng", "key-length", "edge-case"],
    },
    script_content: { type: ["string", "null"] },
    language: { type: ["string", "null"] },
    skipped: { type: "boolean" },
    skip_reason: { type: ["string", "null"] },
  },
} as const;

export interface GenerateCryptoBehavioralHarnessOptions extends AgentRuntimeOptions, CryptoBehavioralPromptOptions {}

export class CryptoBehavioralHarnessExecutionError extends Error {
  readonly costUsd: number;

  constructor(message: string, costUsd = 0) {
    super(message);
    this.name = "CryptoBehavioralHarnessExecutionError";
    this.costUsd = normalizeCostUsd(costUsd);
  }
}

export async function generateCryptoBehavioralHarness(
  finding: Finding,
  testType: CryptoBehavioralTestType,
  repoRoot: string,
  _repoName: string,
  model: string,
  options: GenerateCryptoBehavioralHarnessOptions = {},
): Promise<CryptoBehavioralHarnessOutput> {
  const prompt = buildPromptForTestType(testType, finding, repoRoot, {
    repoContext: options.repoContext,
    timingIterations: options.timingIterations,
  });

  const { resultText, structuredOutput, executionError, costUsd } = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    allowedTools: resolveDefaultPocHarnessTools(options.runtime),
    runtimeOptions: options,
    systemPromptPrefix: buildCryptoBehavioralSystemPrompt(options.repoContext),
    schema: CRYPTO_BEHAVIORAL_HARNESS_SCHEMA,
  });

  if (executionError) {
    throw new CryptoBehavioralHarnessExecutionError(
      `crypto behavioral harness agent failed: ${executionError}`,
      costUsd,
    );
  }

  let parsedResult: CryptoBehavioralHarnessResult;
  try {
    parsedResult = parseCryptoBehavioralHarnessOutput(
      structuredOutput ?? resultText,
      finding.fingerprint,
      testType,
    );
  } catch (error) {
    throw new CryptoBehavioralHarnessExecutionError(
      `crypto behavioral harness output parse failed: ${toErrorMessage(error)}`,
      costUsd,
    );
  }

  parsedResult.costUsd = costUsd;

  if (parsedResult.skipped) {
    parsedResult.scriptPath = null;
    parsedResult.scriptContent = null;
    parsedResult.language = parsedResult.language ?? null;
    parsedResult.parsed = false;
    parsedResult.parseError = null;
    if (!parsedResult.skipReason || parsedResult.skipReason.trim().length === 0) {
      parsedResult.skipReason = "Agent skipped crypto behavioral harness generation without a reason.";
    }

    return {
      result: parsedResult,
      costUsd,
    };
  }

  if (!parsedResult.scriptContent || parsedResult.scriptContent.trim().length === 0) {
    throw new CryptoBehavioralHarnessExecutionError(
      "crypto behavioral harness output parse failed: script_content is required when skipped=false",
      costUsd,
    );
  }

  const outputDir = path.join(repoRoot, ".kuzushi", "crypto-behavioral");
  mkdirSync(outputDir, { recursive: true });

  const extension = resolveScriptExtension(parsedResult.language);
  const scriptPath = path.join(outputDir, `${finding.fingerprint}-${testType}.${extension}`);
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

function parseCryptoBehavioralHarnessOutput(
  raw: unknown,
  fingerprint: string,
  testType: CryptoBehavioralTestType,
): CryptoBehavioralHarnessResult {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    return parseCryptoBehavioralHarnessObject(raw as Record<string, unknown>, fingerprint, testType);
  }

  if (typeof raw === "string") {
    const json = extractJson(raw);
    return parseCryptoBehavioralHarnessObject(JSON.parse(json) as Record<string, unknown>, fingerprint, testType);
  }

  return parseCryptoBehavioralHarnessObject({}, fingerprint, testType);
}

function parseCryptoBehavioralHarnessObject(
  raw: Record<string, unknown>,
  fingerprint: string,
  testType: CryptoBehavioralTestType,
): CryptoBehavioralHarnessResult {
  const skipped = raw["skipped"] === true;
  const scriptContent = normalizeNullableString(raw["script_content"]);

  if (!skipped && (!scriptContent || scriptContent.trim().length === 0)) {
    throw new Error("script_content is required when skipped=false");
  }

  return {
    fingerprint: asString(raw["fingerprint"], fingerprint),
    testType: asTestType(raw["test_type"], testType),
    scriptPath: null,
    language: normalizeLanguage(raw["language"]),
    scriptContent,
    parsed: false,
    parseError: null,
    skipped,
    skipReason: normalizeNullableString(raw["skip_reason"]),
  };
}

function normalizeLanguage(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const normalized = value.trim().toLowerCase();
  return normalized.length > 0 ? normalized : null;
}

function normalizeNullableString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function asString(value: unknown, fallback: string): string {
  return typeof value === "string" ? value : fallback;
}

function asTestType(
  value: unknown,
  fallback: CryptoBehavioralTestType,
): CryptoBehavioralTestType {
  switch (value) {
    case "timing":
    case "ecb-mode":
    case "weak-hash":
    case "weak-prng":
    case "key-length":
    case "edge-case":
      return value;
    default:
      return fallback;
  }
}
