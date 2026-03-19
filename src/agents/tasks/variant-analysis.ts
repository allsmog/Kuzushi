import { createHash } from "node:crypto";
import path from "node:path";
import { getAgentRuntime } from "../../agent-runtime/index.js";
import { scoreFindingMetadata } from "../../scanners/scoring.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { RepoContext, TriageResult } from "../../types.js";
import { createLogger } from "../../logger.js";
import { isRecord, toErrorMessage } from "../../utils.js";

const log = createLogger({ stage: "variant-analysis" });

const VARIANT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["variants"],
  properties: {
    variants: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["filePath", "startLine", "severity", "message", "confidence", "rationale"],
        properties: {
          filePath: { type: "string" },
          startLine: { type: "integer", minimum: 1 },
          severity: { type: "string", enum: ["ERROR", "WARNING", "INFO"] },
          message: { type: "string" },
          confidence: { type: "string", enum: ["HIGH", "MEDIUM", "LOW"] },
          rationale: { type: "string" },
          cwe: { type: "array", items: { type: "string" } },
        },
      },
    },
  },
} as const;

interface VariantFinding {
  filePath: string;
  startLine: number;
  severity: string;
  message: string;
  confidence: string;
  rationale: string;
  cwe?: string[];
}

export interface VariantAnalysisConfig {
  model: string;
  maxFindings: number;
}

export interface VariantAnalysisInput {
  confirmedFindings: Array<{ finding: Finding; triageResult: TriageResult }>;
  repoRoot: string;
  repoName: string;
  repoContext?: RepoContext;
}

export interface VariantAnalysisOutput {
  findings: Finding[];
  costUsd: number;
}

function buildPrompt(original: Finding, triageResult: TriageResult): string {
  return [
    "You are a senior security researcher performing variant analysis.",
    "A confirmed vulnerability has been found. Your job is to search the codebase for OTHER locations",
    "with the same vulnerability pattern.",
    "",
    "## Confirmed vulnerability",
    `Scanner: ${original.scanner}`,
    `Rule: ${original.ruleId}`,
    `File: ${original.filePath}:${original.startLine}`,
    `Severity: ${original.severity}`,
    `Message: ${original.message}`,
    `CWE: ${original.cwe.join(", ") || "none"}`,
    `Evidence: ${original.evidence || "none"}`,
    "",
    "## Triage assessment",
    `Verdict: ${triageResult.verdict}`,
    `Rationale: ${triageResult.rationale}`,
    "",
    "## Variant analysis methodology",
    "1. Read the confirmed vulnerable code to extract the vulnerability pattern:",
    "   - What is the source? (user input, request param, file, etc.)",
    "   - What is the sink? (dangerous API, query, command, etc.)",
    "   - What guard/sanitization is missing?",
    "2. Use Grep to search for the same sink pattern across the entire codebase.",
    "3. For each candidate location, Read the code and verify:",
    "   - Same type of sink is present",
    "   - Input reaches the sink without the required guard",
    "   - The location is DIFFERENT from the original finding",
    "4. Only report variants you can verify in code. Do NOT speculate.",
    "",
    "## Anti-hallucination constraints",
    "- Skip the original file:line — only report NEW locations.",
    "- Each variant must have a different filePath or startLine from the original.",
    "- Confidence must be HIGH or MEDIUM — do not report LOW confidence variants.",
    "- If you find no variants, return an empty array.",
  ].join("\n");
}

function normalizeVariants(
  raw: unknown,
  repoRoot: string,
  repoName: string,
  original: Finding,
  maxFindings: number,
): Finding[] {
  if (!isRecord(raw) || !Array.isArray(raw["variants"])) return [];

  const deduped = new Map<string, Finding>();
  for (const item of raw["variants"] as unknown[]) {
    if (!isRecord(item)) continue;
    const v = item as unknown as VariantFinding;
    if (!v.filePath?.trim()) continue;

    const filePath = normalizeFilePath(repoRoot, v.filePath);

    // Skip if same location as original
    if (filePath === original.filePath && v.startLine === original.startLine) continue;

    // Skip LOW confidence
    if (v.confidence === "LOW") continue;

    const cweList = v.cwe ?? original.cwe;
    const fingerprint = computeFingerprint(repoName, filePath, v, original.ruleId);

    const finding: Finding = {
      scanner: "variant-analysis",
      fingerprint,
      ruleId: `variant/${original.ruleId}`,
      filePath,
      startLine: Math.max(1, Math.floor(Number(v.startLine) || 1)),
      severity: v.severity || original.severity,
      message: v.message || `Variant of ${original.ruleId}: ${original.message}`,
      evidence: v.rationale || null,
      scannerConfidence: v.confidence || "MEDIUM",
      subcategory: ["vuln"],
      likelihood: v.confidence || "MEDIUM",
      impact: v.severity === "ERROR" ? "HIGH" : v.severity === "INFO" ? "LOW" : "MEDIUM",
      cwe: cweList,
      score: scoreFindingMetadata({
        severity: v.severity || original.severity,
        likelihood: v.confidence || "MEDIUM",
        impact: v.severity === "ERROR" ? "HIGH" : v.severity === "INFO" ? "LOW" : "MEDIUM",
        subcategory: ["vuln"],
      }),
    };

    const existing = deduped.get(fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(fingerprint, finding);
    }
  }

  return [...deduped.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, maxFindings);
}

function computeFingerprint(
  repoName: string,
  filePath: string,
  v: VariantFinding,
  originalRuleId: string,
): string {
  const source = [repoName, "variant-analysis", originalRuleId, filePath, String(v.startLine)].join("|");
  return createHash("sha256").update(source).digest("hex");
}

function normalizeFilePath(repoRoot: string, filePath: string): string {
  if (!path.isAbsolute(filePath)) return filePath;
  const relative = path.relative(repoRoot, filePath);
  if (relative.startsWith("..")) return filePath;
  return relative || filePath;
}

/**
 * Run variant analysis for a single confirmed TP finding.
 */
export async function analyzeVariants(
  finding: Finding,
  triageResult: TriageResult,
  repoRoot: string,
  repoName: string,
  model: string,
  maxFindings: number,
): Promise<VariantAnalysisOutput> {
  const prompt = buildPrompt(finding, triageResult);
  const runtime = getAgentRuntime();

  let structuredOutput: unknown;
  let resultText = "";
  let costUsd = 0;

  const tag = "[variant-analysis]";
  log.info(`Searching for variants of ${finding.ruleId} in ${finding.filePath}:${finding.startLine}`);

  try {
    for await (const message of runtime.query({
      prompt,
      options: {
        cwd: repoRoot,
        model,
        maxTurns: 15,
        allowedTools: ["Read", "Glob", "Grep"],
        permissionMode: "dontAsk",
        outputFormat: {
          type: "json_schema",
          schema: VARIANT_SCHEMA,
          strict: true,
          retryInvalidStructuredOutput: 2,
        },
      },
    })) {
      if (message.type !== "result") continue;
      if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
        costUsd = message.totalCostUsd;
      }
      if ("result" in message) {
        resultText = message.result;
        structuredOutput = message.structuredOutput;
      }
    }
  } catch (error) {
    throw new Error(`${tag} Agent error: ${toErrorMessage(error)}`);
  }

  const findings = normalizeVariants(
    structuredOutput ?? parseJson(resultText, tag),
    repoRoot,
    repoName,
    finding,
    maxFindings,
  );

  return {
    findings: attachTaskOutputMeta(findings, { costUsd }),
    costUsd,
  };
}

export function buildVariantTriageConfig(finding: Finding, repoName: string): TriageAgentConfig {
  return {
    prompt: [
      `You are triaging a variant analysis finding in "${repoName}".`,
      `This is a potential variant of a confirmed vulnerability.`,
      "",
      `Rule: ${finding.ruleId}`,
      `File: ${finding.filePath}:${finding.startLine}`,
      `Message: ${finding.message}`,
      finding.evidence ? `Rationale: ${finding.evidence}` : "",
      "",
      "Verify that this variant follows the same vulnerability pattern as the original.",
      "Check if the same missing guard/sanitization applies at this location.",
    ].filter(Boolean).join("\n"),
  };
}

const BATCH_VARIANT_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["results"],
  properties: {
    results: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["originalFingerprint", "variants"],
        properties: {
          originalFingerprint: { type: "string" },
          variants: VARIANT_SCHEMA.properties.variants,
        },
      },
    },
  },
} as const;

function buildBatchPrompt(
  items: Array<{ finding: Finding; triageResult: TriageResult }>,
): string {
  const findingDescriptions = items.map((item, idx) => [
    `### Finding ${idx + 1} (fingerprint: ${item.finding.fingerprint})`,
    `Scanner: ${item.finding.scanner}`,
    `Rule: ${item.finding.ruleId}`,
    `File: ${item.finding.filePath}:${item.finding.startLine}`,
    `Severity: ${item.finding.severity}`,
    `Message: ${item.finding.message}`,
    `CWE: ${item.finding.cwe.join(", ") || "none"}`,
    `Evidence: ${item.finding.evidence || "none"}`,
    `Triage verdict: ${item.triageResult.verdict}`,
    `Triage rationale: ${item.triageResult.rationale}`,
  ].join("\n")).join("\n\n");

  return [
    "You are a senior security researcher performing variant analysis.",
    `${items.length} confirmed vulnerabilities have been found. Your job is to search the codebase for OTHER locations`,
    "with the same vulnerability patterns.",
    "",
    "## Confirmed vulnerabilities",
    findingDescriptions,
    "",
    "## Variant analysis methodology",
    "For EACH confirmed vulnerability above:",
    "1. Read the confirmed vulnerable code to extract the vulnerability pattern:",
    "   - What is the source? (user input, request param, file, etc.)",
    "   - What is the sink? (dangerous API, query, command, etc.)",
    "   - What guard/sanitization is missing?",
    "2. Use Grep to search for the same sink pattern across the entire codebase.",
    "3. For each candidate location, Read the code and verify:",
    "   - Same type of sink is present",
    "   - Input reaches the sink without the required guard",
    "   - The location is DIFFERENT from the original finding",
    "4. Only report variants you can verify in code. Do NOT speculate.",
    "",
    "## Anti-hallucination constraints",
    "- Skip the original file:line for each finding — only report NEW locations.",
    "- Each variant must have a different filePath or startLine from its original.",
    "- Confidence must be HIGH or MEDIUM — do not report LOW confidence variants.",
    "- If you find no variants for a finding, return an empty variants array for it.",
    "- Tag each result with the originalFingerprint so we can map variants back.",
  ].join("\n");
}

/**
 * Run variant analysis for multiple confirmed TP findings in a single LLM call.
 */
export async function analyzeVariantsBatch(
  items: Array<{ finding: Finding; triageResult: TriageResult }>,
  repoRoot: string,
  repoName: string,
  model: string,
  maxFindingsPerVariant: number,
): Promise<VariantAnalysisOutput> {
  const prompt = buildBatchPrompt(items);
  const runtime = getAgentRuntime();

  let structuredOutput: unknown;
  let resultText = "";
  let costUsd = 0;

  const tag = "[variant-analysis-batch]";
  log.info(`Batch analyzing ${items.length} findings for variants`);

  try {
    for await (const message of runtime.query({
      prompt,
      options: {
        cwd: repoRoot,
        model,
        maxTurns: 15,
        allowedTools: ["Read", "Glob", "Grep"],
        permissionMode: "dontAsk",
        outputFormat: {
          type: "json_schema",
          schema: BATCH_VARIANT_SCHEMA,
          strict: true,
          retryInvalidStructuredOutput: 2,
        },
      },
    })) {
      if (message.type !== "result") continue;
      if (typeof message.totalCostUsd === "number" && Number.isFinite(message.totalCostUsd)) {
        costUsd = message.totalCostUsd;
      }
      if ("result" in message) {
        resultText = message.result;
        structuredOutput = message.structuredOutput;
      }
    }
  } catch (error) {
    throw new Error(`${tag} Agent error: ${toErrorMessage(error)}`);
  }

  const parsed = structuredOutput ?? parseJson(resultText, tag);
  const allFindings: Finding[] = [];

  if (isRecord(parsed) && Array.isArray(parsed["results"])) {
    const fingerprintToItem = new Map(items.map((item) => [item.finding.fingerprint, item]));

    for (const entry of parsed["results"] as unknown[]) {
      if (!isRecord(entry)) continue;
      const fp = String(entry["originalFingerprint"] ?? "");
      const original = fingerprintToItem.get(fp);
      if (!original) continue;

      const variants = normalizeVariants(
        { variants: entry["variants"] },
        repoRoot,
        repoName,
        original.finding,
        maxFindingsPerVariant,
      );
      allFindings.push(...variants);
    }
  }

  return {
    findings: attachTaskOutputMeta(allFindings, { costUsd }),
    costUsd,
  };
}

function parseJson(text: string, tag: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`${tag} Invalid JSON output: ${toErrorMessage(error)}`);
  }
}

export const __variantAnalysisInternals = {
  buildPrompt,
  normalizeVariants,
  computeFingerprint,
};
