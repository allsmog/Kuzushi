import { readFileSync } from "node:fs";
import path from "node:path";
import { runStructuredAgentQuery } from "../agent-runtime/execution.js";
import type { Finding } from "./types.js";
import { isRecord, toErrorMessage } from "../utils.js";

export interface LlmRescoreResult {
  fingerprint: string;
  score: number;
  reason: string;
  keep: boolean;
}

export interface RescoreOptions {
  model?: string;
  threshold?: number;
  concurrency?: number;
  repoRoot: string;
}

const RESCORE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["score", "reason"],
  properties: {
    score: { type: "integer", minimum: 1, maximum: 10 },
    reason: { type: "string" },
  },
} as const;

/**
 * Re-score findings using a cheap single-turn LLM call per finding.
 * Groups findings by file to amortize file reads.
 * Findings below threshold are marked as not-kept.
 */
export async function rescoreFindings(
  findings: Finding[],
  options: RescoreOptions,
): Promise<LlmRescoreResult[]> {
  if (findings.length === 0) return [];

  const threshold = options.threshold ?? 4;
  const concurrency = Math.max(1, options.concurrency ?? 5);
  const model = options.model ?? "anthropic:claude-haiku-4-5-20251001";

  // Group findings by file to batch file reads
  const byFile = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = finding.filePath;
    const existing = byFile.get(key) ?? [];
    existing.push(finding);
    byFile.set(key, existing);
  }

  // Read file contents once per file
  const fileContents = new Map<string, string>();
  for (const filePath of byFile.keys()) {
    try {
      const fullPath = path.isAbsolute(filePath)
        ? filePath
        : path.join(options.repoRoot, filePath);
      const content = readFileSync(fullPath, "utf-8");
      // Limit to first 500 lines to keep token count manageable
      const lines = content.split("\n");
      fileContents.set(filePath, lines.slice(0, 500).join("\n"));
    } catch {
      fileContents.set(filePath, "[file not readable]");
    }
  }

  const results: LlmRescoreResult[] = [];
  const pending: Array<() => Promise<LlmRescoreResult>> = [];

  for (const finding of findings) {
    const fileContent = fileContents.get(finding.filePath) ?? "[no content]";
    pending.push(() => rescoreSingleFinding(finding, fileContent, model, options.repoRoot, threshold));
  }

  // Execute with concurrency limit
  const executing = new Set<Promise<void>>();
  for (const task of pending) {
    const p = task().then((result) => {
      results.push(result);
    });
    const tracked = p.then(() => { executing.delete(tracked); });
    executing.add(tracked);

    if (executing.size >= concurrency) {
      await Promise.race(executing);
    }
  }
  await Promise.all(executing);

  return results;
}

async function rescoreSingleFinding(
  finding: Finding,
  fileContent: string,
  model: string,
  repoRoot: string,
  threshold: number,
): Promise<LlmRescoreResult> {
  // Extract relevant lines around the finding (±20 lines)
  const lines = fileContent.split("\n");
  const startLine = Math.max(0, finding.startLine - 21);
  const endLine = Math.min(lines.length, finding.startLine + 20);
  const relevantContent = lines.slice(startLine, endLine).join("\n");

  const prompt = [
    "Rate this security finding as a true positive on a scale of 1-10.",
    "1 = almost certainly a false positive, 10 = almost certainly a true positive.",
    "",
    `Rule: ${finding.ruleId}`,
    `File: ${finding.filePath}:${finding.startLine}`,
    `Severity: ${finding.severity}`,
    `CWE: ${finding.cwe.join(", ") || "none"}`,
    `Message: ${finding.message}`,
    `Evidence: ${finding.evidence || "none"}`,
    "",
    "## Relevant code",
    "```",
    relevantContent,
    "```",
    "",
    "Consider:",
    "- Is the vulnerability pattern real or a scanner false positive?",
    "- Is the flagged code actually reachable and exploitable?",
    "- Are there obvious mitigations visible in the code context?",
    "",
    "Return your score (1-10) and a brief reason.",
  ].join("\n");

  try {
    const { structuredOutput, executionError } = await runStructuredAgentQuery({
      prompt,
      cwd: repoRoot,
      model,
      maxTurns: 1,
      allowedTools: [],
      runtimeOptions: {},
      schema: RESCORE_SCHEMA,
    });

    if (executionError || !isRecord(structuredOutput)) {
      // On error, keep the finding (don't filter)
      return {
        fingerprint: finding.fingerprint,
        score: threshold,
        reason: executionError ?? "Failed to parse rescore output",
        keep: true,
      };
    }

    const score = typeof structuredOutput["score"] === "number"
      ? Math.max(1, Math.min(10, Math.floor(structuredOutput["score"])))
      : threshold;
    const reason = typeof structuredOutput["reason"] === "string"
      ? structuredOutput["reason"]
      : "";

    return {
      fingerprint: finding.fingerprint,
      score,
      reason,
      keep: score >= threshold,
    };
  } catch (error) {
    return {
      fingerprint: finding.fingerprint,
      score: threshold,
      reason: `Rescore error: ${toErrorMessage(error)}`,
      keep: true,
    };
  }
}
