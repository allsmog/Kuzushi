import { readFileSync } from "node:fs";
import path from "node:path";
import type { AgentRuntime, AgentSession } from "../agent-runtime/types.js";
import { runStructuredAgentQuery, runStructuredSessionQuery, runStructuredBatchQuery } from "../agent-runtime/execution.js";
import { writeBatchFile, cleanupBatchFiles } from "../agent-runtime/batch-files.js";
import { emitDiagnostic } from "../ui/output.js";
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
  runtime: AgentRuntime;
}

const BATCH_RESCORE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["scores"],
  properties: {
    scores: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["fingerprint", "score", "reason"],
        properties: {
          fingerprint: { type: "string" },
          score: { type: "integer", minimum: 1, maximum: 10 },
          reason: { type: "string" },
        },
      },
    },
  },
} as const;

const MAX_FINDINGS_PER_BATCH = 25;

/**
 * Re-score findings using batched LLM calls.
 * Groups findings into chunks of ~25 and sends each chunk as a single
 * LLM call with all findings + code context, instead of one call per finding.
 */
export async function rescoreFindings(
  findings: Finding[],
  options: RescoreOptions,
): Promise<LlmRescoreResult[]> {
  if (findings.length === 0) return [];

  const threshold = options.threshold ?? 4;
  const model = options.model ?? "anthropic:claude-haiku-4-5-20251001";

  // Read file contents once per unique file
  const fileContents = new Map<string, string>();
  for (const finding of findings) {
    if (fileContents.has(finding.filePath)) continue;
    try {
      const fullPath = path.isAbsolute(finding.filePath)
        ? finding.filePath
        : path.join(options.repoRoot, finding.filePath);
      const content = readFileSync(fullPath, "utf-8");
      const lines = content.split("\n");
      fileContents.set(finding.filePath, lines.slice(0, 500).join("\n"));
    } catch {
      fileContents.set(finding.filePath, "[file not readable]");
    }
  }

  // Chunk findings into batches
  const batches: Finding[][] = [];
  for (let i = 0; i < findings.length; i += MAX_FINDINGS_PER_BATCH) {
    batches.push(findings.slice(i, i + MAX_FINDINGS_PER_BATCH));
  }

  const allResults: LlmRescoreResult[] = [];
  const runtime = options.runtime;

  // ── Priority 1: Batch API path (50% cost reduction) ──
  if (runtime.queryBatch) {
    emitDiagnostic("llm-rescore", `Using Batch API for ${batches.length} batch(es) (50% cost reduction)`);

    // Collect all batch prompts upfront
    const batchRequests: Array<{ id: string; prompt: string; systemPrompt?: string }> = [];
    for (let batchIdx = 0; batchIdx < batches.length; batchIdx++) {
      const batch = batches[batchIdx];
      const findingEntries = batch.map((finding) => {
        const fileContent = fileContents.get(finding.filePath) ?? "[no content]";
        const lines = fileContent.split("\n");
        const startLine = Math.max(0, finding.startLine - 11);
        const endLine = Math.min(lines.length, finding.startLine + 10);
        const relevantContent = lines.slice(startLine, endLine).join("\n");

        return [
          `### Finding: ${finding.fingerprint}`,
          `Rule: ${finding.ruleId}`,
          `File: ${finding.filePath}:${finding.startLine}`,
          `Severity: ${finding.severity}`,
          `CWE: ${finding.cwe.join(", ") || "none"}`,
          `Message: ${finding.message}`,
          `Evidence: ${finding.evidence || "none"}`,
          "```",
          relevantContent,
          "```",
        ].join("\n");
      });

      batchRequests.push({
        id: `rescore-batch${batchIdx}`,
        prompt: [
          `Return a JSON array with one entry per finding, using the fingerprint to identify each.`,
          "",
          ...findingEntries,
        ].join("\n"),
        systemPrompt: RESCORE_SYSTEM_PROMPT,
      });
    }

    const resultsMap = await runStructuredBatchQuery(batchRequests, {
      cwd: options.repoRoot,
      model,
      schema: BATCH_RESCORE_SCHEMA as unknown as Record<string, unknown>,
      runtimeOptions: { runtime },
    });

    for (let batchIdx = 0; batchIdx < batches.length; batchIdx++) {
      const batch = batches[batchIdx];
      const reqId = `rescore-batch${batchIdx}`;
      const result = resultsMap.get(reqId);

      if (!result || result.executionError || !isRecord(result.structuredOutput)) {
        // On error, keep all findings (don't filter)
        allResults.push(...batch.map((f) => ({
          fingerprint: f.fingerprint,
          score: threshold,
          reason: result?.executionError ?? "Failed to parse batch rescore output",
          keep: true,
        })));
        continue;
      }

      const scores = Array.isArray(result.structuredOutput["scores"]) ? result.structuredOutput["scores"] : [];
      const scoreMap = new Map<string, { score: number; reason: string }>();
      for (const entry of scores) {
        if (isRecord(entry) && typeof entry["fingerprint"] === "string") {
          scoreMap.set(entry["fingerprint"] as string, {
            score: typeof entry["score"] === "number"
              ? Math.max(1, Math.min(10, Math.floor(entry["score"] as number)))
              : threshold,
            reason: typeof entry["reason"] === "string" ? entry["reason"] as string : "",
          });
        }
      }

      allResults.push(...batch.map((f) => {
        const entry = scoreMap.get(f.fingerprint);
        const score = entry?.score ?? threshold;
        return {
          fingerprint: f.fingerprint,
          score,
          reason: entry?.reason ?? "No rescore result returned",
          keep: score >= threshold,
        };
      }));

      emitDiagnostic("llm-rescore", `Batch ${batchIdx + 1}/${batches.length}: rescored ${batch.length} findings`);
    }

    return allResults;
  }

  // ── Priority 2: Session path — reuse a single subprocess across batches ──
  // ── Priority 3: One-shot query fallback ──
  const session = runtime.createSession?.({
    cwd: options.repoRoot,
    model,
    allowedTools: ["Read"],
    permissionMode: "dontAsk",
    outputFormat: {
      type: "json_schema",
      schema: BATCH_RESCORE_SCHEMA,
      strict: true,
    },
    systemPromptPrefix: RESCORE_SYSTEM_PROMPT,
  });

  const runId = session ? crypto.randomUUID() : "";

  try {
    for (let batchIdx = 0; batchIdx < batches.length; batchIdx++) {
      const batch = batches[batchIdx];
      emitDiagnostic("llm-rescore", `Batch ${batchIdx + 1}/${batches.length}: rescoring ${batch.length} findings...`);

      const batchResults = session
        ? await rescoreBatchSession(
            batch,
            fileContents,
            options.repoRoot,
            threshold,
            session,
            runId,
            batchIdx,
          )
        : await rescoreBatch(
            batch,
            fileContents,
            model,
            options.repoRoot,
            threshold,
            runtime,
          );
      allResults.push(...batchResults);
    }
  } finally {
    await session?.close();
    if (runId) cleanupBatchFiles(options.repoRoot, runId);
  }

  return allResults;
}

const RESCORE_SYSTEM_PROMPT = [
  "Rate each security finding as a true positive on a scale of 1-10.",
  "1 = almost certainly a false positive, 10 = almost certainly a true positive.",
  "",
  "For each finding, consider:",
  "- Is the vulnerability pattern real or a scanner false positive?",
  "- Is the flagged code actually reachable and exploitable?",
  "- Are there obvious mitigations visible in the code context?",
  "",
  "Return a JSON object with a `scores` array, one entry per finding, using the fingerprint to identify each.",
].join("\n");

async function rescoreBatchSession(
  findings: Finding[],
  fileContents: Map<string, string>,
  repoRoot: string,
  threshold: number,
  session: AgentSession,
  runId: string,
  batchIdx: number,
): Promise<LlmRescoreResult[]> {
  const batchData = findings.map((finding) => {
    const fileContent = fileContents.get(finding.filePath) ?? "[no content]";
    const lines = fileContent.split("\n");
    const startLine = Math.max(0, finding.startLine - 11);
    const endLine = Math.min(lines.length, finding.startLine + 10);
    const relevantContent = lines.slice(startLine, endLine).join("\n");

    return {
      fingerprint: finding.fingerprint,
      ruleId: finding.ruleId,
      filePath: finding.filePath,
      startLine: finding.startLine,
      severity: finding.severity,
      cwe: finding.cwe,
      message: finding.message,
      evidence: finding.evidence || null,
      codeSnippet: relevantContent,
    };
  });

  const filePath = writeBatchFile(repoRoot, runId, "llm-rescore", batchIdx, batchData);

  try {
    const { structuredOutput, executionError } = await runStructuredSessionQuery(
      session,
      `Read ${filePath} and score each finding.`,
    );

    if (executionError || !isRecord(structuredOutput)) {
      return findings.map((f) => ({
        fingerprint: f.fingerprint,
        score: threshold,
        reason: executionError ?? "Failed to parse batch rescore output",
        keep: true,
      }));
    }

    const scores = Array.isArray(structuredOutput["scores"]) ? structuredOutput["scores"] : [];
    const scoreMap = new Map<string, { score: number; reason: string }>();
    for (const entry of scores) {
      if (isRecord(entry) && typeof entry["fingerprint"] === "string") {
        scoreMap.set(entry["fingerprint"] as string, {
          score: typeof entry["score"] === "number"
            ? Math.max(1, Math.min(10, Math.floor(entry["score"] as number)))
            : threshold,
          reason: typeof entry["reason"] === "string" ? entry["reason"] as string : "",
        });
      }
    }

    return findings.map((f) => {
      const entry = scoreMap.get(f.fingerprint);
      const score = entry?.score ?? threshold;
      return {
        fingerprint: f.fingerprint,
        score,
        reason: entry?.reason ?? "No rescore result returned",
        keep: score >= threshold,
      };
    });
  } catch (error) {
    return findings.map((f) => ({
      fingerprint: f.fingerprint,
      score: threshold,
      reason: `Rescore error: ${toErrorMessage(error)}`,
      keep: true,
    }));
  }
}

async function rescoreBatch(
  findings: Finding[],
  fileContents: Map<string, string>,
  model: string,
  repoRoot: string,
  threshold: number,
  runtime: AgentRuntime,
): Promise<LlmRescoreResult[]> {
  // Build a single prompt with all findings and their code context
  const findingEntries = findings.map((finding) => {
    const fileContent = fileContents.get(finding.filePath) ?? "[no content]";
    const lines = fileContent.split("\n");
    const startLine = Math.max(0, finding.startLine - 11);
    const endLine = Math.min(lines.length, finding.startLine + 10);
    const relevantContent = lines.slice(startLine, endLine).join("\n");

    return [
      `### Finding: ${finding.fingerprint}`,
      `Rule: ${finding.ruleId}`,
      `File: ${finding.filePath}:${finding.startLine}`,
      `Severity: ${finding.severity}`,
      `CWE: ${finding.cwe.join(", ") || "none"}`,
      `Message: ${finding.message}`,
      `Evidence: ${finding.evidence || "none"}`,
      "```",
      relevantContent,
      "```",
    ].join("\n");
  });

  const prompt = [
    "Rate each security finding as a true positive on a scale of 1-10.",
    "1 = almost certainly a false positive, 10 = almost certainly a true positive.",
    "",
    "For each finding, consider:",
    "- Is the vulnerability pattern real or a scanner false positive?",
    "- Is the flagged code actually reachable and exploitable?",
    "- Are there obvious mitigations visible in the code context?",
    "",
    `Return a JSON array with one entry per finding, using the fingerprint to identify each.`,
    "",
    ...findingEntries,
  ].join("\n");

  try {
    const { structuredOutput, executionError } = await runStructuredAgentQuery({
      prompt,
      cwd: repoRoot,
      model,
      allowedTools: [],
      runtimeOptions: { runtime },
      schema: BATCH_RESCORE_SCHEMA,
    });

    if (executionError || !isRecord(structuredOutput)) {
      // On error, keep all findings (don't filter)
      return findings.map((f) => ({
        fingerprint: f.fingerprint,
        score: threshold,
        reason: executionError ?? "Failed to parse batch rescore output",
        keep: true,
      }));
    }

    const scores = Array.isArray(structuredOutput["scores"]) ? structuredOutput["scores"] : [];
    const scoreMap = new Map<string, { score: number; reason: string }>();
    for (const entry of scores) {
      if (isRecord(entry) && typeof entry["fingerprint"] === "string") {
        scoreMap.set(entry["fingerprint"] as string, {
          score: typeof entry["score"] === "number"
            ? Math.max(1, Math.min(10, Math.floor(entry["score"] as number)))
            : threshold,
          reason: typeof entry["reason"] === "string" ? entry["reason"] as string : "",
        });
      }
    }

    return findings.map((f) => {
      const entry = scoreMap.get(f.fingerprint);
      const score = entry?.score ?? threshold;
      return {
        fingerprint: f.fingerprint,
        score,
        reason: entry?.reason ?? "No rescore result returned",
        keep: score >= threshold,
      };
    });
  } catch (error) {
    return findings.map((f) => ({
      fingerprint: f.fingerprint,
      score: threshold,
      reason: `Rescore error: ${toErrorMessage(error)}`,
      keep: true,
    }));
  }
}
