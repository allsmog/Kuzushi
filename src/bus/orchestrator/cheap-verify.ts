/**
 * Cheap single-turn verification.
 *
 * A single structured API call (Sonnet, no tools) that confirms
 * exploitability based on the triage rationale + code evidence already
 * gathered. ~$0.03-0.05 per finding instead of ~$1.70 for the full
 * multi-turn verification agent.
 *
 * Used for findings the LLM gate classified as "cheap_verify" — likely
 * exploitable but needing a quick confirmation, not a full investigation.
 */

import type { AgentRuntime } from "../../agent-runtime/types.js";
import { getLogger } from "../../logger.js";
import type { Finding } from "../../scanners/types.js";
import type { TriageResult, VerificationResult } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";

const log = getLogger("cheap-verify");

export interface CheapVerifyCandidate {
  finding: Finding;
  triageResult: TriageResult;
}

export interface CheapVerifyResult {
  fingerprint: string;
  verification: VerificationResult;
  costUsd: number;
}

const CHEAP_VERIFY_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["fingerprint", "exploitable", "poc_payload", "poc_description", "confidence"],
  properties: {
    fingerprint: { type: "string" },
    exploitable: { type: "boolean" },
    poc_payload: { type: ["string", "null"] },
    poc_description: { type: "string" },
    confidence: { type: "number", minimum: 0, maximum: 1 },
    proof_level: { type: "integer", minimum: 1, maximum: 4 },
  },
} as const;

const CHEAP_VERIFY_SYSTEM_PROMPT = [
  "You are a security verification expert. You are given a finding that has already been triaged",
  "as a true positive with supporting evidence. Your job is to confirm exploitability and, if",
  "possible, construct a PoC payload — all from the evidence already provided (no tool use).",
  "",
  "You have the triage rationale, code evidence, and vulnerability context. Based on this:",
  "1. Determine if the vulnerability is exploitable in practice",
  "2. If exploitable, construct a concrete PoC payload string (e.g., the malicious input)",
  "3. Rate your confidence (0-1)",
  "",
  "Return a JSON object with: fingerprint, exploitable (boolean), poc_payload (string or null),",
  "poc_description (explanation), confidence (0-1), proof_level (1=rationale only, 2=payload constructed).",
].join("\n");

export interface CheapVerifyOptions {
  model?: string;
  runtime: AgentRuntime;
  repoRoot: string;
}

/**
 * Run cheap single-turn verification on a batch of candidates.
 * Each candidate gets one structured API call with no tool use.
 */
export async function cheapVerifyCandidates(
  candidates: CheapVerifyCandidate[],
  options: CheapVerifyOptions,
): Promise<CheapVerifyResult[]> {
  if (candidates.length === 0) return [];

  const model = options.model ?? "anthropic:claude-sonnet-4-6";
  const runtime = options.runtime;
  const results: CheapVerifyResult[] = [];

  // Try batch API first
  if (runtime.queryBatch) {
    try {
      const batchRequests = candidates.map((c, idx) => ({
        id: `cheap-verify-${idx}`,
        prompt: formatCheapVerifyPrompt(c),
        systemPrompt: CHEAP_VERIFY_SYSTEM_PROMPT,
      }));

      const batchResults = await runtime.queryBatch(batchRequests, {
        cwd: options.repoRoot,
        model,
        outputFormat: {
          type: "json_schema",
          schema: CHEAP_VERIFY_SCHEMA as unknown as Record<string, unknown>,
        },
        permissionMode: "dontAsk",
      });

      for (let i = 0; i < candidates.length; i++) {
        const candidate = candidates[i];
        const result = batchResults.get(`cheap-verify-${i}`);
        results.push(parseCheapVerifyResult(candidate, result));
      }
      return results;
    } catch (err) {
      log.warn(`Batch cheap-verify failed, falling back to direct: ${toErrorMessage(err)}`);
    }
  }

  // Fallback: direct API calls
  for (const candidate of candidates) {
    try {
      let resultText = "";
      let structuredOutput: unknown;
      let costUsd = 0;

      for await (const message of runtime.query({
        prompt: formatCheapVerifyPrompt(candidate),
        options: {
          cwd: options.repoRoot,
          model,
          allowedTools: [],
          permissionMode: "dontAsk",
          systemPromptPrefix: CHEAP_VERIFY_SYSTEM_PROMPT,
          outputFormat: {
            type: "json_schema",
            schema: CHEAP_VERIFY_SCHEMA as unknown as Record<string, unknown>,
            strict: true,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if ("result" in message) {
          resultText = message.result;
          structuredOutput = message.structuredOutput;
          if (typeof message.totalCostUsd === "number") costUsd = message.totalCostUsd;
        }
      }

      const parsed = structuredOutput ?? tryParseJson(resultText);
      results.push(
        parseCheapVerifyResult(candidate, {
          resultText,
          structuredOutput: parsed,
          executionError: null,
          costUsd,
        }),
      );
    } catch (err) {
      log.warn(`Cheap verify failed for ${candidate.finding.fingerprint}: ${toErrorMessage(err)}`);
      results.push({
        fingerprint: candidate.finding.fingerprint,
        verification: {
          fingerprint: candidate.finding.fingerprint,
          exploitable: true,
          pocPayload: null,
          pocDescription: "Cheap verify failed — accepting based on triage confidence",
          attackVector: null,
          preconditions: [],
          confidence: candidate.triageResult.confidence,
          proofLevel: 1,
          proofVerdict: "exploited",
          verifyCostUsd: 0,
        },
        costUsd: 0,
      });
    }
  }

  return results;
}

function formatCheapVerifyPrompt(candidate: CheapVerifyCandidate): string {
  const { finding, triageResult } = candidate;
  const evidence = triageResult.sink?.evidence ?? finding.evidence ?? "";
  const scenario = triageResult.exploitScenario ?? "";

  return [
    `Fingerprint: ${finding.fingerprint}`,
    `Rule: ${finding.ruleId}`,
    `File: ${finding.filePath}:${finding.startLine}`,
    `Severity: ${finding.severity} | CWE: ${finding.cwe?.join(", ") || "none"}`,
    "",
    "## Triage rationale",
    triageResult.rationale,
    "",
    evidence ? `## Code evidence\n${evidence}\n` : "",
    scenario ? `## Exploit scenario\n${scenario}\n` : "",
    triageResult.verificationSteps?.length
      ? `## Verification steps\n${triageResult.verificationSteps.join("\n")}\n`
      : "",
    "Based on the above, confirm exploitability and construct a PoC payload if possible.",
  ]
    .filter(Boolean)
    .join("\n");
}

function parseCheapVerifyResult(
  candidate: CheapVerifyCandidate,
  result:
    | {
        resultText: string;
        structuredOutput: unknown;
        executionError: string | null;
        costUsd: number;
      }
    | undefined,
): CheapVerifyResult {
  if (!result || result.executionError || !isRecord(result.structuredOutput)) {
    return {
      fingerprint: candidate.finding.fingerprint,
      verification: {
        fingerprint: candidate.finding.fingerprint,
        exploitable: true,
        pocPayload: null,
        pocDescription:
          result?.executionError ?? "Cheap verify parse failed — accepting based on triage",
        attackVector: null,
        preconditions: [],
        confidence: candidate.triageResult.confidence,
        proofLevel: 1,
        proofVerdict: "exploited",
        verifyCostUsd: result?.costUsd ?? 0,
      },
      costUsd: result?.costUsd ?? 0,
    };
  }

  const out = result.structuredOutput;
  return {
    fingerprint: candidate.finding.fingerprint,
    verification: {
      fingerprint: candidate.finding.fingerprint,
      exploitable: out["exploitable"] === true,
      pocPayload: typeof out["poc_payload"] === "string" ? (out["poc_payload"] as string) : null,
      pocDescription:
        typeof out["poc_description"] === "string"
          ? (out["poc_description"] as string)
          : "Cheap verification",
      attackVector: null,
      preconditions: [],
      confidence:
        typeof out["confidence"] === "number"
          ? (out["confidence"] as number)
          : candidate.triageResult.confidence,
      proofLevel:
        typeof out["proof_level"] === "number" ? (out["proof_level"] as 1 | 2 | 3 | 4) : 2,
      proofVerdict: out["exploitable"] === true ? "exploited" : "false_positive",
      verifyCostUsd: result.costUsd,
    },
    costUsd: result.costUsd,
  };
}

function tryParseJson(text: string): unknown {
  try {
    const fenceMatch = text.match(/```(?:json)?\s*\n([\s\S]*?)\n\s*```/);
    const jsonStr = fenceMatch ? fenceMatch[1].trim() : text.trim();
    return JSON.parse(jsonStr);
  } catch {
    return undefined;
  }
}
