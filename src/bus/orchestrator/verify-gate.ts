/**
 * LLM-based verification gate.
 *
 * Cheap, fast LLM call (Haiku batch) between triage and verification that
 * triages whether each finding is worth spending ~$1.70 on a full
 * verification agent. Returns one of three decisions per finding:
 *
 *   verify       — uncertain, needs full exploitability verification
 *   auto_accept  — high confidence TP with clear evidence, skip verification
 *   skip         — not worth verifying (weak evidence, likely FP noise)
 */

import type { AgentRuntime } from "../../agent-runtime/types.js";
import type { Finding } from "../../scanners/types.js";
import type { TriageResult } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { getLogger } from "../../logger.js";
import { extractSystemsHuntArtifactPath, readSystemsHuntArtifactByPath } from "../../agents/tasks/systems-hunt/artifacts.js";

const log = getLogger("verify-gate");

// ---------------------------------------------------------------------------
// Sink-pattern extraction
// ---------------------------------------------------------------------------

/* eslint-disable no-useless-escape -- sink names contain dots and parens */
const KNOWN_SINKS = /\b(SafeExecWithTimeout|ExecWithOutput|popen|system|exec|eval|subprocess\.(?:call|run|Popen)|os\.system|os\.popen|Runtime\.exec|ProcessBuilder|child_process\.exec|child_process\.spawn|execSync|spawnSync|query|execute|raw|prepare|createConnection|innerHTML|document\.write)\b/i;

/**
 * Extract the sink function from a triage result.
 * Uses the structured `sinkFunction` field first, then regex-parses
 * the rationale and sink evidence as fallback.
 */
export function extractSinkFunction(triageResult: TriageResult): string | null {
  if (triageResult.sinkFunction) return triageResult.sinkFunction;
  const sinkEvidence = triageResult.sink?.evidence ?? "";
  const match = sinkEvidence.match(KNOWN_SINKS) ?? triageResult.rationale.match(KNOWN_SINKS);
  return match ? match[1] : null;
}

/**
 * Build a pattern key for dedup. Groups findings by primary CWE + sink function.
 * Returns null if not enough signal to build a key.
 */
function buildPatternKey(candidate: VerifyGateCandidate): string | null {
  const sink = extractSinkFunction(candidate.triageResult);
  if (!sink) return null;
  const cwe = candidate.finding.cwe?.[0] ?? "unknown";
  return `${cwe}:${sink}`;
}

/**
 * Zero-cost pattern dedup: auto-accept findings that match a sink pattern
 * already verified as exploitable in this run.
 */
export function deduplicateByPattern(
  candidates: VerifyGateCandidate[],
  state: { verifiedPatterns?: Map<string, string> },
): { remaining: VerifyGateCandidate[]; autoAccepted: VerifyGateResult[] } {
  const patterns = state.verifiedPatterns;
  if (!patterns || patterns.size === 0) {
    return { remaining: candidates, autoAccepted: [] };
  }

  const remaining: VerifyGateCandidate[] = [];
  const autoAccepted: VerifyGateResult[] = [];

  for (const candidate of candidates) {
    const key = buildPatternKey(candidate);
    if (key && patterns.has(key)) {
      autoAccepted.push({
        fingerprint: candidate.finding.fingerprint,
        decision: "auto_accept",
        reason: `Pattern match: ${key} already verified as exploitable (${patterns.get(key)})`,
      });
    } else {
      remaining.push(candidate);
    }
  }

  return { remaining, autoAccepted };
}

/**
 * Register a verified exploitable finding's pattern for future dedup.
 */
export function registerVerifiedPattern(
  patterns: Map<string, string>,
  finding: Finding,
  triageResult: TriageResult,
): void {
  const sink = extractSinkFunction(triageResult);
  if (!sink) return;
  const cwe = finding.cwe?.[0] ?? "unknown";
  const key = `${cwe}:${sink}`;
  if (!patterns.has(key)) {
    patterns.set(key, finding.fingerprint);
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type VerifyGateDecision = "verify" | "auto_accept" | "skip" | "cheap_verify";

export interface VerifyGateResult {
  fingerprint: string;
  decision: VerifyGateDecision;
  reason: string;
}

export interface VerifyGateOptions {
  model?: string;
  runtime: AgentRuntime;
  repoRoot: string;
}

export interface VerifyGateCandidate {
  finding: Finding;
  triageResult: TriageResult;
}

// ---------------------------------------------------------------------------
// Schema for structured output
// ---------------------------------------------------------------------------

const GATE_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["decisions"],
  properties: {
    decisions: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["fingerprint", "decision", "reason"],
        properties: {
          fingerprint: { type: "string" },
          decision: { type: "string", enum: ["verify", "auto_accept", "skip", "cheap_verify"] },
          reason: { type: "string" },
        },
      },
    },
  },
} as const;

const MAX_CANDIDATES_PER_BATCH = 15;

// ---------------------------------------------------------------------------
// System prompt
// ---------------------------------------------------------------------------

const GATE_SYSTEM_PROMPT = [
  "You are a security verification gate. For each finding you receive, decide whether it needs",
  "full exploitability verification (an expensive, multi-turn agent call costing ~$1.70).",
  "",
  "Return one of four decisions per finding:",
  "",
  "  verify       — The finding is plausible but uncertain. It has moderate confidence,",
  "                  ambiguous evidence, or a complex attack path that needs full agent investigation.",
  "",
  "  cheap_verify — The finding is likely exploitable and the evidence is strong enough to confirm",
  "                  with a single-turn check (no tool use). The triage rationale describes a clear",
  "                  vulnerability pattern but confidence is in the 0.7-0.9 range. A quick payload",
  "                  confirmation is sufficient. Examples: command injection with string concatenation",
  "                  but needs payload construction, SQL injection with clear flow but needs proof.",
  "",
  "  auto_accept  — The finding is clearly a true positive. The triage rationale is strong,",
  "                  confidence is high (>= 0.85), there is concrete evidence (taint path,",
  "                  multiple scanners, clear exploit scenario), and verification would be",
  "                  redundant. Examples: hardcoded secrets with high-entropy values, SQL injection",
  "                  with clear unsanitized user input to query, command injection with obvious",
  "                  shell metacharacter passthrough.",
  "",
  "  skip         — The finding is not worth verifying. The triage rationale is weak,",
  "                  confidence is low, the evidence is speculative, or the vulnerability class",
  "                  is informational/best-practice. Verification would waste budget.",
  "                  Examples: informational findings, style issues flagged as security,",
  "                  findings where triage rationale says \"might be\" or \"could potentially\"",
  "                  with no concrete evidence.",
  "",
  "Consider these signals:",
  "- Triage confidence score and rationale quality",
  "- Whether corroborating evidence exists (taint path, multiple scanners)",
  "- Severity and CWE class (critical/high RCE, injection → lean toward verify or auto_accept)",
  "- Whether verification steps are actionable or vague",
  "- Proof state from prior analysis (execution_confirmed → auto_accept)",
  "",
  "Be conservative: when in doubt, choose verify. Never auto_accept without strong evidence.",
  "Return a JSON object with a `decisions` array, one entry per finding.",
].join("\n");

// ---------------------------------------------------------------------------
// Gate implementation
// ---------------------------------------------------------------------------

export async function gateVerificationCandidates(
  candidates: VerifyGateCandidate[],
  options: VerifyGateOptions,
): Promise<VerifyGateResult[]> {
  if (candidates.length === 0) return [];

  const preclassified = await preclassifySystemsHuntCandidates(candidates, options.repoRoot);
  const remainingCandidates = preclassified.remaining;
  if (remainingCandidates.length === 0) {
    return preclassified.results;
  }

  const model = options.model ?? "anthropic:claude-haiku-4-5-20251001";

  // Chunk into batches
  const batches: VerifyGateCandidate[][] = [];
  for (let i = 0; i < remainingCandidates.length; i += MAX_CANDIDATES_PER_BATCH) {
    batches.push(remainingCandidates.slice(i, i + MAX_CANDIDATES_PER_BATCH));
  }

  const allResults: VerifyGateResult[] = [...preclassified.results];
  const runtime = options.runtime;

  // ── Try Batch API first (50% cost reduction) ──
  if (runtime.queryBatch) {
    try {
      log.info(`Trying Batch API for ${batches.length} gate batch(es)`);

      const batchRequests = batches.map((batch, batchIdx) => ({
        id: `gate-batch${batchIdx}`,
        prompt: [
          "Evaluate each finding and decide: verify, auto_accept, or skip.",
          "",
          ...batch.map((c) => formatCandidateEntry(c)),
        ].join("\n"),
        systemPrompt: GATE_SYSTEM_PROMPT,
      }));

      const resultsMap = await runtime.queryBatch(batchRequests, {
        cwd: options.repoRoot,
        model,
        outputFormat: { type: "json_schema", schema: GATE_SCHEMA as unknown as Record<string, unknown> },
        thinkingDisabled: true,
        permissionMode: "dontAsk",
      });

      for (let batchIdx = 0; batchIdx < batches.length; batchIdx++) {
        const batch = batches[batchIdx];
        const result = resultsMap.get(`gate-batch${batchIdx}`);
        allResults.push(...parseBatchResult(batch, result));
        log.info(`Gate batch ${batchIdx + 1}/${batches.length}: gated ${batch.length} candidates`);
      }
      return allResults;
    } catch (err) {
      log.warn(`Batch API failed, falling back to direct queries: ${toErrorMessage(err)}`);
    }
  }

  // ── Fallback: direct API calls per batch (no subprocess, no hanging) ──
  log.info(`Using direct queries for ${batches.length} gate batch(es)`);
  for (let batchIdx = 0; batchIdx < batches.length; batchIdx++) {
    const batch = batches[batchIdx];
    const prompt = [
      "Evaluate each finding and decide: verify, auto_accept, or skip.",
      "",
      ...batch.map((c) => formatCandidateEntry(c)),
    ].join("\n");

    try {
      let resultText = "";
      let structuredOutput: unknown = undefined;
      for await (const message of runtime.query({
        prompt,
        options: {
          cwd: options.repoRoot,
          model,
          allowedTools: [],
          permissionMode: "dontAsk",
          thinkingDisabled: true,
          systemPromptPrefix: GATE_SYSTEM_PROMPT,
          outputFormat: {
            type: "json_schema",
            schema: GATE_SCHEMA as unknown as Record<string, unknown>,
            strict: true,
          },
        },
      })) {
        if (message.type !== "result") continue;
        if ("result" in message) {
          resultText = message.result;
          structuredOutput = message.structuredOutput;
        }
      }

      const parsed = structuredOutput ?? (resultText ? tryParseJson(resultText) : undefined);
      allResults.push(...parseBatchResult(batch, {
        resultText: resultText ?? "",
        structuredOutput: parsed,
        executionError: null,
        costUsd: 0,
      }));
      log.info(`Gate batch ${batchIdx + 1}/${batches.length}: gated ${batch.length} candidates`);
    } catch (err) {
      log.warn(`Gate batch ${batchIdx + 1} failed: ${toErrorMessage(err)}`);
      allResults.push(...batch.map((c) => ({
        fingerprint: c.finding.fingerprint,
        decision: "verify" as const,
        reason: `Gate query failed — defaulting to verify`,
      })));
    }
  }

  return allResults;
}

async function preclassifySystemsHuntCandidates(
  candidates: VerifyGateCandidate[],
  repoRoot: string,
): Promise<{ remaining: VerifyGateCandidate[]; results: VerifyGateResult[] }> {
  const remaining: VerifyGateCandidate[] = [];
  const results: VerifyGateResult[] = [];

  for (const candidate of candidates) {
    if (candidate.finding.scanner !== "systems-hunt") {
      remaining.push(candidate);
      continue;
    }

    const artifactPath = extractSystemsHuntArtifactPath(candidate.finding);
    const resolvedPath = artifactPath
      ? (artifactPath.startsWith("/") ? artifactPath : `${repoRoot}/${artifactPath}`.replace(/\/+/g, "/"))
      : undefined;
    const artifact = resolvedPath ? await readSystemsHuntArtifactByPath(resolvedPath) : undefined;

    if (artifact?.cheapVerifiable === true) {
      results.push({
        fingerprint: candidate.finding.fingerprint,
        decision: "cheap_verify",
        reason: "Systems hunt artifact marked this finding as cheap_verifiable",
      });
      continue;
    }

    results.push({
      fingerprint: candidate.finding.fingerprint,
      decision: "skip",
      reason: artifactPath
        ? `Systems hunt finding defaults to skip verification in v1 unless artifact is cheap_verifiable (${artifactPath})`
        : "Systems hunt finding defaults to skip verification in v1 unless its artifact is cheap_verifiable",
    });
  }

  return { remaining, results };
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

function parseBatchResult(
  batch: VerifyGateCandidate[],
  result: { resultText: string; structuredOutput: unknown; executionError: string | null; costUsd: number } | undefined,
): VerifyGateResult[] {
  if (!result || result.executionError || !isRecord(result.structuredOutput)) {
    return batch.map((c) => ({
      fingerprint: c.finding.fingerprint,
      decision: "verify" as const,
      reason: result?.executionError ?? "Gate batch failed — defaulting to verify",
    }));
  }

  const decisions = Array.isArray(result.structuredOutput["decisions"])
    ? result.structuredOutput["decisions"]
    : [];
  const decisionMap = new Map<string, { decision: VerifyGateDecision; reason: string }>();
  for (const entry of decisions) {
    if (isRecord(entry) && typeof entry["fingerprint"] === "string") {
      const d = entry["decision"];
      const decision: VerifyGateDecision =
        d === "auto_accept" || d === "skip" || d === "cheap_verify" ? d : "verify";
      decisionMap.set(entry["fingerprint"] as string, {
        decision,
        reason: typeof entry["reason"] === "string" ? entry["reason"] as string : "",
      });
    }
  }

  return batch.map((c) => {
    const entry = decisionMap.get(c.finding.fingerprint);
    return {
      fingerprint: c.finding.fingerprint,
      decision: entry?.decision ?? "verify",
      reason: entry?.reason ?? "No gate decision returned — defaulting to verify",
    };
  });
}

// ---------------------------------------------------------------------------
// Prompt formatting
// ---------------------------------------------------------------------------

function formatCandidateEntry(candidate: VerifyGateCandidate): string {
  const { finding, triageResult } = candidate;

  const signals: string[] = [];
  if (finding.taintPath?.length) {
    signals.push(`taint path (${finding.taintPath.length} steps)`);
  }
  if (finding.corroboratingSignals?.length) {
    signals.push(`${finding.corroboratingSignals.length} corroborating scanner(s)`);
  }
  if (finding.proofState) {
    signals.push(`proof: ${finding.proofState}`);
  }
  if (triageResult.calibratedConfidence != null) {
    signals.push(`calibrated confidence: ${triageResult.calibratedConfidence.toFixed(2)}`);
  }
  if (triageResult.compositeConfidence != null) {
    signals.push(`composite confidence: ${triageResult.compositeConfidence.toFixed(2)}`);
  }

  const verificationSteps = triageResult.verificationSteps?.length
    ? triageResult.verificationSteps.slice(0, 3).join("; ")
    : "none";

  return [
    `### Finding: ${finding.fingerprint}`,
    `Scanner: ${finding.scanner} | Rule: ${finding.ruleId}`,
    `File: ${finding.filePath}:${finding.startLine}`,
    `Severity: ${finding.severity} | CWE: ${finding.cwe?.join(", ") || "none"}`,
    `Verdict: ${triageResult.verdict} | Confidence: ${triageResult.confidence.toFixed(2)}`,
    `Rationale: ${triageResult.rationale}`,
    `Verification steps: ${verificationSteps}`,
    signals.length > 0 ? `Corroborating evidence: ${signals.join(", ")}` : "Corroborating evidence: none",
    "",
  ].join("\n");
}
