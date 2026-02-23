import type { LLMClient, RawFinding, TriageResult, Verdict } from "./types.js";

const TRIAGE_SYSTEM_PROMPT = `You are a security triage agent. Your job is to eliminate false positives that Semgrep cannot distinguish from true positives due to lack of semantic context. Semgrep matches syntactic patterns; you verify data flow and intent.

Rules:
- DO NOT suggest edits to source files.
- DO NOT print secrets (redact if needed).`;

function buildTriagePrompt(
  finding: RawFinding,
  codeContext: string,
  repoName: string,
): string {
  return `## Finding to triage

Repo: ${repoName}
Rule: ${finding.ruleId}
File: ${finding.filePath}:${finding.startLine}
Severity: ${finding.severity}
Semgrep Confidence: ${finding.semgrepConfidence}
Likelihood: ${finding.likelihood}
Impact: ${finding.impact}
CWE: ${finding.cwe.join(", ") || "none"}
Message: ${finding.message}

## Source code context

${codeContext}

## Instructions

1. Read the code around line ${finding.startLine}.
2. Trace the flagged value back to its source:
   - Is it user-controlled, config-derived, or hardcoded?
   - Is there sanitization or validation between source and sink?
   - Is the code path reachable? (Check for dead code, feature flags, test-only)
3. Inspect call sites if the data flow crosses function boundaries.
4. Note the finding's semgrep_confidence and likelihood — factor these into your assessment.
5. Assign a verdict:
   - tp: confirmed true positive
   - fp: confirmed false positive (explain why Semgrep was wrong)
   - needs_review: ONLY when you cannot determine the verdict after reading the code
6. Assign confidence (0.0-1.0, be conservative).
7. Write a short rationale referencing specific variable names, functions, and code patterns.
8. List 2-6 concrete verification steps a human reviewer could follow.
9. Optionally produce a unified diff fix (or null if not applicable).

## Output format

Respond with ONLY a JSON object (no markdown fencing, no extra text):
{
  "fingerprint": "${finding.fingerprint}",
  "verdict": "tp" | "fp" | "needs_review",
  "confidence": 0.0-1.0,
  "rationale": "...",
  "verification_steps": ["..."],
  "fix_patch": "..." or null
}`;
}

/** Parse a verdict string, defaulting to needs_review for unknown values. */
export function parseVerdict(v: string): Verdict {
  if (v === "tp" || v === "fp" || v === "needs_review") return v;
  return "needs_review";
}

/** Extract JSON from LLM response, handling markdown fences and preamble. */
export function extractJson(text: string): string {
  // Try to extract from markdown code fence
  const fenceMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
  if (fenceMatch) return fenceMatch[1].trim();

  // Try to find a JSON object directly
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
  const jsonStr = extractJson(text);
  const parsed = JSON.parse(jsonStr);

  return {
    fingerprint,
    verdict: parseVerdict(parsed.verdict),
    confidence: Math.max(0, Math.min(1, Number(parsed.confidence) || 0)),
    rationale: String(parsed.rationale ?? ""),
    verificationSteps: Array.isArray(parsed.verification_steps)
      ? parsed.verification_steps.map(String)
      : [],
    fixPatch: parsed.fix_patch ?? null,
  };
}

/** Triage a single finding via an LLM client. */
export async function triageFinding(
  llm: LLMClient,
  finding: RawFinding,
  codeContext: string,
  repoName: string,
): Promise<TriageResult> {
  const userPrompt = buildTriagePrompt(finding, codeContext, repoName);
  const text = await llm.complete(TRIAGE_SYSTEM_PROMPT, userPrompt);
  return parseTriageResponse(text, finding.fingerprint);
}
