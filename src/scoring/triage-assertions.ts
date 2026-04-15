import type { TriageAssertionConfig } from "../types.js";
import { getLogger } from "../logger.js";

export type { TriageAssertionConfig };

const log = getLogger("triage-assertions");

export interface AssertionResult {
  name: string;
  passed: boolean;
  score: number;      // 0-1
  reason: string;
  weight: number;
}

const DEFAULT_ASSERTION_WEIGHTS = {
  rationaleHasEvidence: 1.0,
  verificationStepsActionable: 1.0,
  confidenceMatchesEvidence: 1.0,
  noEmptyRationale: 1.0,
  cweMentionsRelevant: 0.8,
  fixPatchValid: 0.5,
  severityVerdictAlignment: 0.8,
  verdictConsistency: 0.7,
  costEfficiency: 0.5,
  latencyReasonable: 0.3,
};

interface TriageOutput {
  verdict: string;
  confidence: number;
  rationale: string;
  verificationSteps?: string[];
  evidence?: string[];
  // Extended fields for additional assertions
  fingerprint?: string;
  findingSeverity?: string;
  findingCwe?: string[];
  costUsd?: number;
  durationMs?: number;
  fixPatch?: string | null;
  historicalVerdicts?: Array<{ verdict: string; confidence: number }>;
  /** Median triage cost for the current run, used by cost-efficiency assertion. */
  runMedianCostUsd?: number;
}

/**
 * Check that the rationale references specific files or line numbers.
 */
function assertRationaleHasEvidence(output: TriageOutput): AssertionResult {
  const weight = DEFAULT_ASSERTION_WEIGHTS.rationaleHasEvidence;
  const rationale = output.rationale ?? "";

  // Look for file paths, line numbers, code references
  const hasFilePath = /[\w\-/.]+\.\w{1,5}/.test(rationale);
  const hasLineNumber = /line\s+\d+|:\d+/i.test(rationale);
  const hasCodeRef = /`[^`]+`/.test(rationale);
  const hasEvidence = (output.evidence?.length ?? 0) > 0;

  const evidenceCount = [hasFilePath, hasLineNumber, hasCodeRef, hasEvidence].filter(Boolean).length;
  const score = Math.min(1, evidenceCount / 2); // 2+ indicators = full score

  return {
    name: "rationale-has-evidence",
    passed: score >= 0.5,
    score,
    reason: score >= 0.5
      ? "Rationale references specific code locations"
      : "Rationale lacks specific file/line references",
    weight,
  };
}

/**
 * Check that verification steps are concrete and actionable.
 */
function assertVerificationStepsActionable(output: TriageOutput): AssertionResult {
  const weight = DEFAULT_ASSERTION_WEIGHTS.verificationStepsActionable;
  const steps = output.verificationSteps ?? [];

  if (steps.length === 0) {
    return {
      name: "verification-steps-actionable",
      passed: false,
      score: 0,
      reason: "No verification steps provided",
      weight,
    };
  }

  // Check each step for actionability (contains verbs, specific enough)
  const actionVerbs = /\b(check|verify|test|inspect|review|confirm|run|examine|look|search|trace|follow|read|open)\b/i;
  const actionableSteps = steps.filter(step => actionVerbs.test(step) && step.length > 20);
  const score = actionableSteps.length / steps.length;

  return {
    name: "verification-steps-actionable",
    passed: score >= 0.5,
    score,
    reason: score >= 0.5
      ? `${actionableSteps.length}/${steps.length} steps are actionable`
      : `Only ${actionableSteps.length}/${steps.length} steps appear actionable`,
    weight,
  };
}

/**
 * Check that high confidence is backed by strong evidence.
 * High confidence (>0.8) should have evidence; low confidence (<0.3) shouldn't claim certainty.
 */
function assertConfidenceMatchesEvidence(output: TriageOutput): AssertionResult {
  const weight = DEFAULT_ASSERTION_WEIGHTS.confidenceMatchesEvidence;
  const confidence = output.confidence;
  const rationale = output.rationale ?? "";
  const evidenceCount = (output.evidence?.length ?? 0);

  let score = 1.0;
  let reason = "Confidence level matches evidence strength";

  // High confidence but no evidence
  if (confidence > 0.8 && evidenceCount === 0 && rationale.length < 100) {
    score = 0.3;
    reason = "High confidence but weak evidence/rationale";
  }

  // Very low confidence with strong evidence (possibly under-confident)
  if (confidence < 0.3 && evidenceCount >= 3) {
    score = 0.5;
    reason = "Low confidence despite multiple evidence items (possibly under-confident)";
  }

  // Moderate confidence with moderate evidence = reasonable
  // This is the expected case

  return {
    name: "confidence-matches-evidence",
    passed: score >= 0.5,
    score,
    reason,
    weight,
  };
}

/**
 * Check that rationale is not empty or too short.
 */
function assertNoEmptyRationale(output: TriageOutput): AssertionResult {
  const weight = DEFAULT_ASSERTION_WEIGHTS.noEmptyRationale;
  const rationale = output.rationale ?? "";
  const length = rationale.trim().length;

  let score: number;
  let reason: string;

  if (length === 0) {
    score = 0;
    reason = "Rationale is empty";
  } else if (length < 50) {
    score = 0.3;
    reason = `Rationale too short (${length} chars, minimum 50 recommended)`;
  } else if (length < 100) {
    score = 0.7;
    reason = `Rationale is brief (${length} chars)`;
  } else {
    score = 1.0;
    reason = `Rationale has sufficient detail (${length} chars)`;
  }

  return {
    name: "no-empty-rationale",
    passed: score >= 0.5,
    score,
    reason,
    weight,
  };
}

/** CWE keyword map for relevance checks. */
const CWE_KEYWORD_MAP: Record<string, string[]> = {
  "CWE-89": ["injection", "sql", "query", "parameterized", "prepared"],
  "CWE-79": ["xss", "script", "sanitiz", "encod", "escape"],
  "CWE-78": ["command", "injection", "exec", "shell", "subprocess"],
  "CWE-918": ["ssrf", "request", "url", "redirect"],
  "CWE-22": ["path", "traversal", "directory", ".."],
  "CWE-287": ["auth", "bypass", "session", "token", "jwt"],
  "CWE-862": ["authorization", "access", "permission", "idor", "privilege"],
};

/**
 * Check that the rationale mentions keywords relevant to the finding's CWEs.
 * Only runs when `findingCwe` is provided and non-empty.
 */
function assertCweMentionsRelevant(output: TriageOutput): AssertionResult | null {
  const weight = DEFAULT_ASSERTION_WEIGHTS.cweMentionsRelevant;
  const cwes = output.findingCwe;

  if (!cwes || cwes.length === 0) return null;

  const rationale = (output.rationale ?? "").toLowerCase();
  let matchedCount = 0;
  let checkedCount = 0;

  for (const cwe of cwes) {
    const keywords = CWE_KEYWORD_MAP[cwe];
    if (!keywords) continue; // Unknown CWE, skip
    checkedCount++;
    const hasMatch = keywords.some(kw => rationale.includes(kw));
    if (hasMatch) matchedCount++;
  }

  // If none of the CWEs are in our keyword map, consider it a pass
  if (checkedCount === 0) {
    return {
      name: "cwe-mentions-relevant",
      passed: true,
      score: 1.0,
      reason: "No mapped CWEs to check against",
      weight,
    };
  }

  const score = matchedCount / checkedCount;

  return {
    name: "cwe-mentions-relevant",
    passed: score >= 0.5,
    score,
    reason: score >= 0.5
      ? `Rationale mentions keywords for ${matchedCount}/${checkedCount} CWEs`
      : `Rationale missing keywords for ${checkedCount - matchedCount}/${checkedCount} CWEs`,
    weight,
  };
}

/**
 * Check that a provided fixPatch contains actual code/diff content, not just prose.
 * Only runs when `fixPatch` is provided.
 */
function assertFixPatchValid(output: TriageOutput): AssertionResult | null {
  const weight = DEFAULT_ASSERTION_WEIGHTS.fixPatchValid;
  const patch = output.fixPatch;

  if (patch === undefined || patch === null || patch.trim() === "") return null;

  const hasDiffMarkers = /[+\-]|@@|diff/.test(patch);
  const hasCodeSyntax = /[;{}()=>]|\breturn\b|\bimport\b/.test(patch);
  const isValid = hasDiffMarkers || hasCodeSyntax;

  return {
    name: "fix-patch-valid",
    passed: isValid,
    score: isValid ? 1.0 : 0.3,
    reason: isValid
      ? "Fix patch contains code or diff content"
      : "Fix patch appears to be prose without code/diff markers",
    weight,
  };
}

/**
 * Flag misalignment between finding severity and triage verdict.
 * High/CRITICAL severity marked FP with low confidence is suspicious.
 * Only runs when `findingSeverity` is provided.
 */
function assertSeverityVerdictAlignment(output: TriageOutput): AssertionResult | null {
  const weight = DEFAULT_ASSERTION_WEIGHTS.severityVerdictAlignment;
  const severity = output.findingSeverity;

  if (!severity) return null;

  const upperSeverity = severity.toUpperCase();
  const isHighSeverity = upperSeverity === "HIGH" || upperSeverity === "CRITICAL";
  const isFpVerdict = output.verdict.toLowerCase() === "fp";
  const lowConfidence = output.confidence < 0.7;

  const misaligned = isHighSeverity && isFpVerdict && lowConfidence;

  return {
    name: "severity-verdict-alignment",
    passed: !misaligned,
    score: misaligned ? 0.5 : 1.0,
    reason: misaligned
      ? `${upperSeverity} severity finding dismissed as FP with low confidence (${output.confidence})`
      : "Severity and verdict are aligned",
    weight,
  };
}

/**
 * Check verdict consistency across historical runs for the same fingerprint.
 * Only runs when `historicalVerdicts` is provided and non-empty.
 */
function assertVerdictConsistency(output: TriageOutput): AssertionResult | null {
  const weight = DEFAULT_ASSERTION_WEIGHTS.verdictConsistency;
  const history = output.historicalVerdicts;

  if (!history || history.length === 0) return null;

  const currentVerdict = output.verdict.toLowerCase();
  const flips = history.filter(h => h.verdict.toLowerCase() !== currentVerdict).length;
  const total = history.length;
  const score = 1.0 - (flips / total) * 0.5;

  return {
    name: "verdict-consistency",
    passed: score >= 0.5,
    score,
    reason: flips === 0
      ? `Verdict consistent across ${total} historical run(s)`
      : `Verdict flipped ${flips}/${total} time(s) compared to history`,
    weight,
  };
}

/**
 * Flag findings that cost significantly more than the run median.
 * Only runs when both `costUsd` and `runMedianCostUsd` are provided.
 */
function assertCostEfficiency(output: TriageOutput): AssertionResult | null {
  const weight = DEFAULT_ASSERTION_WEIGHTS.costEfficiency;

  if (output.costUsd === undefined || output.runMedianCostUsd === undefined) return null;

  const ratio = output.runMedianCostUsd > 0
    ? output.costUsd / output.runMedianCostUsd
    : 0;

  let score: number;
  let reason: string;

  if (ratio <= 1) {
    score = 1.0;
    reason = `Triage cost ($${output.costUsd.toFixed(4)}) at or below median`;
  } else if (ratio <= 2) {
    score = 0.7;
    reason = `Triage cost ($${output.costUsd.toFixed(4)}) is ${ratio.toFixed(1)}x median`;
  } else if (ratio <= 3) {
    score = 0.5;
    reason = `Triage cost ($${output.costUsd.toFixed(4)}) is ${ratio.toFixed(1)}x median`;
  } else {
    score = 0.3;
    reason = `Triage cost ($${output.costUsd.toFixed(4)}) is ${ratio.toFixed(1)}x median (>3x threshold)`;
  }

  return {
    name: "cost-efficiency",
    passed: score >= 0.5,
    score,
    reason,
    weight,
  };
}

/**
 * Score based on triage duration. Flags excessively slow triages.
 * Only runs when `durationMs` is provided.
 */
function assertLatencyReasonable(output: TriageOutput): AssertionResult | null {
  const weight = DEFAULT_ASSERTION_WEIGHTS.latencyReasonable;

  if (output.durationMs === undefined) return null;

  const seconds = output.durationMs / 1000;
  let score: number;
  let reason: string;

  if (seconds < 60) {
    score = 1.0;
    reason = `Triage completed in ${seconds.toFixed(1)}s (< 60s)`;
  } else if (seconds < 180) {
    score = 0.7;
    reason = `Triage took ${seconds.toFixed(1)}s (< 180s)`;
  } else if (seconds < 300) {
    score = 0.3;
    reason = `Triage took ${seconds.toFixed(1)}s (< 300s, approaching limit)`;
  } else {
    score = 0.1;
    reason = `Triage took ${seconds.toFixed(1)}s (>= 300s, excessive)`;
  }

  return {
    name: "latency-reasonable",
    passed: score >= 0.5,
    score,
    reason,
    weight,
  };
}

/**
 * Run all triage assertions and return results.
 */
export function runTriageAssertions(
  output: TriageOutput,
  config?: TriageAssertionConfig
): AssertionResult[] {
  if (config?.enabled === false) return [];

  // Core assertions (always run)
  const results: AssertionResult[] = [
    assertRationaleHasEvidence(output),
    assertVerificationStepsActionable(output),
    assertConfidenceMatchesEvidence(output),
    assertNoEmptyRationale(output),
  ];

  // Conditional assertions (only run when required data is present)
  const conditionalAssertions = [
    assertCweMentionsRelevant(output),
    assertFixPatchValid(output),
    assertSeverityVerdictAlignment(output),
    assertVerdictConsistency(output),
    assertCostEfficiency(output),
    assertLatencyReasonable(output),
  ];

  for (const result of conditionalAssertions) {
    if (result !== null) {
      results.push(result);
    }
  }

  // Apply custom weights if provided
  if (config?.weights) {
    for (const result of results) {
      const key = result.name.replace(/-/g, "") as string;
      // Map assertion names to config keys
      const weightMap: Record<string, keyof NonNullable<TriageAssertionConfig["weights"]>> = {
        "rationalehasevidence": "rationaleHasEvidence",
        "verificationstepsactionable": "verificationStepsActionable",
        "confidencematchesevidence": "confidenceMatchesEvidence",
        "noemptyrationale": "noEmptyRationale",
        "cwementionsrelevant": "cweMentionsRelevant",
        "fixpatchvalid": "fixPatchValid",
        "severityverdictalignment": "severityVerdictAlignment",
        "verdictconsistency": "verdictConsistency",
        "costefficiency": "costEfficiency",
        "latencyreasonable": "latencyReasonable",
      };
      const configKey = weightMap[key];
      if (configKey && config.weights[configKey] !== undefined) {
        result.weight = config.weights[configKey]!;
      }
    }
  }

  const passed = results.filter(r => r.passed).length;
  log.info(
    { passed, total: results.length },
    "Triage assertions completed",
  );

  return results;
}

/**
 * Compute aggregate quality score from assertion results.
 */
export function computeTriageQualityScore(results: AssertionResult[]): number {
  if (results.length === 0) return 1.0;
  const totalWeight = results.reduce((sum, r) => sum + r.weight, 0);
  if (totalWeight === 0) return 1.0;
  return results.reduce((sum, r) => sum + r.score * r.weight, 0) / totalWeight;
}
