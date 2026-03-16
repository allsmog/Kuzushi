import type { TriageAssertionConfig } from "../types.js";

export type { TriageAssertionConfig };

const tag = "[triage-assertions]";

export interface AssertionResult {
  name: string;
  passed: boolean;
  score: number;      // 0-1
  reason: string;
  weight: number;
}

export const DEFAULT_ASSERTION_WEIGHTS = {
  rationaleHasEvidence: 1.0,
  verificationStepsActionable: 1.0,
  confidenceMatchesEvidence: 1.0,
  noEmptyRationale: 1.0,
};

interface TriageOutput {
  verdict: string;
  confidence: number;
  rationale: string;
  verificationSteps?: string[];
  evidence?: string[];
}

/**
 * Check that the rationale references specific files or line numbers.
 */
export function assertRationaleHasEvidence(output: TriageOutput): AssertionResult {
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
export function assertVerificationStepsActionable(output: TriageOutput): AssertionResult {
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
export function assertConfidenceMatchesEvidence(output: TriageOutput): AssertionResult {
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
export function assertNoEmptyRationale(output: TriageOutput): AssertionResult {
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

/**
 * Run all triage assertions and return results.
 */
export function runTriageAssertions(
  output: TriageOutput,
  config?: TriageAssertionConfig
): AssertionResult[] {
  if (config?.enabled === false) return [];

  const results = [
    assertRationaleHasEvidence(output),
    assertVerificationStepsActionable(output),
    assertConfidenceMatchesEvidence(output),
    assertNoEmptyRationale(output),
  ];

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
      };
      const configKey = weightMap[key];
      if (configKey && config.weights[configKey] !== undefined) {
        result.weight = config.weights[configKey]!;
      }
    }
  }

  const passed = results.filter(r => r.passed).length;
  console.error(`${tag} Triage assertions completed: ${passed}/${results.length} passed`);

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
