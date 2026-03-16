/**
 * Multi-Signal Composite Confidence scoring.
 *
 * Combines scanner severity, triage LLM confidence, verification results,
 * history (trajectory memory), and context sensitivity into a single
 * weighted composite score in the range [0, 1].
 */

import type { Finding } from "../scanners/types.js";

export interface ConfidenceSignal {
  name: string;
  score: number; // 0-1
  weight: number;
  source: string;
}

export interface CompositeConfidenceResult {
  composite: number; // 0-1 weighted average
  signals: ConfidenceSignal[];
}

export interface ConfidenceSignalWeights {
  scanner?: number;
  triage?: number;
  verification?: number;
  history?: number;
  context?: number;
}

export const DEFAULT_SIGNAL_WEIGHTS: Required<ConfidenceSignalWeights> = {
  scanner: 1.0,
  triage: 3.0,
  verification: 2.0,
  history: 1.0,
  context: 0.5,
};

/**
 * Extract confidence signal from scanner severity/likelihood.
 */
export function extractScannerSignal(finding: Finding): ConfidenceSignal {
  const severityMap: Record<string, number> = {
    critical: 1.0,
    high: 0.8,
    medium: 0.5,
    low: 0.3,
    info: 0.1,
    error: 0.8,
    warning: 0.5,
  };
  const score =
    severityMap[(finding.severity ?? "medium").toLowerCase()] ?? 0.5;
  return {
    name: "scanner",
    score,
    weight: 0,
    source: finding.scanner ?? "unknown",
  };
}

/**
 * Extract confidence signal from triage LLM response.
 */
export function extractTriageSignal(
  triageConfidence: number,
): ConfidenceSignal {
  return {
    name: "triage",
    score: Math.max(0, Math.min(1, triageConfidence)),
    weight: 0,
    source: "triage-llm",
  };
}

/**
 * Extract confidence signal from verification/exploitability result.
 */
export function extractVerificationSignal(
  isExploitable: boolean | undefined,
): ConfidenceSignal {
  const score =
    isExploitable === true ? 1.0 : isExploitable === false ? 0.2 : 0.5;
  return { name: "verification", score, weight: 0, source: "verification" };
}

/**
 * Extract confidence signal from finding history (trajectory memory).
 * Recurring findings that were previously confirmed as TP get higher scores.
 */
export function extractHistorySignal(
  previousVerdicts: string[],
): ConfidenceSignal {
  if (previousVerdicts.length === 0) {
    return { name: "history", score: 0.5, weight: 0, source: "history" };
  }
  const tpCount = previousVerdicts.filter((v) => v === "tp").length;
  const score = tpCount / previousVerdicts.length;
  return { name: "history", score, weight: 0, source: "history" };
}

/**
 * Extract confidence signal from data sensitivity context.
 */
export function extractContextSignal(
  hasAuthContext: boolean,
  hasSensitiveData: boolean,
): ConfidenceSignal {
  let score = 0.5;
  if (hasAuthContext) score += 0.25;
  if (hasSensitiveData) score += 0.25;
  return {
    name: "context",
    score: Math.min(1, score),
    weight: 0,
    source: "context",
  };
}

/**
 * Compute composite confidence from multiple signals.
 */
export function computeCompositeConfidence(
  signals: ConfidenceSignal[],
  weights: ConfidenceSignalWeights = DEFAULT_SIGNAL_WEIGHTS,
): CompositeConfidenceResult {
  const resolvedWeights = { ...DEFAULT_SIGNAL_WEIGHTS, ...weights };

  // Apply weights to signals
  const weightedSignals = signals.map((signal) => ({
    ...signal,
    weight:
      resolvedWeights[signal.name as keyof ConfidenceSignalWeights] ?? 1.0,
  }));

  const totalWeight = weightedSignals.reduce((sum, s) => sum + s.weight, 0);
  const composite =
    totalWeight > 0
      ? weightedSignals.reduce((sum, s) => sum + s.score * s.weight, 0) /
        totalWeight
      : 0;

  return {
    composite: Math.round(composite * 1000) / 1000, // round to 3 decimal places
    signals: weightedSignals,
  };
}
