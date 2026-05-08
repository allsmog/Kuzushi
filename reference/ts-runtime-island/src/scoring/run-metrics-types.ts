/**
 * Run metrics type definitions.
 *
 * Extracted to break the circular type dependency between
 * bus/events.ts (PipelineStats -> RunMetrics) and
 * scoring/run-metrics.ts (computeRunMetrics -> PipelineStats).
 */

export interface DurationBreakdown {
  scan: number;
  triage: number;
  verify?: number;
  pocHarness?: number;
  dynamicAnalysis?: number;
  total: number;
}

export interface CostBreakdown {
  triage: number;
  verify: number;
  pocHarness: number;
  dynamicAnalysis: number;
  variantAnalysis: number;
  total: number;
}

export interface StructuredEvidenceMetrics {
  findingsWithTaintPath: number;
  proofStateCounts: Record<string, number>;
  engineKindCounts: Record<string, number>;
}

export interface RunMetrics {
  verdictCounts: Record<string, number>;
  severityCounts: Record<string, number>;
  taskYield: Record<string, number>;
  averageConfidence: number;
  tpRate: number;
  fpRate: number;
  durationBreakdown: DurationBreakdown;
  costBreakdown: CostBreakdown;
  exploitabilityRate?: number;
  structuredEvidence: StructuredEvidenceMetrics;
  corroboratedClusters?: number;
  verificationOutcomes?: {
    exploitable: number;
    notExploitable: number;
    errors: number;
  };
  pocOutcomes?: {
    generated: number;
    skipped: number;
    errors: number;
  };
  assertionSummary?: {
    totalAssertions: number;
    passedAssertions: number;
    averageQualityScore: number;
    perAssertion: Record<string, { passed: number; failed: number; avgScore: number }>;
  };
  promptHash?: string;
}

export interface StageTimestamps {
  pipelineStart: string;
  pipelineEnd: string;
  scanStart?: string;
  scanEnd?: string;
  triageStart?: string;
  triageEnd?: string;
  verifyStart?: string;
  verifyEnd?: string;
  pocStart?: string;
  pocEnd?: string;
  dynamicStart?: string;
  dynamicEnd?: string;
}

export interface StageCosts {
  triage: number;
  verify: number;
  pocHarness: number;
  dynamicAnalysis: number;
  variantAnalysis: number;
}
