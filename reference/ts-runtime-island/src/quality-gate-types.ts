/**
 * Quality gate type definitions.
 *
 * Extracted into a standalone file to avoid circular type imports
 * between types.ts and quality-gate.ts.
 */

export interface QualityGateConfig {
  /** Any high/critical severity true positive = fail. */
  failOnHighSeverityTP?: boolean;
  /** Maximum number of non-FP (open) findings allowed. */
  maxOpenFindings?: number;
  /** Minimum triage confidence threshold (0-1). Findings below this cause failure. */
  minTriageConfidence?: number;
  /** Any confirmed exploitable finding = fail. */
  failOnExploitable?: boolean;
}

export interface QualityGateViolation {
  rule: string;
  message: string;
  fingerprints?: string[];
}

export interface QualityGateResult {
  passed: boolean;
  violations: QualityGateViolation[];
  summary: string;
}
