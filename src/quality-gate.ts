import type { FindingRow, Verdict } from "./types.js";

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

/** Severity values considered high/critical for the failOnHighSeverityTP gate. */
const HIGH_SEVERITIES = new Set(["ERROR", "CRITICAL", "HIGH"]);

/** Verdicts considered true positive for gate evaluation. */
const TP_VERDICTS = new Set<Verdict>(["tp"]);

/**
 * Evaluate quality gates against a set of triaged findings.
 *
 * Each enabled gate is checked independently, and all violations are collected.
 * The result passes only when zero violations are found.
 */
export function evaluateQualityGates(
  findings: ReadonlyArray<
    Pick<
      FindingRow,
      "fingerprint" | "verdict" | "confidence" | "severity" | "verifyExploitable"
    >
  >,
  config: QualityGateConfig,
): QualityGateResult {
  const violations: QualityGateViolation[] = [];

  // Gate 1: failOnHighSeverityTP — any high/critical true positive = fail
  if (config.failOnHighSeverityTP) {
    const offending = findings.filter(
      (f) =>
        TP_VERDICTS.has(f.verdict) &&
        HIGH_SEVERITIES.has(f.severity.toUpperCase()),
    );
    if (offending.length > 0) {
      violations.push({
        rule: "failOnHighSeverityTP",
        message: `${offending.length} high/critical severity true positive(s) found`,
        fingerprints: offending.map((f) => f.fingerprint),
      });
    }
  }

  // Gate 2: maxOpenFindings — cap on non-FP findings
  if (config.maxOpenFindings != null) {
    const openFindings = findings.filter((f) => f.verdict !== "fp");
    if (openFindings.length > config.maxOpenFindings) {
      violations.push({
        rule: "maxOpenFindings",
        message: `${openFindings.length} open finding(s) exceed threshold of ${config.maxOpenFindings}`,
        fingerprints: openFindings.map((f) => f.fingerprint),
      });
    }
  }

  // Gate 3: minTriageConfidence — findings with confidence below threshold = fail
  if (config.minTriageConfidence != null) {
    const lowConfidence = findings.filter(
      (f) =>
        f.verdict !== "fp" &&
        f.confidence < config.minTriageConfidence!,
    );
    if (lowConfidence.length > 0) {
      violations.push({
        rule: "minTriageConfidence",
        message: `${lowConfidence.length} finding(s) have triage confidence below ${(config.minTriageConfidence * 100).toFixed(0)}%`,
        fingerprints: lowConfidence.map((f) => f.fingerprint),
      });
    }
  }

  // Gate 4: failOnExploitable — confirmed exploitable finding = fail
  if (config.failOnExploitable) {
    const exploitable = findings.filter(
      (f) => f.verifyExploitable === 1,
    );
    if (exploitable.length > 0) {
      violations.push({
        rule: "failOnExploitable",
        message: `${exploitable.length} confirmed exploitable finding(s)`,
        fingerprints: exploitable.map((f) => f.fingerprint),
      });
    }
  }

  const passed = violations.length === 0;
  const summary = passed
    ? "All quality gates passed"
    : `Quality gates failed: ${violations.length} violation(s) — ${violations.map((v) => v.rule).join(", ")}`;

  return { passed, violations, summary };
}
