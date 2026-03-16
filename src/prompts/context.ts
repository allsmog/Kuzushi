/**
 * Context builders that transform domain objects (Finding, TriageResult)
 * into plain-object shapes suitable for template rendering.
 */

import type { Finding } from "../scanners/types.js";
import type { TriageResult } from "../types.js";

/** Context shape available inside triage prompt templates. */
export interface TriageTemplateContext {
  finding: {
    scanner: string;
    ruleId: string;
    filePath: string;
    startLine: number;
    severity: string;
    scannerConfidence: string;
    likelihood: string;
    impact: string;
    cwe: string[];
    cweDisplay: string;
    message: string;
    evidence: string;
    fingerprint: string;
    subcategory: string[];
    score: number;
  };
  repoName: string;
  findingCount?: number;
}

/** Context shape available inside verification prompt templates. */
export interface VerifyTemplateContext {
  finding: TriageTemplateContext["finding"];
  triage: {
    verdict: string;
    confidence: number;
    rationale: string;
    verificationSteps: string[];
    verificationStepsDisplay: string;
  };
  repoName: string;
}

/**
 * Build a template context for a single triage prompt from a Finding.
 */
export function buildTriageContext(finding: Finding, repoName: string): TriageTemplateContext {
  return {
    finding: {
      scanner: finding.scanner,
      ruleId: finding.ruleId,
      filePath: finding.filePath,
      startLine: finding.startLine,
      severity: finding.severity,
      scannerConfidence: finding.scannerConfidence,
      likelihood: finding.likelihood,
      impact: finding.impact,
      cwe: finding.cwe,
      cweDisplay: finding.cwe.join(", ") || "none",
      message: finding.message,
      evidence: finding.evidence || "none",
      fingerprint: finding.fingerprint,
      subcategory: finding.subcategory,
      score: finding.score,
    },
    repoName,
  };
}

/**
 * Build a template context for a verification prompt from a Finding + TriageResult.
 */
export function buildVerifyContext(
  finding: Finding,
  triageResult: TriageResult,
  repoName: string,
): VerifyTemplateContext {
  return {
    finding: {
      scanner: finding.scanner,
      ruleId: finding.ruleId,
      filePath: finding.filePath,
      startLine: finding.startLine,
      severity: finding.severity,
      scannerConfidence: finding.scannerConfidence,
      likelihood: finding.likelihood,
      impact: finding.impact,
      cwe: finding.cwe,
      cweDisplay: finding.cwe.join(", ") || "none",
      message: finding.message,
      evidence: finding.evidence || "none",
      fingerprint: finding.fingerprint,
      subcategory: finding.subcategory,
      score: finding.score,
    },
    triage: {
      verdict: triageResult.verdict,
      confidence: triageResult.confidence,
      rationale: triageResult.rationale,
      verificationSteps: triageResult.verificationSteps,
      verificationStepsDisplay: triageResult.verificationSteps.join(" | ") || "none",
    },
    repoName,
  };
}
