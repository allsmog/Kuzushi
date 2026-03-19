/**
 * Context builders that transform domain objects (Finding, TriageResult)
 * into plain-object shapes suitable for template rendering.
 */

import type { BypassEntry } from "../bypass-knowledge.js";
import type { Finding } from "../scanners/types.js";
import type { TriageResult } from "../types.js";
import { sanitizeForPrompt } from "./sanitize.js";

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
  bypassKnowledge?: { category: string; techniques: string[] };
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
      message: sanitizeForPrompt(finding.message, 500),
      evidence: sanitizeForPrompt(finding.evidence || "none", 500),
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
  bypassEntry?: BypassEntry,
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
      message: sanitizeForPrompt(finding.message, 1000),
      evidence: sanitizeForPrompt(finding.evidence || "none", 1000),
      fingerprint: finding.fingerprint,
      subcategory: finding.subcategory,
      score: finding.score,
    },
    triage: {
      verdict: triageResult.verdict,
      confidence: triageResult.confidence,
      rationale: sanitizeForPrompt(triageResult.rationale),
      verificationSteps: triageResult.verificationSteps,
      verificationStepsDisplay: triageResult.verificationSteps.join(" | ") || "none",
    },
    repoName,
    bypassKnowledge: bypassEntry
      ? { category: bypassEntry.category, techniques: bypassEntry.techniques }
      : undefined,
  };
}

/** Context shape for batch triage prompt templates. */
export interface BatchTriageTemplateContext {
  repoName: string;
  findingCount: number;
  findings: TriageTemplateContext["finding"][];
}

/**
 * Build a template context for a batch triage prompt from an array of Findings.
 */
export function buildBatchTriageContext(
  findings: Finding[],
  repoName: string,
): BatchTriageTemplateContext {
  return {
    repoName,
    findingCount: findings.length,
    findings: findings.map(f => ({
      scanner: f.scanner,
      ruleId: f.ruleId,
      filePath: f.filePath,
      startLine: f.startLine,
      severity: f.severity,
      scannerConfidence: f.scannerConfidence,
      likelihood: f.likelihood,
      impact: f.impact,
      cwe: f.cwe,
      cweDisplay: f.cwe.join(", ") || "none",
      message: sanitizeForPrompt(f.message, 500),
      evidence: sanitizeForPrompt(f.evidence || "none", 500),
      fingerprint: f.fingerprint,
      subcategory: f.subcategory,
      score: f.score,
    })),
  };
}

/** Context shape for batch verification prompt templates. */
export interface BatchVerifyTemplateContext {
  repoName: string;
  findingCount: number;
  items: Array<{
    finding: TriageTemplateContext["finding"];
    triage: VerifyTemplateContext["triage"];
  }>;
}

/**
 * Build a template context for a batch verification prompt.
 */
export function buildBatchVerifyContext(
  items: Array<{ finding: Finding; triageResult: TriageResult }>,
  repoName: string,
): BatchVerifyTemplateContext {
  return {
    repoName,
    findingCount: items.length,
    items: items.map(({ finding, triageResult }) => ({
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
        message: sanitizeForPrompt(finding.message, 1000),
        evidence: sanitizeForPrompt(finding.evidence || "none", 1000),
        fingerprint: finding.fingerprint,
        subcategory: finding.subcategory,
        score: finding.score,
      },
      triage: {
        verdict: triageResult.verdict,
        confidence: triageResult.confidence,
        rationale: sanitizeForPrompt(triageResult.rationale),
        verificationSteps: triageResult.verificationSteps,
        verificationStepsDisplay: triageResult.verificationSteps.join(" | ") || "none",
      },
    })),
  };
}
