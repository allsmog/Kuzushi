import { describe, expect, it } from "vitest";
import {
  createRun,
  initDb,
  updateRunStatus,
  updateVerificationResult,
  upsertFinding,
} from "../src/store.js";
import { generateMarkdownReport } from "../src/report-markdown.js";
import type { Finding } from "../src/scanners/types.js";
import type { KuzushiConfig, ScanOpts, TriageResult, VerificationResult } from "../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    scanners: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    scannerConfig: { semgrep: {} },
  };
}

function makeScanOpts(): ScanOpts {
  return {
    severity: ["ERROR"],
    excludePatterns: [],
    scanners: ["semgrep"],
    fresh: false,
  };
}

function makeFinding(): Finding {
  return {
    scanner: "semgrep",
    fingerprint: "fp-md-1",
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: 8,
    severity: "ERROR",
    message: "Potential SQL injection",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 88,
  };
}

function makeTriageResult(): TriageResult {
  return {
    fingerprint: "fp-md-1",
    verdict: "tp",
    confidence: 0.94,
    rationale: "User-controlled input reaches SQL sink.",
    verificationSteps: ["trace source", "verify sink"],
    fixPatch: null,
  };
}

function makeVerificationResult(): VerificationResult {
  return {
    fingerprint: "fp-md-1",
    exploitable: true,
    pocPayload: "' OR 1=1 --",
    pocDescription: "Inject in query param",
    attackVector: "HTTP query",
    preconditions: ["Endpoint reachable"],
    confidence: 0.89,
  };
}

describe("generateMarkdownReport", () => {
  it("scopes report to fingerprints when provided", () => {
    const db = initDb(":memory:");
    const runId = "run-md-fp";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, runId, "triaging");

    const finding1 = { ...makeFinding(), fingerprint: "fp-current" };
    const triage1 = { ...makeTriageResult(), fingerprint: "fp-current" };
    upsertFinding(db, finding1, triage1, "repo", "HEAD");

    const finding2 = { ...makeFinding(), fingerprint: "fp-stale", ruleId: "stale.rule" };
    const triage2 = { ...makeTriageResult(), fingerprint: "fp-stale" };
    upsertFinding(db, finding2, triage2, "repo", "HEAD");

    const markdown = generateMarkdownReport(
      db,
      "repo",
      { totalFindings: 1, queuedForTriage: 1, skippedAlreadyTriaged: 0 },
      runId,
      ["fp-current"],
    );

    expect(markdown).toContain("test.rule");
    expect(markdown).not.toContain("stale.rule");

    db.close();
  });

  it("renders summary and actionable findings sections", () => {
    const db = initDb(":memory:");
    const runId = "run-md-1";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, runId, "triaging");

    const finding = makeFinding();
    const triage = makeTriageResult();
    upsertFinding(db, finding, triage, "repo", "HEAD");

    const verification = makeVerificationResult();
    updateVerificationResult(db, finding.fingerprint, verification);

    const markdown = generateMarkdownReport(
      db,
      "repo",
      {
        totalFindings: 1,
        queuedForTriage: 1,
        skippedAlreadyTriaged: 0,
        skippedLowConfidence: 0,
        triaged: 1,
        triageErrors: 2,
        verified: 1,
        verifyErrors: 1,
        startedAt: "2026-01-01T00:00:00.000Z",
        completedAt: "2026-01-01T00:01:00.000Z",
      },
      runId,
    );

    expect(markdown).toContain("# Kuzushi Security Report - repo");
    expect(markdown).toContain("## Summary");
    expect(markdown).toContain("## Actionable Findings");
    expect(markdown).toContain("Verification result: **EXPLOITABLE**");
    expect(markdown).toContain("| Triage errors | 2 |");
    expect(markdown).toContain("| Verification errors | 1 |");
    expect(markdown).toContain("```text");
    expect(markdown).toContain("' OR 1=1 --");

    db.close();
  });
});
