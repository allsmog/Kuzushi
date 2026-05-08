import { describe, expect, it } from "vitest";
import type { Finding } from "../src/scanners/types.js";
import type {
  PocHarnessResult,
  RepoContext,
  ScanOpts,
  TriageResult,
  Verdict,
} from "../src/types.js";
import {
  FindingMetadataSchema,
  FindingRowSchema,
  TriageResultSchema,
  VerificationResultSchema,
} from "../src/types.js";

describe("types", () => {
  it("Verdict accepts valid values", () => {
    const verdicts: Verdict[] = ["tp", "fp", "needs_review"];
    expect(verdicts).toHaveLength(3);
  });

  it("Finding shape is constructible", () => {
    const finding: Finding = {
      taskId: "semgrep",
      fingerprint: "abc123",
      ruleId: "test.rule",
      filePath: "src/app.ts",
      startLine: 1,
      severity: "ERROR",
      message: "test",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["CWE-79"],
      score: 54,
    };
    expect(finding.fingerprint).toBe("abc123");
  });

  it("TriageResult shape is constructible", () => {
    const result: TriageResult = {
      fingerprint: "abc123",
      title: "SQL injection in lookup",
      attackNarrative: "Alice submits crafted input and reads Bob's records.",
      displaySeverity: "high",
      verdict: "fp",
      confidence: 0.95,
      rationale: "safe",
      verificationSteps: ["check code"],
      fixPatch: null,
      compositeConfidence: 0.91,
    };
    expect(result.verdict).toBe("fp");
    expect(TriageResultSchema.parse(result).displaySeverity).toBe("high");
  });

  it("VerificationResult schema accepts composite confidence used by workers", () => {
    const parsed = VerificationResultSchema.parse({
      fingerprint: "abc123",
      exploitable: false,
      pocPayload: null,
      pocDescription: "not exploitable",
      attackVector: null,
      preconditions: [],
      confidence: 0.8,
      compositeConfidence: 0.76,
    });
    expect(parsed.compositeConfidence).toBe(0.76);
  });

  it("ScanOpts shape is constructible", () => {
    const opts: ScanOpts = {
      severity: ["ERROR"],
      maxFindings: 10,
      excludePatterns: ["node_modules"],
      tasks: ["semgrep"],
      fresh: false,
    };
    expect(opts.severity).toEqual(["ERROR"]);
  });

  it("RepoContext shape is constructible", () => {
    const context: RepoContext = {
      languages: ["TypeScript"],
      frameworks: ["Express"],
      authPatterns: ["JWT"],
      sanitizationLibs: ["helmet"],
      ormOrDb: ["Prisma"],
      entryPoints: ["src/pages/api/*"],
    };
    expect(context.frameworks).toContain("Express");
  });

  it("PocHarnessResult shape is constructible", () => {
    const result: PocHarnessResult = {
      fingerprint: "abc123",
      scriptPath: "/tmp/repo/.kuzushi/poc/abc123-cwe89.ts",
      language: "typescript",
      scriptContent: "console.log('PASS')",
      parsed: true,
      parseError: null,
      skipped: false,
      skipReason: null,
      costUsd: 0.01,
    };
    expect(result.parsed).toBe(true);
  });

  it("Finding metadata schema accepts blame fields persisted by the store", () => {
    const parsed = FindingMetadataSchema.parse({
      latestDynamicStatus: "confirmed",
      blame: { sha: "abc", author: "Ada", date: "2026-04-24", summary: "fix auth" },
      introducedIn: "abc",
    });
    expect(parsed.blame?.author).toBe("Ada");
  });

  it("FindingRow schema includes metadata JSON persisted by SQLite rows", () => {
    const parsed = FindingRowSchema.parse({
      taskId: "semgrep",
      fingerprint: "abc123",
      repo: "repo",
      ref: "HEAD",
      ruleId: "test.rule",
      filePath: "src/app.ts",
      startLine: 1,
      severity: "ERROR",
      message: "test",
      verdict: "needs_review",
      confidence: 0.5,
      rationale: "needs review",
      verificationSteps: "[]",
      fixPatch: null,
      findingMetadataJson: '{"introducedIn":"abc"}',
      createdAt: "2026-04-24T00:00:00.000Z",
      updatedAt: "2026-04-24T00:00:00.000Z",
    });
    expect(parsed.findingMetadataJson).toContain("introducedIn");
  });
});
