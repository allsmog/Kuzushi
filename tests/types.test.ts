import { describe, it, expect } from "vitest";
import type { RepoContext, Verdict, TriageResult, ScanOpts } from "../src/types.js";
import type { Finding } from "../src/scanners/types.js";

describe("types", () => {
  it("Verdict accepts valid values", () => {
    const verdicts: Verdict[] = ["tp", "fp", "needs_review"];
    expect(verdicts).toHaveLength(3);
  });

  it("Finding shape is constructible", () => {
    const finding: Finding = {
      scanner: "semgrep",
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
      verdict: "fp",
      confidence: 0.95,
      rationale: "safe",
      verificationSteps: ["check code"],
      fixPatch: null,
    };
    expect(result.verdict).toBe("fp");
  });

  it("ScanOpts shape is constructible", () => {
    const opts: ScanOpts = {
      severity: ["ERROR"],
      maxFindings: 10,
      excludePatterns: ["node_modules"],
      scanners: ["semgrep"],
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
});
