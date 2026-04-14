import { describe, expect, it } from "vitest";
import { selectTopFindings } from "../src/scanners/finding-selection.js";
import type { Finding } from "../src/scanners/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    taskId: "semgrep",
    fingerprint: "fp-default",
    ruleId: "javascript.security.audit.sql-injection",
    filePath: "src/app.ts",
    startLine: 12,
    severity: "ERROR",
    message: "Potential SQL injection",
    evidence: null,
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 80,
    ...overrides,
  };
}

describe("selectTopFindings", () => {
  it("deduplicates exact fingerprints and keeps highest score", () => {
    const findings = [
      makeFinding({ fingerprint: "fp-1", score: 30, message: "lower score" }),
      makeFinding({ fingerprint: "fp-1", score: 75, message: "higher score" }),
    ];

    const selected = selectTopFindings(findings);
    expect(selected).toHaveLength(1);
    expect(selected[0].score).toBe(75);
    expect(selected[0].message).toBe("higher score");
  });

  it("deduplicates cross-scanner findings by location and CWE", () => {
    const semgrepFinding = makeFinding({
      taskId: "semgrep",
      fingerprint: "fp-semgrep",
      ruleId: "semgrep.sql-injection",
      filePath: "src/db.ts",
      startLine: 44,
      score: 70,
      cwe: ["CWE-89"],
    });
    const codeqlFinding = makeFinding({
      taskId: "codeql",
      fingerprint: "fp-codeql",
      ruleId: "js/sql-injection",
      filePath: "/src/db.ts",
      startLine: 44,
      score: 88,
      cwe: ["CWE-89"],
    });

    const selected = selectTopFindings([semgrepFinding, codeqlFinding]);
    expect(selected).toHaveLength(1);
    expect(selected[0].fingerprint).toBe("fp-codeql");
  });

  it("deduplicates cross-scanner findings by location and normalized rule id when CWE is missing", () => {
    const semgrepFinding = makeFinding({
      taskId: "semgrep",
      fingerprint: "fp-semgrep",
      ruleId: "javascript.lang.security.audit.path-traversal",
      filePath: "src/fs.ts",
      startLine: 7,
      cwe: [],
      score: 61,
    });
    const codeqlFinding = makeFinding({
      taskId: "codeql",
      fingerprint: "fp-codeql",
      ruleId: "js/path-traversal",
      filePath: "src/fs.ts",
      startLine: 7,
      cwe: [],
      score: 74,
    });

    const selected = selectTopFindings([semgrepFinding, codeqlFinding]);
    expect(selected).toHaveLength(1);
    expect(selected[0].fingerprint).toBe("fp-codeql");
  });

  it("deduplicates by pure CWE key even when rule ids differ", () => {
    const semgrepFinding = makeFinding({
      taskId: "semgrep",
      fingerprint: "fp-semgrep-cwe",
      ruleId: "semgrep.ssti.unsafe-template",
      filePath: "src/template.ts",
      startLine: 27,
      message: "Template injection risk",
      cwe: ["CWE-94"],
      score: 67,
    });
    const codeqlFinding = makeFinding({
      taskId: "codeql",
      fingerprint: "fp-codeql-cwe",
      ruleId: "js/code-injection",
      filePath: "/src/template.ts",
      startLine: 27,
      message: "Untrusted data reaches eval-like sink",
      cwe: ["CWE-94"],
      score: 82,
    });

    const selected = selectTopFindings([semgrepFinding, codeqlFinding]);
    expect(selected).toHaveLength(1);
    expect(selected[0].fingerprint).toBe("fp-codeql-cwe");
  });

  it("falls back to message dedupe when rule id has only stop words and CWE is empty", () => {
    const first = makeFinding({
      taskId: "semgrep",
      fingerprint: "fp-stop-1",
      ruleId: "security.audit.rule",
      filePath: "src/auth.ts",
      startLine: 19,
      message: "User input reaches dangerous sink",
      cwe: [],
      score: 60,
    });
    const second = makeFinding({
      taskId: "codeql",
      fingerprint: "fp-stop-2",
      ruleId: "js/security/audit/rule",
      filePath: "src/auth.ts",
      startLine: 19,
      message: "User input reaches dangerous sink",
      cwe: [],
      score: 78,
    });

    const selected = selectTopFindings([first, second]);
    expect(selected).toHaveLength(1);
    expect(selected[0].fingerprint).toBe("fp-stop-2");
  });

  it("does not dedupe genuinely different findings at the same line", () => {
    const sql = makeFinding({
      taskId: "semgrep",
      fingerprint: "fp-diff-1",
      ruleId: "semgrep.sql-injection",
      filePath: "src/handler.ts",
      startLine: 10,
      message: "Potential SQL injection",
      cwe: [],
      score: 65,
    });
    const xss = makeFinding({
      taskId: "codeql",
      fingerprint: "fp-diff-2",
      ruleId: "js/xss",
      filePath: "src/handler.ts",
      startLine: 10,
      message: "Potential cross-site scripting",
      cwe: [],
      score: 70,
    });

    const selected = selectTopFindings([sql, xss]);
    expect(selected).toHaveLength(2);
  });

  it("respects maxFindings after dedupe", () => {
    const selected = selectTopFindings(
      [
        makeFinding({ fingerprint: "fp-1", filePath: "a.ts", startLine: 1, score: 90, cwe: ["CWE-79"] }),
        makeFinding({ fingerprint: "fp-2", filePath: "b.ts", startLine: 2, score: 85, cwe: ["CWE-79"] }),
        makeFinding({ fingerprint: "fp-3", filePath: "c.ts", startLine: 3, score: 80, cwe: ["CWE-79"] }),
      ],
      2,
    );

    expect(selected).toHaveLength(2);
    expect(selected[0].score).toBeGreaterThanOrEqual(selected[1].score);
  });
});
