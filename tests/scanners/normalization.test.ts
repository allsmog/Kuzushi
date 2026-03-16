import { describe, expect, it } from "vitest";
import {
  applyRescoreResults,
  capFindingsForTriage,
  clusterFindings,
  selectFindingsForRescore,
} from "../../src/scanners/normalization.js";
import type { Finding } from "../../src/scanners/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    scanner: "semgrep",
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

describe("normalization pipeline", () => {
  it("clusters cross-scanner duplicates and preserves corroborating signals", () => {
    const semgrepFinding = makeFinding({
      scanner: "semgrep",
      fingerprint: "fp-semgrep",
      filePath: "src/db.ts",
      startLine: 44,
      score: 70,
      cwe: ["CWE-89"],
    });
    const codeqlFinding = makeFinding({
      scanner: "codeql",
      fingerprint: "fp-codeql",
      ruleId: "js/sql-injection",
      filePath: "/src/db.ts",
      startLine: 44,
      score: 88,
      cwe: ["CWE-89"],
    });

    const clustered = clusterFindings([semgrepFinding, codeqlFinding]);
    expect(clustered.findings).toHaveLength(1);
    expect(clustered.corroboratedClusters).toBe(1);
    expect(clustered.findings[0].fingerprint).toBe("fp-codeql");
    expect(clustered.findings[0].corroboratingSignals).toEqual([
      expect.objectContaining({
        fingerprint: "fp-semgrep",
        scanner: "semgrep",
      }),
    ]);
  });

  it("bounds LLM rescore to top 2x maxFindings and applies the final cap afterward", () => {
    const findings = [
      makeFinding({ fingerprint: "fp-1", score: 90 }),
      makeFinding({ fingerprint: "fp-2", score: 85 }),
      makeFinding({ fingerprint: "fp-3", score: 80 }),
      makeFinding({ fingerprint: "fp-4", score: 75 }),
      makeFinding({ fingerprint: "fp-5", score: 70 }),
    ];

    const rescoreWindow = selectFindingsForRescore(findings, 2);
    expect(rescoreWindow.map((finding) => finding.fingerprint)).toEqual([
      "fp-1",
      "fp-2",
      "fp-3",
      "fp-4",
    ]);

    const applied = applyRescoreResults(findings, [
      { fingerprint: "fp-2", score: 2, reason: "discard", keep: false },
      { fingerprint: "fp-3", score: 3, reason: "discard", keep: false },
    ]);
    const capped = capFindingsForTriage(applied.findings, 2);
    expect(applied.skippedByLlmRescore).toBe(2);
    expect(capped.map((finding) => finding.fingerprint)).toEqual(["fp-1", "fp-4"]);
  });
});
