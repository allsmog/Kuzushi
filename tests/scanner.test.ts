import { describe, it, expect } from "vitest";
import { scoreFinding, computeFingerprint, selectFindings, type SemgrepResult, type SemgrepOutput } from "../src/scanner.js";

function makeFinding(overrides: Partial<SemgrepResult> = {}): SemgrepResult {
  return {
    check_id: "javascript.express.security.audit.xss",
    path: "src/app.ts",
    start: { line: 42, col: 1 },
    end: { line: 42, col: 50 },
    extra: {
      severity: "ERROR",
      message: "Potential XSS vulnerability",
      lines: "res.send(userInput)",
      metadata: {
        confidence: "HIGH",
        subcategory: ["vuln"],
        likelihood: "HIGH",
        impact: "HIGH",
        cwe: ["CWE-79"],
      },
    },
    ...overrides,
  };
}

describe("scoreFinding", () => {
  it("scores a high-severity vuln finding as 54", () => {
    // ERROR(3) * HIGH(3) * HIGH(3) * vuln(2) = 54
    const finding = makeFinding();
    expect(scoreFinding(finding)).toBe(54);
  });

  it("scores a low-severity audit finding as 1", () => {
    const finding = makeFinding({
      extra: {
        severity: "INFO",
        message: "audit note",
        metadata: {
          likelihood: "LOW",
          impact: "LOW",
          subcategory: ["audit"],
        },
      },
    });
    // INFO(1) * LOW(1) * LOW(1) * audit(1) = 1
    expect(scoreFinding(finding)).toBe(1);
  });

  it("uses defaults for missing metadata", () => {
    const finding: SemgrepResult = {
      check_id: "test.rule",
      path: "test.ts",
      start: { line: 1, col: 1 },
      end: { line: 1, col: 10 },
    };
    // INFO(1) * LOW(1) * LOW(1) * audit(1) = 1
    expect(scoreFinding(finding)).toBe(1);
  });

  it("scores WARNING/MEDIUM correctly", () => {
    const finding = makeFinding({
      extra: {
        severity: "WARNING",
        message: "test",
        metadata: {
          likelihood: "MEDIUM",
          impact: "MEDIUM",
          subcategory: ["vuln"],
        },
      },
    });
    // WARNING(2) * MEDIUM(2) * MEDIUM(2) * vuln(2) = 16
    expect(scoreFinding(finding)).toBe(16);
  });
});

describe("computeFingerprint", () => {
  it("returns a 64-char hex string", () => {
    const fp = computeFingerprint("my-repo", "HEAD", makeFinding());
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic for same inputs", () => {
    const finding = makeFinding();
    const fp1 = computeFingerprint("repo", "main", finding);
    const fp2 = computeFingerprint("repo", "main", finding);
    expect(fp1).toBe(fp2);
  });

  it("differs for different repos", () => {
    const finding = makeFinding();
    const fp1 = computeFingerprint("repo-a", "HEAD", finding);
    const fp2 = computeFingerprint("repo-b", "HEAD", finding);
    expect(fp1).not.toBe(fp2);
  });

  it("falls back to start_line when lines is empty", () => {
    const finding = makeFinding({
      extra: {
        severity: "ERROR",
        message: "test",
        lines: "",
        metadata: {},
      },
    });
    const fp = computeFingerprint("repo", "HEAD", finding);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });

  it('falls back to start_line when lines is "requires login"', () => {
    const finding = makeFinding({
      extra: {
        severity: "ERROR",
        message: "test",
        lines: "requires login",
        metadata: {},
      },
    });
    const fp = computeFingerprint("repo", "HEAD", finding);
    expect(fp).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("selectFindings", () => {
  it("returns ranked findings", () => {
    const output: SemgrepOutput = {
      results: [
        makeFinding({ check_id: "low-sev", extra: { severity: "INFO", message: "low", metadata: {} } }),
        makeFinding({ check_id: "high-sev" }),
      ],
    };
    const selected = selectFindings(output, "repo", "HEAD");
    expect(selected.length).toBe(2);
    // Highest score first
    expect(selected[0].score).toBeGreaterThanOrEqual(selected[1].score);
  });

  it("deduplicates by fingerprint keeping highest score", () => {
    const finding = makeFinding();
    const output: SemgrepOutput = {
      results: [finding, finding], // duplicate
    };
    const selected = selectFindings(output, "repo", "HEAD");
    expect(selected.length).toBe(1);
  });

  it("respects maxFindings", () => {
    const output: SemgrepOutput = {
      results: Array.from({ length: 10 }, (_, i) =>
        makeFinding({ check_id: `rule-${i}`, path: `file-${i}.ts` }),
      ),
    };
    const selected = selectFindings(output, "repo", "HEAD", 3);
    expect(selected.length).toBe(3);
  });

  it("handles empty results", () => {
    const output: SemgrepOutput = { results: [] };
    const selected = selectFindings(output, "repo", "HEAD");
    expect(selected).toEqual([]);
  });

  it("maps all fields correctly", () => {
    const output: SemgrepOutput = { results: [makeFinding()] };
    const [f] = selectFindings(output, "repo", "HEAD");
    expect(f.ruleId).toBe("javascript.express.security.audit.xss");
    expect(f.filePath).toBe("src/app.ts");
    expect(f.startLine).toBe(42);
    expect(f.severity).toBe("ERROR");
    expect(f.semgrepConfidence).toBe("HIGH");
    expect(f.cwe).toEqual(["CWE-79"]);
    expect(f.fingerprint).toMatch(/^[0-9a-f]{64}$/);
  });
});
