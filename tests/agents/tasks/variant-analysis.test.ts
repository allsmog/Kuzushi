import { describe, expect, it } from "vitest";
import { __variantAnalysisInternals } from "../../../src/agents/tasks/variant-analysis.js";
import type { Finding } from "../../../src/scanners/types.js";

const { buildPrompt, normalizeVariants, computeFingerprint } = __variantAnalysisInternals;

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    taskId: "test",
    fingerprint: "abc123",
    ruleId: "sql-injection/parameterized",
    filePath: "src/api/users.ts",
    startLine: 42,
    severity: "ERROR",
    message: "SQL injection in user query",
    evidence: "User input concatenated into SQL string",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["89"],
    score: 54,
    ...overrides,
  };
}

describe("buildPrompt", () => {
  it("includes original finding details", () => {
    const finding = makeFinding();
    const triageResult = {
      fingerprint: "abc123",
      verdict: "tp" as const,
      confidence: 0.95,
      rationale: "Confirmed SQL injection",
      verificationSteps: ["Checked query construction"],
      fixPatch: null,
    };

    const prompt = buildPrompt(finding, triageResult);
    expect(prompt).toContain("sql-injection/parameterized");
    expect(prompt).toContain("src/api/users.ts:42");
    expect(prompt).toContain("Confirmed SQL injection");
    expect(prompt).toContain("variant analysis");
  });

  it("includes anti-hallucination constraints", () => {
    const prompt = buildPrompt(makeFinding(), {
      fingerprint: "abc123",
      verdict: "tp" as const,
      confidence: 0.9,
      rationale: "confirmed",
      verificationSteps: [],
      fixPatch: null,
    });
    expect(prompt).toContain("Skip the original file:line");
    expect(prompt).toContain("Do NOT speculate");
  });
});

describe("normalizeVariants", () => {
  const original = makeFinding();

  it("normalizes valid variants", () => {
    const raw = {
      variants: [
        {
          filePath: "src/api/orders.ts",
          startLine: 15,
          severity: "ERROR",
          message: "Same SQL injection pattern in order query",
          confidence: "HIGH",
          rationale: "User input concatenated into SQL string",
        },
      ],
    };

    const variants = normalizeVariants(raw, "/tmp/repo", "test-repo", original, 10);
    expect(variants).toHaveLength(1);
    expect(variants[0].taskId).toBe("variant-analysis");
    expect(variants[0].ruleId).toBe("variant/sql-injection/parameterized");
    expect(variants[0].filePath).toBe("src/api/orders.ts");
  });

  it("skips the original location", () => {
    const raw = {
      variants: [
        {
          filePath: "src/api/users.ts",
          startLine: 42,
          severity: "ERROR",
          message: "Same finding as original",
          confidence: "HIGH",
          rationale: "Duplicate",
        },
      ],
    };

    const variants = normalizeVariants(raw, "/tmp/repo", "test-repo", original, 10);
    expect(variants).toHaveLength(0);
  });

  it("skips LOW confidence variants", () => {
    const raw = {
      variants: [
        {
          filePath: "src/api/products.ts",
          startLine: 5,
          severity: "WARNING",
          message: "Possible variant",
          confidence: "LOW",
          rationale: "Not certain",
        },
      ],
    };

    const variants = normalizeVariants(raw, "/tmp/repo", "test-repo", original, 10);
    expect(variants).toHaveLength(0);
  });

  it("inherits CWE from original when not provided", () => {
    const raw = {
      variants: [
        {
          filePath: "src/api/orders.ts",
          startLine: 15,
          severity: "ERROR",
          message: "Variant found",
          confidence: "HIGH",
          rationale: "Same pattern",
        },
      ],
    };

    const variants = normalizeVariants(raw, "/tmp/repo", "test-repo", original, 10);
    expect(variants[0].cwe).toEqual(["89"]);
  });

  it("returns empty for invalid input", () => {
    expect(normalizeVariants(null, "/tmp/repo", "test-repo", original, 10)).toEqual([]);
    expect(normalizeVariants({}, "/tmp/repo", "test-repo", original, 10)).toEqual([]);
  });

  it("respects maxFindings", () => {
    const raw = {
      variants: Array.from({ length: 10 }, (_, i) => ({
        filePath: `src/file${i}.ts`,
        startLine: 1,
        severity: "ERROR",
        message: `Variant ${i}`,
        confidence: "HIGH",
        rationale: "Same pattern",
      })),
    };

    const variants = normalizeVariants(raw, "/tmp/repo", "test-repo", original, 3);
    expect(variants).toHaveLength(3);
  });
});

describe("computeFingerprint", () => {
  it("produces stable fingerprints", () => {
    const v = {
      filePath: "src/a.ts",
      startLine: 1,
      severity: "ERROR",
      message: "",
      confidence: "HIGH",
      rationale: "",
    };
    const fp1 = computeFingerprint("repo", "src/a.ts", v, "sql-injection");
    const fp2 = computeFingerprint("repo", "src/a.ts", v, "sql-injection");
    expect(fp1).toBe(fp2);
  });

  it("differs by original ruleId", () => {
    const v = {
      filePath: "src/a.ts",
      startLine: 1,
      severity: "ERROR",
      message: "",
      confidence: "HIGH",
      rationale: "",
    };
    const fp1 = computeFingerprint("repo", "src/a.ts", v, "sql-injection");
    const fp2 = computeFingerprint("repo", "src/a.ts", v, "xss");
    expect(fp1).not.toBe(fp2);
  });
});
