import { describe, expect, it } from "vitest";
import { invariantCheckTask, __invariantCheckInternals } from "../../../../src/agents/tasks/invariant-analysis/check.js";

const { buildCheckPrompt, parseViolations, normalizeViolation, violationToFinding, computeFingerprint } = __invariantCheckInternals;

describe("invariantCheckTask", () => {
  it("has correct metadata", () => {
    expect(invariantCheckTask.id).toBe("invariant-check");
    expect(invariantCheckTask.outputKind).toBe("findings");
    expect(invariantCheckTask.dependsOn).toEqual(["invariant-extract"]);
  });
});

describe("buildCheckPrompt", () => {
  it("includes invariant descriptions", () => {
    const invariants = [
      {
        id: "inv-1",
        kind: "security-invariant" as const,
        scope: { filePath: "src/auth.ts", startLine: 10, endLine: 15 },
        statement: "User must be authenticated",
        confidence: 0.9,
        derivedFrom: "middleware",
        securityRelevance: "high" as const,
      },
    ];

    const prompt = buildCheckPrompt(invariants);
    expect(prompt).toContain("inv-1");
    expect(prompt).toContain("User must be authenticated");
    expect(prompt).toContain("src/auth.ts:10");
  });
});

describe("parseViolations", () => {
  it("parses valid violations", () => {
    const raw = {
      violations: [
        {
          invariantId: "inv-1",
          invariantStatement: "User must be authenticated",
          violatingFilePath: "src/routes/public.ts",
          violatingStartLine: 42,
          violationDescription: "Endpoint skips auth middleware",
          severity: "ERROR",
          confidence: 0.85,
          cwe: "862",
          attackScenario: "Unauthenticated access to admin route",
        },
      ],
    };

    const violations = parseViolations(raw, 0.6);
    expect(violations).toHaveLength(1);
    expect(violations[0].invariantId).toBe("inv-1");
    expect(violations[0].severity).toBe("ERROR");
    expect(violations[0].cwe).toBe("862");
  });

  it("filters low-confidence violations", () => {
    const raw = {
      violations: [
        { invariantId: "inv-1", invariantStatement: "x", violatingFilePath: "a.ts", violatingStartLine: 1, violationDescription: "y", severity: "WARNING", confidence: 0.3 },
        { invariantId: "inv-2", invariantStatement: "x", violatingFilePath: "b.ts", violatingStartLine: 1, violationDescription: "y", severity: "WARNING", confidence: 0.8 },
      ],
    };

    const violations = parseViolations(raw, 0.6);
    expect(violations).toHaveLength(1);
    expect(violations[0].invariantId).toBe("inv-2");
  });

  it("returns empty for invalid input", () => {
    expect(parseViolations(null, 0.6)).toEqual([]);
    expect(parseViolations({ violations: "not-array" }, 0.6)).toEqual([]);
  });
});

describe("normalizeViolation", () => {
  it("returns null for missing required fields", () => {
    expect(normalizeViolation({})).toBeNull();
    expect(normalizeViolation({ invariantId: "inv-1" })).toBeNull();
  });

  it("returns null for empty invariantStatement", () => {
    expect(normalizeViolation({
      invariantId: "inv-1",
      invariantStatement: "",
      violatingFilePath: "a.ts",
      violatingStartLine: 1,
      violationDescription: "desc",
      severity: "ERROR",
      confidence: 0.9,
    })).toBeNull();
  });

  it("normalizes valid violation", () => {
    const v = normalizeViolation({
      invariantId: "inv-1",
      invariantStatement: "Auth required",
      violatingFilePath: "src/api.ts",
      violatingStartLine: 10,
      violationDescription: "No auth check",
      severity: "ERROR",
      confidence: 0.9,
      cwe: "862",
    });

    expect(v).not.toBeNull();
    expect(v!.severity).toBe("ERROR");
    expect(v!.confidence).toBe(0.9);
  });

  it("defaults invalid severity to WARNING", () => {
    const v = normalizeViolation({
      invariantId: "inv-1",
      invariantStatement: "x",
      violatingFilePath: "a.ts",
      violatingStartLine: 1,
      violationDescription: "y",
      severity: "CRITICAL",
      confidence: 0.5,
    });

    expect(v!.severity).toBe("WARNING");
  });
});

describe("violationToFinding", () => {
  it("converts violation to Finding", () => {
    const violation = {
      invariantId: "inv-1",
      invariantStatement: "User must be authenticated",
      violatingFilePath: "src/api.ts",
      violatingStartLine: 10,
      violationDescription: "No auth check",
      severity: "ERROR" as const,
      confidence: 0.9,
      cwe: "862",
      attackScenario: "Bypass auth",
    };

    const finding = violationToFinding(violation, "/tmp/repo", "test-repo");
    expect(finding.taskId).toBe("invariant-check");
    expect(finding.ruleId).toBe("invariant/inv-1/862");
    expect(finding.filePath).toBe("src/api.ts");
    expect(finding.startLine).toBe(10);
    expect(finding.severity).toBe("ERROR");
    expect(finding.message).toContain("User must be authenticated");
    expect(finding.evidence).toBe("Bypass auth");
    expect(finding.cwe).toEqual(["862"]);
  });

  it("handles violation without CWE", () => {
    const violation = {
      invariantId: "inv-2",
      invariantStatement: "Input is validated",
      violatingFilePath: "src/handler.ts",
      violatingStartLine: 5,
      violationDescription: "Raw input used",
      severity: "WARNING" as const,
      confidence: 0.7,
    };

    const finding = violationToFinding(violation, "/tmp/repo", "test-repo");
    expect(finding.ruleId).toBe("invariant/inv-2");
    expect(finding.cwe).toEqual([]);
  });
});

describe("computeFingerprint", () => {
  it("produces stable fingerprints", () => {
    const v = { invariantId: "inv-1", invariantStatement: "", violatingFilePath: "a.ts", violatingStartLine: 10, violationDescription: "", severity: "ERROR" as const, confidence: 0.9 };
    const fp1 = computeFingerprint("repo", "a.ts", v);
    const fp2 = computeFingerprint("repo", "a.ts", v);
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64);
  });
});

describe("triageAgentConfig", () => {
  it("returns a prompt mentioning invariant verification", () => {
    const finding = {
      taskId: "invariant-check",
      fingerprint: "abc",
      ruleId: "invariant/inv-1/862",
      filePath: "src/api.ts",
      startLine: 10,
      severity: "ERROR",
      message: 'Invariant violation: "User must be authenticated"',
      evidence: "Bypass auth",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["862"],
      score: 54,
    };

    const config = invariantCheckTask.triageAgentConfig!(finding, "test-repo");
    expect(config.prompt).toContain("invariant");
    expect(config.prompt).toContain("violation is reachable");
  });
});
