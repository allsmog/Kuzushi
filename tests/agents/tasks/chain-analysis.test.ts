import { describe, it, expect } from "vitest";
import { __chainAnalysisInternals } from "../../../src/agents/tasks/chain-analysis.js";
import type { Finding } from "../../../src/scanners/types.js";
import type { TriageResult } from "../../../src/types.js";

const { buildPrompt, parseOutput } = __chainAnalysisInternals;

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    scanner: "test",
    fingerprint: "fp-" + Math.random().toString(36).slice(2, 8),
    ruleId: "test/rule",
    filePath: "src/app.ts",
    startLine: 10,
    severity: "WARNING",
    message: "Test finding",
    evidence: null,
    scannerConfidence: "MEDIUM",
    subcategory: ["vuln"],
    likelihood: "MEDIUM",
    impact: "MEDIUM",
    cwe: [],
    score: 4,
    ...overrides,
  };
}

function makeTriageResult(overrides: Partial<TriageResult> = {}): TriageResult {
  return {
    fingerprint: "fp-test",
    verdict: "tp",
    confidence: 0.8,
    rationale: "Confirmed vulnerable",
    verificationSteps: ["step1"],
    fixPatch: null,
    ...overrides,
  };
}

describe("buildPrompt", () => {
  it("includes all confirmed findings in the prompt", () => {
    const findings = [
      { finding: makeFinding({ fingerprint: "fp-1", ruleId: "sqli/unsafe" }), triageResult: makeTriageResult() },
      { finding: makeFinding({ fingerprint: "fp-2", ruleId: "ssrf/fetch" }), triageResult: makeTriageResult() },
    ];

    const prompt = buildPrompt(findings, "test-repo");

    expect(prompt).toContain("fp-1");
    expect(prompt).toContain("fp-2");
    expect(prompt).toContain("sqli/unsafe");
    expect(prompt).toContain("ssrf/fetch");
    expect(prompt).toContain("test-repo");
    expect(prompt).toContain("Chain Detection Patterns");
    expect(prompt).toContain("at least 2");
  });
});

describe("parseOutput", () => {
  it("parses valid chain analysis output", () => {
    const raw = {
      chains: [
        {
          id: "chain-1",
          name: "SQLi to Config Leak",
          steps: [
            { finding_fingerprint: "fp-1", role: "initial access", description: "SQL injection extracts config" },
            { finding_fingerprint: "fp-2", role: "escalation", description: "Config reveals admin creds" },
          ],
          overall_severity: "CRITICAL",
          preconditions: ["Database accessible"],
          impact_description: "Full system compromise",
        },
      ],
      analysis_notes: "One chain found",
    };

    const result = parseOutput(raw);
    expect(result.chains).toHaveLength(1);
    expect(result.chains[0].name).toBe("SQLi to Config Leak");
    expect(result.chains[0].steps).toHaveLength(2);
    expect(result.chains[0].overallSeverity).toBe("CRITICAL");
    expect(result.analysisNotes).toBe("One chain found");
  });

  it("rejects chains with fewer than 2 steps", () => {
    const raw = {
      chains: [
        {
          id: "chain-1",
          name: "Single step",
          steps: [{ finding_fingerprint: "fp-1", role: "solo", description: "alone" }],
          overall_severity: "HIGH",
          preconditions: [],
          impact_description: "limited",
        },
      ],
      analysis_notes: "filtered",
    };

    const result = parseOutput(raw);
    expect(result.chains).toHaveLength(0);
  });

  it("handles invalid input gracefully", () => {
    const result = parseOutput("not an object");
    expect(result.chains).toEqual([]);
  });

  it("normalizes invalid severity to MEDIUM", () => {
    const raw = {
      chains: [
        {
          id: "chain-1",
          name: "Test",
          steps: [
            { finding_fingerprint: "fp-1", role: "a", description: "a" },
            { finding_fingerprint: "fp-2", role: "b", description: "b" },
          ],
          overall_severity: "INVALID",
          preconditions: [],
          impact_description: "test",
        },
      ],
      analysis_notes: "",
    };

    const result = parseOutput(raw);
    expect(result.chains[0].overallSeverity).toBe("MEDIUM");
  });
});
