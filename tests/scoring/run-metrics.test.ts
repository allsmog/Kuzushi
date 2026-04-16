import { describe, expect, it } from "vitest";
import type { Finding } from "../../src/scanners/types.js";
import type { StageCosts, StageTimestamps } from "../../src/scoring/run-metrics.js";
import { computeRunMetrics, formatMetricsSummary } from "../../src/scoring/run-metrics.js";

function makeTimestamps(): StageTimestamps {
  return {
    pipelineStart: "2026-03-20T10:00:00Z",
    pipelineEnd: "2026-03-20T10:05:00Z",
    scanStart: "2026-03-20T10:00:01Z",
    scanEnd: "2026-03-20T10:01:00Z",
    triageStart: "2026-03-20T10:01:01Z",
    triageEnd: "2026-03-20T10:03:00Z",
    verifyStart: "2026-03-20T10:03:01Z",
    verifyEnd: "2026-03-20T10:04:30Z",
  };
}

function makeCosts(): StageCosts {
  return {
    triage: 0.05,
    verify: 0.12,
    pocHarness: 0.03,
    dynamicAnalysis: 0,
    variantAnalysis: 0.01,
  };
}

function makeFinding(
  overrides: Partial<Finding> & {
    verdict?: string;
    confidence?: number;
    verifyExploitable?: boolean | number;
  } = {},
): Finding {
  return {
    taskId: "agentic",
    fingerprint: `fp-${Math.random().toString(36).slice(2, 8)}`,
    ruleId: "test.rule",
    filePath: "src/test.ts",
    startLine: 10,
    severity: "ERROR",
    message: "test",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-79"],
    score: 70,
    ...overrides,
  } as Finding;
}

describe("computeRunMetrics", () => {
  it("propagates corroborated clusters from pipeline stats", () => {
    const metrics = computeRunMetrics([], makeTimestamps(), makeCosts(), {
      corroboratedClusters: 5,
    });
    expect(metrics.corroboratedClusters).toBe(5);
  });

  it("computes verification outcomes from pipeline stats", () => {
    const findings = [
      makeFinding({ verifyExploitable: true }),
      makeFinding({ verifyExploitable: false }),
      makeFinding({ verifyExploitable: false }),
    ];
    const metrics = computeRunMetrics(findings, makeTimestamps(), makeCosts(), {
      verified: 3,
      verifyErrors: 1,
    });
    expect(metrics.verificationOutcomes).toEqual({
      exploitable: 1,
      notExploitable: 2,
      errors: 1,
    });
  });

  it("computes PoC outcomes from pipeline stats", () => {
    const metrics = computeRunMetrics([], makeTimestamps(), makeCosts(), {
      pocHarnessGenerated: 8,
      pocHarnessSkipped: 2,
      pocHarnessErrors: 1,
    });
    expect(metrics.pocOutcomes).toEqual({
      generated: 8,
      skipped: 2,
      errors: 1,
    });
  });

  it("omits verification/poc outcomes when stats are zero/absent", () => {
    const metrics = computeRunMetrics([], makeTimestamps(), makeCosts());
    expect(metrics.verificationOutcomes).toBeUndefined();
    expect(metrics.pocOutcomes).toBeUndefined();
  });
});

describe("formatMetricsSummary", () => {
  it("includes pipeline quality stats in formatted output", () => {
    const metrics = computeRunMetrics([], makeTimestamps(), makeCosts(), {
      corroboratedClusters: 3,
      pocHarnessGenerated: 5,
      pocHarnessSkipped: 1,
      pocHarnessErrors: 0,
    });
    const summary = formatMetricsSummary(metrics);
    expect(summary).toContain("Corroborated Clusters: 3");
    expect(summary).toContain("PoC Generation: 5 generated, 1 skipped, 0 errors");
  });
});
