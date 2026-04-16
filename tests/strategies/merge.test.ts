import { describe, expect, it } from "vitest";
import type { Finding } from "../../src/scanners/types.js";
import { mergeStrategyResults } from "../../src/strategies/merge.js";
import type { StrategyResult } from "../../src/strategies/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    taskId: "test",
    fingerprint: "fp-1",
    ruleId: "rule-1",
    filePath: "src/app.ts",
    startLine: 10,
    severity: "ERROR",
    message: "Test finding",
    scannerConfidence: "HIGH",
    subcategory: [],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 15,
    ...overrides,
  };
}

function makeResult(
  kind: "syntactic" | "dataflow" | "reasoning",
  findings: Finding[],
  confidence: number = 0.8,
): StrategyResult {
  return {
    strategyKind: kind,
    strategyId: `${kind}-test`,
    findings,
    confidence,
    costUsd: 0.01,
    durationMs: 100,
    evidence: [{ kind: "pattern-match", description: `${kind} evidence` }],
  };
}

describe("mergeStrategyResults", () => {
  it("returns empty for no results", () => {
    const merged = mergeStrategyResults([]);
    expect(merged.findings).toHaveLength(0);
    expect(merged.strategyAgreement).toBe("single");
    expect(merged.flagForReview).toBe(false);
  });

  it("returns single strategy findings as-is", () => {
    const finding = makeFinding();
    const result = makeResult("syntactic", [finding]);
    const merged = mergeStrategyResults([result]);

    expect(merged.findings).toHaveLength(1);
    expect(merged.findings[0]!.filePath).toBe("src/app.ts");
  });

  it("boosts confidence when multiple strategies agree", () => {
    const f1 = makeFinding({ score: 15 });
    const f2 = makeFinding({ fingerprint: "fp-2", score: 14 }); // same location, different fingerprint

    const r1 = makeResult("syntactic", [f1]);
    const r2 = makeResult("dataflow", [f2]);
    const merged = mergeStrategyResults([r1, r2]);

    // Should be merged into 1 finding with boosted score
    expect(merged.findings).toHaveLength(1);
    expect(merged.findings[0]!.adjustedScore).toBeGreaterThan(15);
  });

  it("detects unanimous agreement across 3+ strategies", () => {
    const finding = makeFinding();
    const r1 = makeResult("syntactic", [finding]);
    const r2 = makeResult("dataflow", [{ ...finding, fingerprint: "fp-2" }]);
    const r3 = makeResult("reasoning", [{ ...finding, fingerprint: "fp-3" }]);

    const merged = mergeStrategyResults([r1, r2, r3]);
    expect(merged.strategyAgreement).toBe("unanimous");
  });

  it("deduplicates findings from different strategies at same location", () => {
    const f1 = makeFinding({ fingerprint: "fp-1" });
    const f2 = makeFinding({ fingerprint: "fp-2" }); // same file:line

    const r1 = makeResult("syntactic", [f1]);
    const r2 = makeResult("dataflow", [f2]);
    const merged = mergeStrategyResults([r1, r2]);

    expect(merged.findings).toHaveLength(1);
    expect(merged.findings[0]!.corroboratingSignals!.length).toBeGreaterThan(0);
  });

  it("keeps findings at different locations separate", () => {
    const f1 = makeFinding({ filePath: "src/a.ts", startLine: 10 });
    const f2 = makeFinding({ filePath: "src/b.ts", startLine: 20, fingerprint: "fp-2" });

    const r1 = makeResult("syntactic", [f1, f2]);
    const merged = mergeStrategyResults([r1]);

    expect(merged.findings).toHaveLength(2);
  });

  it("collects generated rules from all results", () => {
    const r1: StrategyResult = {
      ...makeResult("syntactic", []),
      generatedRules: [
        {
          kind: "semgrep",
          vulnClass: "sqli",
          cweIds: ["CWE-89"],
          ruleContent: "rules: ...",
          description: "test rule",
          sourceFinding: { fingerprint: "fp-1", filePath: "a.ts", startLine: 1 },
        },
      ],
    };

    const merged = mergeStrategyResults([r1]);
    expect(merged.generatedRules).toHaveLength(1);
  });
});
