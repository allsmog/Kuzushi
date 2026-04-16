import { describe, expect, it } from "vitest";
import { StrategyRegistry } from "../../src/strategies/registry.js";
import type { AnalysisStrategy, StrategyResult } from "../../src/strategies/types.js";

function makeStrategy(
  id: string,
  kind: "syntactic" | "dataflow" | "reasoning" | "execution",
  costTier: number,
  cwes: string[],
): AnalysisStrategy {
  return {
    id,
    kind,
    displayName: id,
    costTier,
    appliesTo(targetCweIds) {
      return targetCweIds.some((cwe) => cwes.includes(cwe));
    },
    async run(): Promise<StrategyResult> {
      return {
        strategyKind: kind,
        strategyId: id,
        findings: [],
        confidence: 0.5,
        costUsd: 0.01,
        durationMs: 100,
        evidence: [],
      };
    },
  };
}

describe("StrategyRegistry", () => {
  it("registers and retrieves strategies", () => {
    const reg = new StrategyRegistry();
    reg.register(makeStrategy("s1", "syntactic", 1, ["CWE-89"]));

    expect(reg.getById("s1")).toBeDefined();
    expect(reg.ids()).toEqual(["s1"]);
  });

  it("throws on duplicate registration", () => {
    const reg = new StrategyRegistry();
    reg.register(makeStrategy("s1", "syntactic", 1, ["CWE-89"]));
    expect(() => reg.register(makeStrategy("s1", "dataflow", 3, ["CWE-89"]))).toThrow(
      /already registered/,
    );
  });

  it("filters by CWE", () => {
    const reg = new StrategyRegistry();
    reg.register(makeStrategy("sqli", "syntactic", 1, ["CWE-89"]));
    reg.register(makeStrategy("xss", "syntactic", 1, ["CWE-79"]));
    reg.register(makeStrategy("ssrf", "dataflow", 3, ["CWE-918"]));

    const sqlStrategies = reg.getForCwe(["CWE-89"]);
    expect(sqlStrategies).toHaveLength(1);
    expect(sqlStrategies[0]!.id).toBe("sqli");
  });

  it("orders by costTier", () => {
    const reg = new StrategyRegistry();
    reg.register(makeStrategy("expensive", "reasoning", 7, ["CWE-89"]));
    reg.register(makeStrategy("cheap", "syntactic", 1, ["CWE-89"]));
    reg.register(makeStrategy("medium", "dataflow", 4, ["CWE-89"]));

    const ordered = reg.getOrderedForCwe(["CWE-89"]);
    expect(ordered.map((s) => s.id)).toEqual(["cheap", "medium", "expensive"]);
  });

  it("returns empty for unknown CWE", () => {
    const reg = new StrategyRegistry();
    reg.register(makeStrategy("s1", "syntactic", 1, ["CWE-89"]));

    expect(reg.getForCwe(["CWE-999"])).toHaveLength(0);
  });
});
