import { describe, expect, it } from "vitest";
import type { StrideThreat } from "../../src/agents/tasks/threat-modeling/types.js";
import {
  cellGlyph,
  computeImpactLikelihoodPivot,
  computeStrideCell,
} from "../../src/ui/components/ThreatStrideMatrix.js";

function mkThreat(partial: Partial<StrideThreat>): StrideThreat {
  return {
    id: partial.id ?? "t1",
    elementId: partial.elementId ?? "E1",
    category: partial.category ?? "spoofing",
    title: partial.title ?? "threat",
    description: "",
    attackVector: "",
    preconditions: [],
    impact: partial.impact ?? "high",
    likelihood: partial.likelihood ?? "medium",
    existingMitigations: [],
    missingMitigations: [],
    relatedCwe: [],
    affectedFiles: [],
  };
}

describe("computeStrideCell", () => {
  it("returns null when no threat matches (element, category)", () => {
    expect(computeStrideCell([], "E1", "spoofing")).toBeNull();
    expect(computeStrideCell([mkThreat({ elementId: "E2" })], "E1", "spoofing")).toBeNull();
  });

  it("returns the single threat's impact when one matches", () => {
    const threats = [mkThreat({ impact: "medium" })];
    expect(computeStrideCell(threats, "E1", "spoofing")).toBe("medium");
  });

  it("returns the WORST impact across multiple matching threats", () => {
    const threats = [
      mkThreat({ id: "a", impact: "low" }),
      mkThreat({ id: "b", impact: "critical" }),
      mkThreat({ id: "c", impact: "medium" }),
    ];
    expect(computeStrideCell(threats, "E1", "spoofing")).toBe("critical");
  });

  it("ignores threats from other categories or elements", () => {
    const threats = [
      mkThreat({ id: "a", elementId: "E1", category: "spoofing", impact: "low" }),
      mkThreat({ id: "b", elementId: "E1", category: "tampering", impact: "critical" }),
      mkThreat({ id: "c", elementId: "E2", category: "spoofing", impact: "high" }),
    ];
    expect(computeStrideCell(threats, "E1", "spoofing")).toBe("low");
  });
});

describe("computeImpactLikelihoodPivot", () => {
  it("counts threats in the correct (impact, likelihood) buckets", () => {
    const pivot = computeImpactLikelihoodPivot([
      mkThreat({ impact: "critical", likelihood: "high" }),
      mkThreat({ impact: "critical", likelihood: "high" }),
      mkThreat({ impact: "high", likelihood: "medium" }),
      mkThreat({ impact: "medium", likelihood: "low" }),
    ]);
    expect(pivot.critical.high).toBe(2);
    expect(pivot.high.medium).toBe(1);
    expect(pivot.medium.low).toBe(1);
    expect(pivot.low.high).toBe(0);
  });

  it("initialises every cell to 0 for an empty input", () => {
    const pivot = computeImpactLikelihoodPivot([]);
    expect(pivot.critical.high).toBe(0);
    expect(pivot.high.high).toBe(0);
    expect(pivot.medium.high).toBe(0);
    expect(pivot.low.high).toBe(0);
  });
});

describe("cellGlyph", () => {
  it("maps each impact tier to a distinct shade glyph", () => {
    expect(cellGlyph("critical")).toBe("█");
    expect(cellGlyph("high")).toBe("▓");
    expect(cellGlyph("medium")).toBe("▒");
    expect(cellGlyph("low")).toBe("░");
    expect(cellGlyph(null)).toBe("·");
  });
});
