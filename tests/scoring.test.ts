import { describe, expect, it } from "vitest";
import { scoreFindingMetadata } from "../src/scanners/scoring.js";

describe("scoreFindingMetadata", () => {
  it("computes max score for ERROR/HIGH/HIGH/vuln", () => {
    const score = scoreFindingMetadata({
      severity: "ERROR",
      likelihood: "HIGH",
      impact: "HIGH",
      subcategory: ["vuln"],
    });
    // 3 * 3 * 3 * 2 = 54
    expect(score).toBe(54);
  });

  it("computes min score for INFO/LOW/LOW/audit", () => {
    const score = scoreFindingMetadata({
      severity: "INFO",
      likelihood: "LOW",
      impact: "LOW",
      subcategory: ["audit"],
    });
    // 1 * 1 * 1 * 1 = 1
    expect(score).toBe(1);
  });

  it("defaults missing fields to lowest values", () => {
    const score = scoreFindingMetadata({});
    // INFO=1 * LOW=1 * LOW=1 * audit=1 = 1
    expect(score).toBe(1);
  });

  it("normalizes lowercase severity/likelihood/impact", () => {
    const score = scoreFindingMetadata({
      severity: "error",
      likelihood: "high",
      impact: "high",
      subcategory: ["vuln"],
    });
    expect(score).toBe(54);
  });

  it("normalizes mixed-case values", () => {
    const score = scoreFindingMetadata({
      severity: "Warning",
      likelihood: "Medium",
      impact: "Medium",
    });
    // 2 * 2 * 2 * 1(audit default) = 8
    expect(score).toBe(8);
  });

  it("falls back to 1 for unknown severity/likelihood/impact", () => {
    const score = scoreFindingMetadata({
      severity: "CRITICAL",
      likelihood: "VERY_HIGH",
      impact: "CATASTROPHIC",
      subcategory: ["vuln"],
    });
    // 1 * 1 * 1 * 2 = 2
    expect(score).toBe(2);
  });

  it("uses highest subcategory score when multiple are present", () => {
    const score = scoreFindingMetadata({
      severity: "WARNING",
      likelihood: "MEDIUM",
      impact: "MEDIUM",
      subcategory: ["audit", "vuln"],
    });
    // 2 * 2 * 2 * 2(vuln) = 16
    expect(score).toBe(16);
  });
});
