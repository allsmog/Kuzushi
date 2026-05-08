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

  it("applies CWE frequency multiplier for SQLi (CWE-89)", () => {
    const withCwe = scoreFindingMetadata({
      severity: "ERROR",
      likelihood: "HIGH",
      impact: "HIGH",
      subcategory: ["vuln"],
      cwe: ["CWE-89"],
    });
    const withoutCwe = scoreFindingMetadata({
      severity: "ERROR",
      likelihood: "HIGH",
      impact: "HIGH",
      subcategory: ["vuln"],
    });
    // SQLi multiplier is 1.3, so score should be higher
    expect(withCwe).toBeGreaterThan(withoutCwe);
    expect(withCwe).toBeCloseTo(54 * 1.3, 2);
  });

  it("SQLi findings score higher than path traversal at same severity", () => {
    const sqliScore = scoreFindingMetadata({
      severity: "ERROR",
      likelihood: "HIGH",
      impact: "HIGH",
      subcategory: ["vuln"],
      cwe: ["89"],
    });
    const pathTraversalScore = scoreFindingMetadata({
      severity: "ERROR",
      likelihood: "HIGH",
      impact: "HIGH",
      subcategory: ["vuln"],
      cwe: ["22"],
    });
    expect(sqliScore).toBeGreaterThan(pathTraversalScore);
  });

  it("uses highest multiplier when multiple CWEs present", () => {
    const score = scoreFindingMetadata({
      severity: "WARNING",
      likelihood: "MEDIUM",
      impact: "MEDIUM",
      subcategory: ["vuln"],
      cwe: ["CWE-22", "CWE-89"], // 1.05 and 1.3
    });
    // Should use 1.3 (highest)
    expect(score).toBeCloseTo(16 * 1.3, 2);
  });

  it("defaults to 1.0 multiplier for unknown CWEs", () => {
    const knownScore = scoreFindingMetadata({
      severity: "WARNING",
      likelihood: "MEDIUM",
      impact: "MEDIUM",
      subcategory: ["vuln"],
    });
    const unknownCweScore = scoreFindingMetadata({
      severity: "WARNING",
      likelihood: "MEDIUM",
      impact: "MEDIUM",
      subcategory: ["vuln"],
      cwe: ["CWE-999"],
    });
    expect(unknownCweScore).toBe(knownScore);
  });

  it("applies parameter risk boost additively", () => {
    const baseScore = scoreFindingMetadata({
      severity: "WARNING",
      likelihood: "MEDIUM",
      impact: "MEDIUM",
      subcategory: ["vuln"],
    });
    const boostedScore = scoreFindingMetadata({
      severity: "WARNING",
      likelihood: "MEDIUM",
      impact: "MEDIUM",
      subcategory: ["vuln"],
      parameterRiskBoost: 0.15,
    });
    expect(boostedScore).toBeGreaterThan(baseScore);
    expect(boostedScore).toBe(baseScore + 0.15 * 10);
  });
});
