import { describe, expect, it } from "vitest";
import { analyzePrompt, formatPromptReport } from "../../src/prompts/prompt-report.js";

describe("analyzePrompt", () => {
  it("measures a simple prompt as a single section", () => {
    const prompt = "You are a security analyst. Analyze the finding.";
    const report = analyzePrompt(prompt);
    expect(report.sections).toHaveLength(1);
    expect(report.totalChars).toBe(prompt.length);
    expect(report.totalEstimatedTokens).toBeGreaterThan(0);
  });

  it("splits prompt into sections by markdown headers", () => {
    const prompt = [
      "Preamble text",
      "",
      "## Instructions",
      "",
      "Do the analysis.",
      "",
      "## Schema",
      "",
      "Return JSON.",
    ].join("\n");

    const report = analyzePrompt(prompt);
    expect(report.sections.length).toBeGreaterThanOrEqual(2);
  });

  it("emits warning when prompt exceeds threshold", () => {
    const longPrompt = "x".repeat(50_000);
    const report = analyzePrompt(longPrompt, 1000);
    expect(report.warnings.length).toBeGreaterThan(0);
    expect(report.warnings[0]).toContain("exceeds");
  });

  it("calculates estimated tokens as roughly chars/4", () => {
    const prompt = "a".repeat(400);
    const report = analyzePrompt(prompt);
    expect(report.totalEstimatedTokens).toBe(100);
  });

  it("handles empty prompt", () => {
    const report = analyzePrompt("");
    expect(report.sections).toHaveLength(1);
    expect(report.totalChars).toBe(0);
  });
});

describe("formatPromptReport", () => {
  it("produces human-readable output", () => {
    const report = analyzePrompt("## Section A\nContent A\n## Section B\nContent B");
    const formatted = formatPromptReport(report);
    expect(formatted).toContain("Prompt Report:");
    expect(formatted).toContain("estimated tokens");
  });
});
