import { describe, expect, it } from "vitest";
import { parsePatchSynthesisOutput } from "../../src/patch/output-parser.js";

describe("parsePatchSynthesisOutput", () => {
  it("accepts structured output", () => {
    expect(parsePatchSynthesisOutput({ diff: "--- a\n+++ b", explanation: "fixed" })).toEqual({
      diff: "--- a\n+++ b",
      explanation: "fixed",
    });
  });

  it("extracts JSON from response text", () => {
    expect(parsePatchSynthesisOutput('agent said: {"diff":"patch","explanation":"why"}')).toEqual({
      diff: "patch",
      explanation: "why",
    });
  });

  it("rejects empty diffs", () => {
    expect(() => parsePatchSynthesisOutput({ diff: " ", explanation: "empty" })).toThrow(
      "Empty diff",
    );
  });

  it("rejects text without JSON", () => {
    expect(() => parsePatchSynthesisOutput("no json here")).toThrow("Could not extract JSON");
  });
});
