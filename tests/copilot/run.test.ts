import { describe, it, expect } from "vitest";
import { parseToolArgs } from "../../src/copilot/run.js";

describe("parseToolArgs", () => {
  it("treats bare positional as target", () => {
    expect(parseToolArgs(["./repo"])).toEqual({ target: "./repo" });
  });

  it("parses key=value string", () => {
    expect(parseToolArgs(["preset=deep"])).toEqual({ preset: "deep" });
  });

  it("parses boolean values", () => {
    expect(parseToolArgs(["verify=true", "autoPatch=false"])).toEqual({
      verify: true,
      autoPatch: false,
    });
  });

  it("parses comma-separated values as arrays", () => {
    expect(parseToolArgs(["severity=critical,high"])).toEqual({
      severity: ["critical", "high"],
    });
  });

  it("parses integer values", () => {
    expect(parseToolArgs(["max=50"])).toEqual({ max: 50 });
  });

  it("parses float values", () => {
    expect(parseToolArgs(["budget=2.50"])).toEqual({ budget: 2.5 });
  });

  it("handles mixed positional + key=value", () => {
    expect(parseToolArgs(["./repo", "preset=deep", "verify=true"])).toEqual({
      target: "./repo",
      preset: "deep",
      verify: true,
    });
  });

  it("handles empty args", () => {
    expect(parseToolArgs([])).toEqual({});
  });

  it("only uses first bare positional as target", () => {
    expect(parseToolArgs(["./repo", "./other"])).toEqual({ target: "./repo" });
  });
});
