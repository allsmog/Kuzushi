import { describe, expect, it } from "vitest";
import {
  classifyError,
  formatError,
  suggestNextStep,
} from "../../src/ui/error-format.js";

describe("classifyError", () => {
  it("classifies 401 as auth", () => {
    const err: Error & { status?: number } = new Error("unauthorized");
    err.status = 401;
    expect(classifyError(err)).toBe("auth");
  });
  it("classifies 429 as rate_limit", () => {
    const err: Error & { status?: number } = new Error("too many requests");
    err.status = 429;
    expect(classifyError(err)).toBe("rate_limit");
  });
  it("classifies budget errors", () => {
    expect(classifyError(new Error("Spend budget exceeded"))).toBe("budget");
  });
  it("classifies transient network errors", () => {
    expect(classifyError(new Error("fetch failed ECONNRESET"))).toBe(
      "transient",
    );
  });
  it("classifies validation errors", () => {
    expect(classifyError(new Error("Zod validation failed"))).toBe("validation");
  });
  it("falls back to unknown", () => {
    expect(classifyError(new Error("???"))).toBe("unknown");
  });
  it("handles non-Error throwables", () => {
    expect(classifyError("boom")).toBe("unknown");
    expect(classifyError(undefined)).toBe("unknown");
    expect(classifyError(null)).toBe("unknown");
  });
});

describe("suggestNextStep", () => {
  it("provides auth hint", () => {
    expect(suggestNextStep(null, "auth")).toContain("ANTHROPIC_API_KEY");
  });
  it("returns undefined for fatal/unknown", () => {
    expect(suggestNextStep(null, "fatal")).toBeUndefined();
    expect(suggestNextStep(null, "unknown")).toBeUndefined();
  });
});

describe("formatError", () => {
  it("caps the headline length", () => {
    const huge = "x".repeat(500);
    const result = formatError(new Error(huge));
    expect(result.headline.length).toBeLessThanOrEqual(200);
  });
  it("parses frames from stack traces", () => {
    const err = new Error("boom");
    err.stack = [
      "Error: boom",
      "    at someFn (/home/user/Kuzushi/src/foo.ts:10:20)",
      "    at other (/home/user/Kuzushi/src/bar.ts:5:1)",
    ].join("\n");
    const out = formatError(err, { maxFrames: 5 });
    expect(out.frames).toHaveLength(2);
    expect(out.frames[0]?.file).toContain("foo.ts");
    expect(out.frames[0]?.line).toBe(10);
  });
  it("skips node-internal frames", () => {
    const err = new Error("boom");
    err.stack = [
      "Error: boom",
      "    at node:internal/x:1:1",
      "    at real (/src/real.ts:1:2)",
    ].join("\n");
    const out = formatError(err);
    expect(out.frames).toHaveLength(1);
    expect(out.frames[0]?.file).toContain("real.ts");
  });
  it("respects maxFrames", () => {
    const err = new Error("boom");
    err.stack =
      "Error: boom\n" +
      Array.from(
        { length: 20 },
        (_, i) => `    at fn${i} (/src/f${i}.ts:1:1)`,
      ).join("\n");
    const out = formatError(err, { maxFrames: 3 });
    expect(out.frames).toHaveLength(3);
  });
  it("only includes raw stack when requested", () => {
    const err = new Error("boom");
    expect(formatError(err).raw).toBe("");
    expect(formatError(err, { includeRaw: true }).raw).toContain("boom");
  });
  it("handles non-Error throwables safely", () => {
    const out = formatError("boom");
    expect(out.headline).toContain("boom");
    expect(out.frames).toEqual([]);
  });
});
