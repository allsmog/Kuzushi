import { describe, expect, it } from "vitest";
import { generateOperatorContextFromOutputs } from "../src/operator-context.js";

describe("operator context generation", () => {
  it("carries repo auth patterns into external defense hints", () => {
    const ctx = generateOperatorContextFromOutputs({
      repoContext: {
        languages: [],
        frameworks: [],
        authPatterns: ["auth-module", "middleware-guards"],
        sanitizationLibs: ["validator"],
        ormOrDb: [],
        entryPoints: [],
      },
    });

    expect(ctx.trust.externalDefenses.map((item) => item.value)).toEqual([
      "auth-module",
      "middleware-guards",
      "validator",
    ]);
    expect(ctx.trust.externalDefenses.every((item) => item.status === "skipped")).toBe(true);
  });
});
