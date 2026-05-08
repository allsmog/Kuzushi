import { describe, expect, it } from "vitest";
import {
  classifyError,
  editDistance,
  formatError,
  formatUnknownModule,
  formatUnknownTool,
  formatUnknownVerb,
  nearestMatches,
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
    expect(classifyError(new Error("fetch failed ECONNRESET"))).toBe("transient");
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
  it("detects specific env var names in auth errors", () => {
    const err: Error & { status?: number } = new Error("MY_SPECIAL_KEY not set");
    err.status = 401;
    const hint = suggestNextStep(err, "auth");
    expect(hint).toContain("MY_SPECIAL_KEY");
  });
  it("returns undefined for fatal/unknown", () => {
    expect(suggestNextStep(null, "fatal")).toBeUndefined();
    expect(suggestNextStep(null, "unknown")).toBeUndefined();
  });
  it("rate_limit hint mentions advanced config", () => {
    const hint = suggestNextStep(null, "rate_limit") ?? "";
    expect(hint).toContain("triageConcurrency");
    expect(hint).toContain("/config advanced");
  });
  it("budget hint points at budget/model changes before rerunning", () => {
    const hint = suggestNextStep(null, "budget") ?? "";
    expect(hint).toContain("--budget");
    expect(hint).toContain("cheaper model");
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
      Array.from({ length: 20 }, (_, i) => `    at fn${i} (/src/f${i}.ts:1:1)`).join("\n");
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

describe("editDistance", () => {
  it("returns 0 for identical strings", () => {
    expect(editDistance("sast", "sast")).toBe(0);
  });
  it("is case-insensitive", () => {
    expect(editDistance("SAST", "sast")).toBe(0);
  });
  it("returns length of longer string when one is empty", () => {
    expect(editDistance("", "sast")).toBe(4);
    expect(editDistance("sast", "")).toBe(4);
  });
  it("counts single substitutions", () => {
    expect(editDistance("sast", "mast")).toBe(1);
  });
  it("counts insertions and deletions", () => {
    expect(editDistance("scan", "scanr")).toBe(1);
    expect(editDistance("scanr", "scan")).toBe(1);
  });
});

describe("nearestMatches", () => {
  it("returns the closest match first", () => {
    const matches = nearestMatches("sat", ["sast", "dast", "iast", "threats"], 3);
    expect(matches[0]).toBe("sast");
  });
  it("returns at most `limit` matches", () => {
    const matches = nearestMatches("sat", ["sast", "dast", "iast", "threats"], 2);
    expect(matches).toHaveLength(2);
  });
  it("returns empty when nothing is similar enough", () => {
    const matches = nearestMatches("xyz", ["completely", "unrelated", "tokens"]);
    expect(matches).toEqual([]);
  });
  it("returns empty on empty haystack or empty needle", () => {
    expect(nearestMatches("a", [])).toEqual([]);
    expect(nearestMatches("", ["a", "b"])).toEqual([]);
  });
});

describe("formatUnknownTool", () => {
  it("includes the typo and a suggestion", () => {
    const out = formatUnknownTool("sast:sca", ["sast:scan", "semgrep:scan", "codeql:scan"]);
    expect(out).toContain("sast:sca");
    expect(out).toContain("sast:scan");
  });
  it("falls back to /tools when nothing is close", () => {
    const out = formatUnknownTool("xyzabc", ["sast:scan"]);
    expect(out).toContain("/tools");
    expect(out).not.toContain("Did you mean");
  });
});

describe("formatUnknownModule", () => {
  it("suggests the closest loaded module", () => {
    const out = formatUnknownModule("sat", ["sast", "threats", "randori"]);
    expect(out).toContain("sast");
    expect(out).toContain("/modules");
  });
  it("handles empty loaded list", () => {
    const out = formatUnknownModule("sast", []);
    expect(out).toContain("Unknown module");
    expect(out).not.toContain("Did you mean");
  });
});

describe("formatUnknownVerb", () => {
  it("suggests the closest known verb", () => {
    const out = formatUnknownVerb("tunne", ["tune", "trace", "threats"]);
    expect(out).toContain("tune");
    expect(out).toContain("/help");
  });
  it("strips leading slash from the input", () => {
    const out = formatUnknownVerb("/threats-foo", ["threats"]);
    expect(out).toContain("threats-foo");
    // Shouldn't double-slash.
    expect(out).not.toContain("//");
  });
  it("falls back when no known verbs are given", () => {
    const out = formatUnknownVerb("xyz");
    expect(out).toContain("Unknown command");
    expect(out).toContain("/help");
  });
});

describe("preflight credentials error wording", () => {
  // Golden checks for the operator-actionable replacement of the bare
  // `${envVar} is not set.` message. We import lazily to avoid touching the
  // full preflight in modules that don't need it.
  it("links to the Anthropic console + names the three resolution paths", async () => {
    const { runPreflight } = await import("../../src/cli/preflight.js");
    const config = {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: [],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: {},
      agentRuntimeBackend: "claude" as const,
    };
    // Drop any inherited env vars so the missing-cred path triggers.
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;
    try {
      const report = runPreflight(
        config as unknown as Parameters<typeof runPreflight>[0],
        process.cwd(),
      );
      const issue = report.issues.find((i) => i.path === "credentials");
      expect(issue).toBeDefined();
      // Names the env var rather than mumbling "credentials are missing".
      expect(issue!.message).toContain("ANTHROPIC_API_KEY");
      // Provides three concrete resolution paths.
      expect(issue!.hint).toContain("export ANTHROPIC_API_KEY");
      expect(issue!.hint).toContain("--api-key");
      expect(issue!.hint).toContain("kuzushi auth");
      // Anthropic console link is present so first-time operators don't
      // have to bounce to a search engine.
      expect(issue!.hint).toContain("console.anthropic.com");
    } finally {
      if (saved) process.env.ANTHROPIC_API_KEY = saved;
    }
  });
});
