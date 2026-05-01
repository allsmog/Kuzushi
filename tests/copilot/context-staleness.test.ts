import { describe, expect, it } from "vitest";
import {
  classifyContextFreshness,
  computeStaleSlices,
} from "../../src/copilot/context-staleness.js";
import type { ContextSnapshot } from "../../src/ui/state.js";

const baseSnapshot: ContextSnapshot = {
  target: "./acme-api",
  timestamp: 1_700_000_000_000,
  discovery: "auto",
  options: { enrichment: true },
};

describe("computeStaleSlices", () => {
  it("returns no slices when the changed-set is empty", () => {
    expect(computeStaleSlices(baseSnapshot, [])).toEqual([]);
  });

  it("returns no slices when there is no snapshot", () => {
    expect(computeStaleSlices(null, ["src/foo.ts"])).toEqual([]);
  });

  it("flags app-model + repo for a source-file change", () => {
    expect(computeStaleSlices(baseSnapshot, ["src/api/orders.ts"])).toEqual(["repo", "app-model"]);
  });

  it("flags repo for a config-file change without source touching", () => {
    expect(computeStaleSlices(baseSnapshot, ["package.json"])).toEqual(["repo"]);
  });

  it("flags enrichment when a sanitizer/middleware path is touched", () => {
    expect(computeStaleSlices(baseSnapshot, ["src/security/sanitize.ts"])).toEqual([
      "repo",
      "enrichment",
      "app-model",
    ]);
  });

  it("dedupes when multiple paths flag the same slice", () => {
    expect(computeStaleSlices(baseSnapshot, ["src/a.ts", "src/b.ts", "src/c.py"])).toEqual([
      "repo",
      "app-model",
    ]);
  });

  it("ignores empty path strings without throwing", () => {
    expect(computeStaleSlices(baseSnapshot, ["", "src/x.ts"])).toEqual(["repo", "app-model"]);
  });

  it("orders result deterministically: repo → enrichment → app-model", () => {
    const out = computeStaleSlices(baseSnapshot, [
      "src/security/auth.ts",
      "package.json",
      "src/api.ts",
    ]);
    expect(out).toEqual(["repo", "enrichment", "app-model"]);
  });
});

describe("classifyContextFreshness", () => {
  it("returns missing when there is no snapshot", () => {
    expect(classifyContextFreshness(null, [])).toBe("missing");
  });

  it("returns fresh when nothing has changed", () => {
    expect(classifyContextFreshness(baseSnapshot, [])).toBe("fresh");
  });

  it("returns fresh when changed paths are unrelated to slices", () => {
    expect(classifyContextFreshness(baseSnapshot, ["docs/changelog.md", "README.md"])).toBe(
      "fresh",
    );
  });

  it("returns stale when at least one slice would invalidate", () => {
    expect(classifyContextFreshness(baseSnapshot, ["src/api/orders.ts"])).toBe("stale");
  });
});
