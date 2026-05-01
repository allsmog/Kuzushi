import { describe, expect, it } from "vitest";
import {
  buildRunMetadata,
  getKuzushiVersion,
  hashConfig,
} from "../../src/utils/run-metadata.js";

describe("getKuzushiVersion", () => {
  it("returns a semver-shaped string from package.json", () => {
    const v = getKuzushiVersion();
    expect(v).toMatch(/^\d+\.\d+\.\d+/);
  });
});

describe("hashConfig", () => {
  it("produces a stable sha256 for semantically equal configs (key order independent)", () => {
    const a = hashConfig({ b: 2, a: 1, c: { y: 2, x: 1 } });
    const b = hashConfig({ a: 1, c: { x: 1, y: 2 }, b: 2 });
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("produces a different hash when values change", () => {
    expect(hashConfig({ a: 1 })).not.toBe(hashConfig({ a: 2 }));
  });

  it("treats arrays as ordered", () => {
    expect(hashConfig({ tasks: ["a", "b"] })).not.toBe(hashConfig({ tasks: ["b", "a"] }));
  });

  it("handles empty objects", () => {
    expect(hashConfig({})).toMatch(/^[0-9a-f]{64}$/);
  });

  it("handles primitives", () => {
    expect(hashConfig(null)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashConfig("hello")).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("buildRunMetadata", () => {
  it("populates kuzushi version, node version, platform, arch and config hash", () => {
    const meta = buildRunMetadata({
      repoRoot: process.cwd(),
      config: { tasks: ["semgrep"], severity: ["ERROR"] },
      model: "anthropic:claude-sonnet-4-6",
      scanArgs: ["semgrep"],
      startedAt: "2026-04-30T00:00:00Z",
    });
    expect(meta.kuzushiVersion).toMatch(/^\d+\.\d+\.\d+/);
    expect(meta.nodeVersion).toBe(process.versions.node);
    expect(meta.platform).toBe(process.platform);
    expect(meta.arch).toBe(process.arch);
    expect(meta.configHash).toMatch(/^[0-9a-f]{64}$/);
    expect(meta.model).toBe("anthropic:claude-sonnet-4-6");
    expect(meta.scanArgs).toEqual(["semgrep"]);
    expect(meta.startedAt).toBe("2026-04-30T00:00:00Z");
  });

  it("returns undefined git fields when repoRoot is not a git repo", () => {
    const meta = buildRunMetadata({
      repoRoot: "/tmp",
      config: {},
    });
    // /tmp is not a git repo; sha/branch should be undefined.
    expect(meta.gitSha).toBeUndefined();
    expect(meta.gitBranch).toBeUndefined();
  });

  it("defaults startedAt to a valid ISO timestamp when not supplied", () => {
    const meta = buildRunMetadata({ repoRoot: "/tmp", config: {} });
    expect(meta.startedAt).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });
});
