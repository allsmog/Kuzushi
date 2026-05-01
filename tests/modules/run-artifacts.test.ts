import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createRunArtifactStore } from "../../src/modules/run-artifacts.js";
import { createMockRunArtifactStore } from "../../src/testing/mocks/run-artifacts.js";

describe("createRunArtifactStore (host implementation)", () => {
  let dataDir: string;

  beforeEach(() => {
    dataDir = mkdtempSync(path.join(tmpdir(), "kuzushi-run-artifacts-"));
  });

  afterEach(() => {
    rmSync(dataDir, { recursive: true, force: true });
  });

  it("writes a file at the expected per-(runId, moduleId) path", () => {
    const store = createRunArtifactStore({ dataDir, runId: "run1", moduleId: "my-mod" });
    const written = store.write("scan-input.json", '{"target":"x"}\n');
    const expected = path.join(dataDir, "runs", "run1", "my-mod", "scan-input.json");
    expect(written).toBe(expected);
    expect(readFileSync(expected, "utf8")).toBe('{"target":"x"}\n');
  });

  it("creates intermediate subdirectories", () => {
    const store = createRunArtifactStore({ dataDir, runId: "run1", moduleId: "m" });
    const written = store.write("nested/dir/file.txt", "hello");
    expect(readFileSync(written, "utf8")).toBe("hello");
  });

  it("path() returns the absolute target without writing", () => {
    const store = createRunArtifactStore({ dataDir, runId: "r", moduleId: "m" });
    const p = store.path("foo.json");
    expect(p).toBe(path.join(dataDir, "runs", "r", "m", "foo.json"));
    // No file was created.
    expect(() => readFileSync(p)).toThrow();
  });

  it("rejects path-traversal via .. segments", () => {
    const store = createRunArtifactStore({ dataDir, runId: "r", moduleId: "m" });
    expect(() => store.write("../secret.txt", "x")).toThrow(/escapes/);
    expect(() => store.path("../../etc/passwd")).toThrow(/escapes/);
  });

  it("rejects absolute paths", () => {
    const store = createRunArtifactStore({ dataDir, runId: "r", moduleId: "m" });
    expect(() => store.write("/etc/passwd", "x")).toThrow(/relative/);
  });

  it("rejects empty/non-string names", () => {
    const store = createRunArtifactStore({ dataDir, runId: "r", moduleId: "m" });
    expect(() => store.write("", "x")).toThrow(/non-empty/);
  });

  it("exposes runId and moduleId for prefixing log lines", () => {
    const store = createRunArtifactStore({ dataDir, runId: "r1", moduleId: "mod-a" });
    expect(store.runId).toBe("r1");
    expect(store.moduleId).toBe("mod-a");
  });
});

describe("createMockRunArtifactStore (testing helper)", () => {
  it("records writes without touching disk", () => {
    const mock = createMockRunArtifactStore({ runId: "rX", moduleId: "modX" });
    mock.write("a.txt", "alpha");
    mock.write("b.txt", "beta");
    expect(mock.writes).toHaveLength(2);
    expect(mock.writes[0]).toEqual({ name: "a.txt", content: "alpha" });
    expect(mock.writes[1]).toEqual({ name: "b.txt", content: "beta" });
  });

  it("clear() resets recorded writes", () => {
    const mock = createMockRunArtifactStore();
    mock.write("a", "1");
    mock.clear();
    expect(mock.writes).toHaveLength(0);
  });

  it("path() returns a deterministic virtual path", () => {
    const mock = createMockRunArtifactStore({
      runId: "rA",
      moduleId: "mA",
      root: "/virt/rA/mA",
    });
    expect(mock.path("out.json")).toBe("/virt/rA/mA/out.json");
  });

  it("rejects path-traversal and absolute paths in the mock too", () => {
    const mock = createMockRunArtifactStore();
    expect(() => mock.write("../escape", "x")).toThrow(/escapes/);
    expect(() => mock.path("/abs")).toThrow(/escapes/);
  });

  it("default runId/moduleId are populated", () => {
    const mock = createMockRunArtifactStore();
    expect(mock.runId).toBe("test-run");
    expect(mock.moduleId).toBe("test-module");
  });
});
