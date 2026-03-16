import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { loadBootstrapContext, type BootstrapConfig } from "../../src/prompts/bootstrap.js";
import { mkdirSync, writeFileSync, rmSync, existsSync } from "node:fs";
import path from "node:path";
import os from "node:os";

describe("loadBootstrapContext", () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = path.join(os.tmpdir(), `kuzushi-bootstrap-test-${Date.now()}`);
    mkdirSync(tmpDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(tmpDir)) {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("returns empty string with no files configured", () => {
    const result = loadBootstrapContext(tmpDir, {});
    expect(result).toBe("");
  });

  it("returns empty string with empty files array", () => {
    const result = loadBootstrapContext(tmpDir, { files: [] });
    expect(result).toBe("");
  });

  it("loads a single file", () => {
    writeFileSync(path.join(tmpDir, "guidelines.md"), "Be thorough.");
    const result = loadBootstrapContext(tmpDir, { files: ["guidelines.md"] });
    expect(result).toContain("Be thorough.");
    expect(result).toContain("Project Context");
  });

  it("loads multiple files", () => {
    writeFileSync(path.join(tmpDir, "a.md"), "File A content");
    writeFileSync(path.join(tmpDir, "b.md"), "File B content");
    const result = loadBootstrapContext(tmpDir, { files: ["a.md", "b.md"] });
    expect(result).toContain("File A content");
    expect(result).toContain("File B content");
  });

  it("skips missing files silently", () => {
    writeFileSync(path.join(tmpDir, "exists.md"), "Present");
    const result = loadBootstrapContext(tmpDir, {
      files: ["missing.md", "exists.md"],
    });
    expect(result).toContain("Present");
    expect(result).not.toContain("missing");
  });

  it("trims file to per-file budget", () => {
    writeFileSync(path.join(tmpDir, "big.md"), "x".repeat(1000));
    const result = loadBootstrapContext(tmpDir, {
      files: ["big.md"],
      maxCharsPerFile: 100,
    });
    expect(result).toContain("truncated");
    expect(result).toContain("900 chars omitted");
  });

  it("respects total budget across files", () => {
    writeFileSync(path.join(tmpDir, "a.md"), "a".repeat(500));
    writeFileSync(path.join(tmpDir, "b.md"), "b".repeat(500));
    writeFileSync(path.join(tmpDir, "c.md"), "c".repeat(500));
    const result = loadBootstrapContext(tmpDir, {
      files: ["a.md", "b.md", "c.md"],
      totalMaxChars: 800,
    });
    // Should include a.md and b.md but truncate or skip c.md
    expect(result).toContain("a".repeat(100));
    expect(result).toContain("b".repeat(100));
  });
});
