import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { builtinHintFor, detectClaudeCodePlugin } from "../../src/copilot/core.js";

describe("detectClaudeCodePlugin", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(path.join(tmpdir(), "claude-plugin-detect-"));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  function writePlugin(relDir: string): void {
    const dir = path.join(tmp, relDir);
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, "plugin.json"), "{}");
  }

  it("detects a root-level .claude-plugin marker", () => {
    writePlugin(".claude-plugin");
    expect(detectClaudeCodePlugin(tmp)).toBe(".claude-plugin/plugin.json");
  });

  it("detects a nested .claude-plugin marker one level deep (e.g. vuln-scout)", () => {
    writePlugin("whitebox-pentest/.claude-plugin");
    expect(detectClaudeCodePlugin(tmp)).toBe("whitebox-pentest/.claude-plugin/plugin.json");
  });

  it("detects a .claude-plugin marker two levels deep under plugins/ (e.g. tob-skills)", () => {
    writePlugin("plugins/fp-check/.claude-plugin");
    const hint = detectClaudeCodePlugin(tmp);
    expect(hint).toBe("plugins/fp-check/.claude-plugin/plugin.json");
  });

  it("returns null for a regular npm package", () => {
    writeFileSync(path.join(tmp, "package.json"), JSON.stringify({ name: "plain", main: "i.js" }));
    writeFileSync(path.join(tmp, "i.js"), "module.exports = {};");
    expect(detectClaudeCodePlugin(tmp)).toBeNull();
  });

  it("returns null for a nonexistent directory", () => {
    expect(detectClaudeCodePlugin(path.join(tmp, "does-not-exist"))).toBeNull();
  });
});

describe("builtinHintFor", () => {
  it("redirects known plugin packages to their builtin wrappers", () => {
    expect(builtinHintFor("@kuzushi/randori-plugin")).toContain("builtin:randori");
    expect(builtinHintFor("@kuzushi/vuln-scout")).toContain("builtin:vuln-scout");
    expect(builtinHintFor("@kuzushi/tob-skills")).toContain("builtin:tob");
  });

  it("falls back to a generic message for unknown packages", () => {
    const hint = builtinHintFor("@other/some-plugin");
    expect(hint).toContain("cannot be loaded as CopilotModules directly");
  });
});
