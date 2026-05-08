import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  looksLikePromptPath,
  PROMPT_OPTION_KEYS,
  resolvePromptValue,
} from "../../src/modules/sast/prompts.js";

const tempDirs: string[] = [];
afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe("looksLikePromptPath", () => {
  it("treats explicit path prefixes + known suffixes as paths", () => {
    expect(looksLikePromptPath("./foo.md")).toBe(true);
    expect(looksLikePromptPath("/abs/bar.txt")).toBe(true);
    expect(looksLikePromptPath("../up.prompt")).toBe(true);
    expect(looksLikePromptPath("some-file.md")).toBe(true);
  });

  it("treats anything else as inline text", () => {
    expect(looksLikePromptPath("You are a triage agent...")).toBe(false);
    expect(looksLikePromptPath("single-line")).toBe(false);
    expect(looksLikePromptPath("")).toBe(false);
  });
});

describe("resolvePromptValue", () => {
  it("returns undefined for empty/undefined values", async () => {
    expect(await resolvePromptValue(undefined, "/tmp")).toBeUndefined();
    expect(await resolvePromptValue("", "/tmp")).toBeUndefined();
  });

  it("returns inline text unchanged", async () => {
    const inline = "You are a careful triage agent. Always cite line numbers.";
    expect(await resolvePromptValue(inline, "/tmp")).toBe(inline);
  });

  it("reads absolute paths", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "kuzushi-prompts-"));
    tempDirs.push(dir);
    const file = path.join(dir, "triage.md");
    writeFileSync(file, "# Custom triage\nBe thorough.\n", "utf8");
    const value = await resolvePromptValue(file, "/anywhere");
    expect(value).toContain("Custom triage");
  });

  it("reads relative paths against cwd", async () => {
    const dir = mkdtempSync(path.join(tmpdir(), "kuzushi-prompts-"));
    tempDirs.push(dir);
    writeFileSync(path.join(dir, "verify.md"), "# Verify prompt\n", "utf8");
    const value = await resolvePromptValue("./verify.md", dir);
    expect(value).toContain("Verify prompt");
  });
});

describe("PROMPT_OPTION_KEYS", () => {
  it("covers every agentic sub-module", () => {
    expect(PROMPT_OPTION_KEYS).toContain("TRIAGE_PROMPT");
    expect(PROMPT_OPTION_KEYS).toContain("VERIFY_PROMPT");
    expect(PROMPT_OPTION_KEYS).toContain("PATCH_PROMPT");
    expect(PROMPT_OPTION_KEYS).toContain("CARLINI_THREAT_HUNT_PROMPT");
    expect(PROMPT_OPTION_KEYS).toContain("CONTEXT_PROMPT");
  });
});
