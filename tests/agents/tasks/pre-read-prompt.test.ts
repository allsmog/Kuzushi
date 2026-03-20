import { describe, expect, it } from "vitest";
import {
  formatFileTreeForPrompt,
  formatPreReadForPrompt,
  formatPatternMatchesForPrompt,
} from "../../../src/agents/tasks/pre-read-prompt.js";
import type { FileIndex } from "../../../src/types.js";

function makeFileIndex(overrides: Partial<FileIndex> = {}): FileIndex {
  return {
    tree: [{ path: "src/app.ts" }, { path: "src/config.ts" }, { path: "package.json" }],
    totalFiles: 3,
    truncated: false,
    patternMatches: {},
    ...overrides,
  };
}

describe("formatFileTreeForPrompt", () => {
  it("returns empty for undefined fileIndex", () => {
    expect(formatFileTreeForPrompt(undefined)).toBe("");
  });

  it("returns empty for empty tree", () => {
    expect(formatFileTreeForPrompt({ tree: [], totalFiles: 0, truncated: false, patternMatches: {} })).toBe("");
  });

  it("returns full tree when no pattern matches flag", () => {
    const result = formatFileTreeForPrompt(makeFileIndex());
    expect(result).toContain("## Repository file tree");
    expect(result).toContain("src/app.ts");
    expect(result).toContain("src/config.ts");
    expect(result).toContain("package.json");
    expect(result).toContain("3 source files");
  });

  it("returns full tree when hasPatternMatches is false", () => {
    const result = formatFileTreeForPrompt(makeFileIndex(), false);
    expect(result).toContain("## Repository file tree");
    expect(result).toContain("src/app.ts");
  });

  it("returns compact summary when hasPatternMatches is true", () => {
    const result = formatFileTreeForPrompt(makeFileIndex(), true);
    expect(result).toContain("## Repository: 3 source files");
    expect(result).toContain("Use Glob if you need files beyond");
    expect(result).not.toContain("src/app.ts");
    expect(result).not.toContain("```");
  });

  it("includes truncated note in compact summary", () => {
    const result = formatFileTreeForPrompt(makeFileIndex({ truncated: true }), true);
    expect(result).toContain("(truncated)");
  });

  it("includes truncated note in full tree", () => {
    const result = formatFileTreeForPrompt(makeFileIndex({ truncated: true }));
    expect(result).toContain("(truncated)");
  });
});

describe("formatPreReadForPrompt", () => {
  it("returns empty for no files", () => {
    expect(formatPreReadForPrompt({ files: [], totalBytes: 0, truncated: false })).toBe("");
  });

  it("formats pre-read files", () => {
    const result = formatPreReadForPrompt({
      files: [{ path: "src/config.ts", content: "export const x = 1;" }],
      totalBytes: 20,
      truncated: false,
    });
    expect(result).toContain("## Pre-loaded files");
    expect(result).toContain("### src/config.ts");
    expect(result).toContain("export const x = 1;");
  });
});

describe("formatPatternMatchesForPrompt", () => {
  it("returns empty for undefined fileIndex", () => {
    expect(formatPatternMatchesForPrompt(undefined, ["secret-pattern"])).toBe("");
  });

  it("returns empty when no matches for requested domains", () => {
    const fileIndex = makeFileIndex({ patternMatches: { "other-domain": [] } });
    expect(formatPatternMatchesForPrompt(fileIndex, ["secret-pattern"])).toBe("");
  });

  it("returns empty for empty domains array", () => {
    const fileIndex = makeFileIndex({
      patternMatches: { "secret-pattern": [{ filePath: "src/a.ts", lineNumber: 1, lineContent: "API_KEY=abc123" }] },
    });
    expect(formatPatternMatchesForPrompt(fileIndex, [])).toBe("");
  });

  it("formats matches grouped by file", () => {
    const fileIndex = makeFileIndex({
      patternMatches: {
        "secret-pattern": [
          { filePath: "src/handler.ts", lineNumber: 10, lineContent: "const token = 'abc'" },
          { filePath: "src/handler.ts", lineNumber: 20, lineContent: "const secret = 'xyz'" },
        ],
      },
    });
    const result = formatPatternMatchesForPrompt(fileIndex, ["secret-pattern"]);
    expect(result).toContain("## Security pattern matches");
    expect(result).toContain("src/handler.ts");
    expect(result).toContain("L10");
    expect(result).toContain("L20");
  });

  it("non-empty result has positive length", () => {
    const fileIndex = makeFileIndex({
      patternMatches: {
        "secret-pattern": [{ filePath: "src/a.ts", lineNumber: 1, lineContent: "API_KEY=secret" }],
      },
    });
    const result = formatPatternMatchesForPrompt(fileIndex, ["secret-pattern"]);
    expect(result.length).toBeGreaterThan(0);
  });
});
