import { describe, it, expect } from "vitest";
import { readFileContext } from "../src/context.js";
import { writeFileSync, mkdirSync, rmSync } from "node:fs";
import path from "node:path";

const TMP_DIR = path.join(import.meta.dirname, ".tmp-context-test");

function setup() {
  mkdirSync(TMP_DIR, { recursive: true });
}

function teardown() {
  rmSync(TMP_DIR, { recursive: true, force: true });
}

describe("readFileContext", () => {
  it("reads lines around target with line numbers", async () => {
    setup();
    const file = path.join(TMP_DIR, "test.ts");
    const lines = Array.from({ length: 100 }, (_, i) => `line ${i + 1}`);
    writeFileSync(file, lines.join("\n"));

    const result = await readFileContext(file, 50, 5);

    expect(result).toContain("// File:");
    expect(result).toContain(">>> ");
    expect(result).toContain("50");
    // Should contain lines around 50
    expect(result).toContain("line 46");
    expect(result).toContain("line 54");
    // Should NOT contain distant lines
    expect(result).not.toContain("line 1\n");
    expect(result).not.toContain("line 100");

    teardown();
  });

  it("handles file at beginning (line 1)", async () => {
    setup();
    const file = path.join(TMP_DIR, "start.ts");
    writeFileSync(file, "first\nsecond\nthird\n");

    const result = await readFileContext(file, 1, 5);
    expect(result).toContain(">>>");
    expect(result).toContain("first");
    expect(result).toContain("second");

    teardown();
  });

  it("returns error message for nonexistent file", async () => {
    const result = await readFileContext("/nonexistent/path.ts", 1, 5);
    expect(result).toContain("Could not read file");
  });

  it("marks the target line with >>>", async () => {
    setup();
    const file = path.join(TMP_DIR, "marker.ts");
    writeFileSync(file, "a\nb\nc\nd\ne\n");

    const result = await readFileContext(file, 3, 10);
    const lines = result.split("\n");
    const markedLine = lines.find((l) => l.includes(">>>"));
    expect(markedLine).toBeDefined();
    expect(markedLine).toContain("c");

    teardown();
  });
});
