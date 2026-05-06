import { readFileSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "..", "..");

describe("legacy TypeScript shell isolation", () => {
  it("keeps the source CLI from importing the retired Ink shell", () => {
    const source = readFileSync(path.join(repoRoot, "src", "cli", "commands", "shell.ts"), "utf8");

    expect(source).toContain("reference-only");
    expect(source).not.toContain("copilot/shell");
    expect(source).not.toContain("startShell");
    expect(source).not.toContain('from "ink"');
    expect(source).not.toContain('from "react"');
  });

  it("fails actionably instead of starting Ink through src/cli.ts", async () => {
    const { runShellCommand } = await import("../../src/cli/commands/shell.js");

    await expect(runShellCommand({ target: repoRoot })).rejects.toMatchObject({
      exitCode: 2,
      message: expect.stringContaining("TypeScript/Ink shell is retained as reference-only"),
    });
    await expect(runShellCommand({ target: repoRoot })).rejects.toThrow(
      /node bin\/kuzushi-rs\.mjs shell/,
    );
  });
});
