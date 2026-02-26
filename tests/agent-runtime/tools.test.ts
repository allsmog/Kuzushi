import { afterEach, describe, expect, it } from "vitest";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { executeTool } from "../../src/agent-runtime/tools.js";

const tempDirs: string[] = [];

function makeTempWorkspace(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-tools-test-"));
  tempDirs.push(dir);
  mkdirSync(path.join(dir, "src"), { recursive: true });
  mkdirSync(path.join(dir, "scripts"), { recursive: true });
  writeFileSync(
    path.join(dir, "src", "app.ts"),
    [
      "export function a() {",
      "  // TODO: sanitize input",
      "  return 1;",
      "}",
    ].join("\n"),
    "utf8",
  );
  writeFileSync(
    path.join(dir, "scripts", "util.ts"),
    [
      "export const util = true;",
      "// TODO: tighten validation",
    ].join("\n"),
    "utf8",
  );
  writeFileSync(path.join(dir, "README.md"), "hello", "utf8");
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("agent-runtime tools", () => {
  it("Read returns line-numbered slices", async () => {
    const cwd = makeTempWorkspace();
    const output = await executeTool("Read", {
      path: "src/app.ts",
      offset: 1,
      limit: 2,
    }, cwd);

    expect(output).toContain("2 |   // TODO: sanitize input");
    expect(output).toContain("3 |   return 1;");
    expect(output).not.toContain("1 | export function a()");
  });

  it("Glob matches files from the selected root", async () => {
    const cwd = makeTempWorkspace();
    const output = await executeTool("Glob", {
      pattern: "**/*.ts",
      path: "src",
    }, cwd);

    expect(output).toContain("src/app.ts");
    expect(output).not.toContain("scripts/util.ts");
  });

  it("Grep returns file:line:content matches", async () => {
    const cwd = makeTempWorkspace();
    const output = await executeTool("Grep", {
      pattern: "TODO",
      glob: "**/*.ts",
    }, cwd);

    expect(output).toContain("src/app.ts:2:  // TODO: sanitize input");
    expect(output).toContain("scripts/util.ts:2:// TODO: tighten validation");
  });

  it("throws for unsupported tool names", async () => {
    const cwd = makeTempWorkspace();
    await expect(executeTool("Unknown", {}, cwd)).rejects.toThrow(
      "Unsupported tool",
    );
  });

  it("rejects paths that escape the workspace root", async () => {
    const cwd = makeTempWorkspace();
    const outsidePath = path.resolve(cwd, "..", "outside.txt");

    await expect(executeTool("Read", {
      path: outsidePath,
    }, cwd)).rejects.toThrow("Path escapes repository root");

    await expect(executeTool("Read", {
      path: "../outside.txt",
    }, cwd)).rejects.toThrow("Path escapes repository root");
  });
});
