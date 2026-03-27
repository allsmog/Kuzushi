import { afterEach, describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const repoRoot = path.resolve(import.meta.dirname, "..", "..");
const tsxBin = path.join(repoRoot, "node_modules", ".bin", "tsx");
const cliPath = path.join(repoRoot, "src", "cli.ts");
const tempDirs: string[] = [];

function runCli(args: string[]) {
  return spawnSync(tsxBin, [cliPath, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
  });
}

function makeTempRepo(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-cli-"));
  tempDirs.push(dir);
  mkdirSync(path.join(dir, ".kuzushi"), { recursive: true });
  writeFileSync(path.join(dir, "package.json"), JSON.stringify({
    name: "tmp-repo",
    private: true,
  }));
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("CLI surface", () => {
  it("exposes the documented dynamic-analysis and taint-diff flags", () => {
    const result = runCli(["scan", "--help"]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("--dynamic-analysis");
    expect(result.stdout).toContain("--dynamic-max-candidates");
    expect(result.stdout).toContain("--taint-diff-base");
    expect(result.stdout).toContain("--taint-diff-mode");
  }, 20000);

  it("supports the list-tasks shorthand", () => {
    const repoDir = makeTempRepo();
    const result = runCli(["list-tasks", "-r", repoDir]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Registered tasks:");
  }, 20000);
});
