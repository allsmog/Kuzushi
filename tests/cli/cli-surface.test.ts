import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const repoRoot = path.resolve(import.meta.dirname, "..", "..");
const tsxBin = path.join(repoRoot, "node_modules", ".bin", "tsx");
const cliPath = path.join(repoRoot, "src", "cli.ts");
const tempDirs: string[] = [];

function runCli(args: string[]) {
  return spawnSync(tsxBin, [cliPath, ...args], {
    cwd: repoRoot,
    encoding: "utf8",
    // Provide a placeholder credential so the non-TTY credential hook in
    // src/cli.ts doesn't short-circuit before the flag-validation paths
    // we're actually exercising here. Tests that genuinely care about
    // the credential hook should override this.
    env: { ...process.env, ANTHROPIC_API_KEY: "sk-ant-test-placeholder" },
  });
}

function makeTempRepo(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-cli-"));
  tempDirs.push(dir);
  mkdirSync(path.join(dir, ".kuzushi"), { recursive: true });
  writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify({
      name: "tmp-repo",
      private: true,
    }),
  );
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
    expect(result.stdout).toContain("--no-module-discovery");
    expect(result.stdout).toContain("--list-modules");
    expect(result.stdout).toContain("--modules");
    expect(result.stdout).toContain("--module-filter");
    expect(result.stdout).not.toContain("--discover-modules");
    expect(result.stdout).not.toContain("--discovery-model");
  }, 40000);

  it("supports the list-tasks shorthand", () => {
    const repoDir = makeTempRepo();
    const result = runCli(["list-tasks", "-r", repoDir]);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain("Registered tasks:");
  }, 40000);

  it("rejects --module-filter for single-root scans", () => {
    const repoDir = makeTempRepo();
    const result = runCli([
      "scan",
      repoDir,
      "--no-module-discovery",
      "--module-filter",
      "platform*",
    ]);
    expect(result.status).not.toBe(0);
    expect(result.stderr).toContain("--module-filter");
  }, 40000);
});
