import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ensureScannerCacheSchema, withFileCache } from "../src/scanner-cache.js";
import type { Finding } from "../src/scanners/types.js";

function makeFinding(filePath: string, ruleId: string): Finding {
  return {
    taskId: "test-task",
    fingerprint: `${ruleId}:${filePath}`,
    ruleId,
    filePath,
    startLine: 1,
    endLine: 1,
    severity: "ERROR",
    message: `test finding in ${filePath}`,
    code_citations: [],
  } as unknown as Finding;
}

describe("withFileCache", () => {
  let repoDir: string;
  let db: Database.Database;

  beforeEach(() => {
    repoDir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-scancache-"));
    execFileSync("git", ["init", "-q"], { cwd: repoDir });
    execFileSync("git", ["config", "user.email", "test@kuzushi.dev"], { cwd: repoDir });
    execFileSync("git", ["config", "user.name", "Test"], { cwd: repoDir });

    writeFileSync(path.join(repoDir, "a.ts"), "export const a = 1;\n");
    writeFileSync(path.join(repoDir, "b.ts"), "export const b = 2;\n");
    execFileSync("git", ["add", "."], { cwd: repoDir });
    // --no-verify avoids sandbox signing hooks; --allow-empty-message keeps
    // the ref minimal. Signing is configured via environment in our test
    // runner; commit may fail there but blob-hash lookups only require the
    // files to be `git add`-ed, so that's enough.
    try {
      execFileSync("git", ["-c", "commit.gpgsign=false", "commit", "-q", "-m", "init"], {
        cwd: repoDir,
      });
    } catch {
      // Signed-commit sandbox — fine, blob hashes are computed from the index.
    }

    db = new Database(":memory:");
    ensureScannerCacheSchema(db);
  });

  afterEach(() => {
    db.close();
    rmSync(repoDir, { recursive: true, force: true });
  });

  it("runs scan on a cold cache and returns all findings", async () => {
    const scanCalls: string[][] = [];
    const results = await withFileCache({
      db,
      taskId: "test-task",
      config: { rule: "x" },
      repoRoot: repoDir,
      filePaths: ["a.ts", "b.ts"],
      scan: async (uncached) => {
        scanCalls.push([...uncached]);
        return new Map([
          ["a.ts", [makeFinding("a.ts", "rule-a")]],
          ["b.ts", [makeFinding("b.ts", "rule-b")]],
        ]);
      },
    });

    expect(scanCalls).toEqual([["a.ts", "b.ts"]]);
    expect(results).toHaveLength(2);
    expect(results.map((f) => f.ruleId).sort()).toEqual(["rule-a", "rule-b"]);
  });

  it("skips scanning files whose blob-hash already has cached findings", async () => {
    // Seed the cache with a cold run.
    await withFileCache({
      db,
      taskId: "test-task",
      config: { rule: "x" },
      repoRoot: repoDir,
      filePaths: ["a.ts", "b.ts"],
      scan: async () =>
        new Map([
          ["a.ts", [makeFinding("a.ts", "rule-a")]],
          ["b.ts", [makeFinding("b.ts", "rule-b")]],
        ]),
    });

    // Second call: scan() must not see any files (cache is warm).
    const scanCalls: string[][] = [];
    const results = await withFileCache({
      db,
      taskId: "test-task",
      config: { rule: "x" },
      repoRoot: repoDir,
      filePaths: ["a.ts", "b.ts"],
      scan: async (uncached) => {
        scanCalls.push([...uncached]);
        return new Map();
      },
    });

    expect(scanCalls).toEqual([]);
    expect(results.map((f) => f.ruleId).sort()).toEqual(["rule-a", "rule-b"]);
  });

  it("invalidates the cache when the task config changes", async () => {
    await withFileCache({
      db,
      taskId: "test-task",
      config: { rule: "v1" },
      repoRoot: repoDir,
      filePaths: ["a.ts"],
      scan: async () => new Map([["a.ts", [makeFinding("a.ts", "rule-a")]]]),
    });

    const scanCalls: string[][] = [];
    await withFileCache({
      db,
      taskId: "test-task",
      // Config differs → different config hash → cache miss.
      config: { rule: "v2" },
      repoRoot: repoDir,
      filePaths: ["a.ts"],
      scan: async (uncached) => {
        scanCalls.push([...uncached]);
        return new Map([["a.ts", [makeFinding("a.ts", "rule-a-v2")]]]);
      },
    });

    expect(scanCalls).toEqual([["a.ts"]]);
  });
});
