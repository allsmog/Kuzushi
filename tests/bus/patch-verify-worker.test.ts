import { describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { allMigrations, runMigrations } from "../../src/migrations/index.js";
import { insertPatchResult, updatePatchResultStatus, getPatchResult } from "../../src/store/patch-results.js";
import type { PatchResult } from "../../src/types.js";

function createTestDb(): Database.Database {
  const db = new Database(":memory:");
  db.pragma("journal_mode = WAL");
  runMigrations(db, allMigrations);
  return db;
}

function makePatchResult(overrides: Partial<PatchResult> = {}): PatchResult {
  return {
    patchRunId: "patch-run-1",
    fingerprint: "fp-1",
    repo: "test-repo",
    diff: "--- a/file.ts\n+++ b/file.ts\n- old\n+ new",
    status: "SOUND",
    iterations: 2,
    buildCommand: "npm run build",
    testCommand: "npm test",
    worktreePath: "/tmp/worktree",
    costUsd: 0.05,
    validatorLog: "Attempt 1: BUILD_FAILED\nAttempt 2: SOUND",
    history: [
      { attempt: 1, diff: "diff1", status: "BUILD_FAILED", output: "build error" },
      { attempt: 2, diff: "diff2", status: "SOUND", output: "all checks passed" },
    ],
    ...overrides,
  };
}

describe("Patch Store: updatePatchResultStatus", () => {
  it("updates status from SOUND to VERIFIED", () => {
    const db = createTestDb();
    const result = makePatchResult();
    insertPatchResult(db, result);

    updatePatchResultStatus(db, "patch-run-1", "VERIFIED");

    const updated = getPatchResult(db, "patch-run-1");
    expect(updated).toBeDefined();
    expect(updated!.status).toBe("VERIFIED");
  });

  it("updates status from SOUND to STILL_VULNERABLE", () => {
    const db = createTestDb();
    const result = makePatchResult();
    insertPatchResult(db, result);

    updatePatchResultStatus(db, "patch-run-1", "STILL_VULNERABLE");

    const updated = getPatchResult(db, "patch-run-1");
    expect(updated!.status).toBe("STILL_VULNERABLE");
  });

  it("is a no-op for non-existent patch run", () => {
    const db = createTestDb();
    // Should not throw
    updatePatchResultStatus(db, "non-existent", "VERIFIED");
  });

  it("preserves other fields when updating status", () => {
    const db = createTestDb();
    const result = makePatchResult();
    insertPatchResult(db, result);

    updatePatchResultStatus(db, "patch-run-1", "VERIFIED");

    const updated = getPatchResult(db, "patch-run-1");
    expect(updated!.diff).toBe(result.diff);
    expect(updated!.iterations).toBe(result.iterations);
    expect(updated!.costUsd).toBe(result.costUsd);
    expect(updated!.fingerprint).toBe(result.fingerprint);
  });
});

describe("PatchStatus: VERIFIED value", () => {
  it("round-trips VERIFIED status through insert/get", () => {
    const db = createTestDb();
    const result = makePatchResult({ status: "VERIFIED" });
    insertPatchResult(db, result);

    const retrieved = getPatchResult(db, "patch-run-1");
    expect(retrieved!.status).toBe("VERIFIED");
  });
});
