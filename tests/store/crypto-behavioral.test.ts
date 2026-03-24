import { rmSync } from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { initDb } from "../../src/store.js";
import {
  getCryptoBehavioralRunsByFingerprint,
  insertCryptoBehavioralRun,
} from "../../src/store/crypto-behavioral.js";

const TMP_DB_PATH = path.join(import.meta.dirname, "..", ".tmp-crypto-behavioral.sqlite3");

describe("crypto behavioral store", () => {
  it("creates the crypto_behavioral_runs table on new and existing databases", () => {
    rmSync(TMP_DB_PATH, { force: true });

    const first = initDb(TMP_DB_PATH);
    const firstTables = first.prepare(`
      SELECT name FROM sqlite_master
      WHERE type = 'table' AND name = 'crypto_behavioral_runs'
    `).all();
    expect(firstTables).toHaveLength(1);
    first.close();

    const reopened = initDb(TMP_DB_PATH);
    const secondTables = reopened.prepare(`
      SELECT name FROM sqlite_master
      WHERE type = 'table' AND name = 'crypto_behavioral_runs'
    `).all();
    expect(secondTables).toHaveLength(1);
    reopened.close();
  });

  it("round-trips crypto behavioral runs by fingerprint", () => {
    const db = initDb(":memory:");

    insertCryptoBehavioralRun(db, {
      runId: "run-1",
      pipelineRunId: "pipeline-1",
      fingerprint: "fp-1",
      repo: "repo",
      testType: "timing",
      verdict: "vulnerable",
      harnessPath: "/tmp/repo/.kuzushi/crypto-behavioral/fp-1-timing.mjs",
      harnessLanguage: "javascript",
      executionExitCode: 0,
      executionVerdict: "PASS",
      executionStdout: "CRYPTO_RESULT:{...}",
      executionStderr: "",
      executionDurationMs: 10,
      tStatistic: 4.2,
      pValue: 0.001,
      meanANs: 101,
      meanBNs: 84,
      timingIterations: 10_000,
      costUsd: 0.33,
      metadata: { summary: "timing leak observed" },
    });

    expect(getCryptoBehavioralRunsByFingerprint(db, "fp-1")).toEqual([
      expect.objectContaining({
        runId: "run-1",
        pipelineRunId: "pipeline-1",
        fingerprint: "fp-1",
        repo: "repo",
        testType: "timing",
        verdict: "vulnerable",
        tStatistic: 4.2,
        pValue: 0.001,
        timingIterations: 10_000,
        costUsd: 0.33,
        metadata: { summary: "timing leak observed" },
      }),
    ]);
  });
});
