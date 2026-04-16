import type Database from "better-sqlite3";
import type { CryptoBehavioralRun } from "../crypto-behavioral/types.js";
import { safeJsonParse, safeJsonStringify } from "../utils/safe-json.js";

type CryptoBehavioralRunRow = {
  run_id: string;
  pipeline_run_id: string | null;
  fingerprint: string;
  repo: string;
  test_type: string;
  verdict: string;
  harness_path: string | null;
  harness_language: string | null;
  execution_exit_code: number | null;
  execution_verdict: string | null;
  execution_stdout: string | null;
  execution_stderr: string | null;
  execution_duration_ms: number | null;
  t_statistic: number | null;
  p_value: number | null;
  mean_a_ns: number | null;
  mean_b_ns: number | null;
  timing_iterations: number | null;
  observed_behavior: string | null;
  expected_behavior: string | null;
  algorithm_confirmed: string | null;
  key_length_bits: number | null;
  cost_usd: number | null;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
};

export function insertCryptoBehavioralRun(db: Database.Database, run: CryptoBehavioralRun): void {
  db.prepare(`
    INSERT OR REPLACE INTO crypto_behavioral_runs (
      run_id, pipeline_run_id, fingerprint, repo, test_type, verdict,
      harness_path, harness_language, execution_exit_code, execution_verdict,
      execution_stdout, execution_stderr, execution_duration_ms,
      t_statistic, p_value, mean_a_ns, mean_b_ns, timing_iterations,
      observed_behavior, expected_behavior, algorithm_confirmed, key_length_bits,
      cost_usd, metadata_json, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now')), datetime('now'))
  `).run(
    run.runId,
    run.pipelineRunId ?? null,
    run.fingerprint,
    run.repo,
    run.testType,
    run.verdict,
    run.harnessPath ?? null,
    run.harnessLanguage ?? null,
    run.executionExitCode ?? null,
    run.executionVerdict ?? null,
    run.executionStdout ?? null,
    run.executionStderr ?? null,
    run.executionDurationMs ?? null,
    run.tStatistic ?? null,
    run.pValue ?? null,
    run.meanANs ?? null,
    run.meanBNs ?? null,
    run.timingIterations ?? null,
    run.observedBehavior ?? null,
    run.expectedBehavior ?? null,
    run.algorithmConfirmed ?? null,
    run.keyLengthBits ?? null,
    run.costUsd ?? null,
    run.metadata ? safeJsonStringify(run.metadata) : null,
    run.createdAt ?? null,
  );
}

export function getCryptoBehavioralRunsByFingerprint(
  db: Database.Database,
  fingerprint: string,
): CryptoBehavioralRun[] {
  const rows = db
    .prepare(`
    SELECT * FROM crypto_behavioral_runs
    WHERE fingerprint = ?
    ORDER BY created_at DESC
  `)
    .all(fingerprint) as CryptoBehavioralRunRow[];

  return rows.map(rowToCryptoBehavioralRun);
}

function rowToCryptoBehavioralRun(row: CryptoBehavioralRunRow): CryptoBehavioralRun {
  return {
    runId: row.run_id,
    pipelineRunId: row.pipeline_run_id ?? undefined,
    fingerprint: row.fingerprint,
    repo: row.repo,
    testType: row.test_type as CryptoBehavioralRun["testType"],
    verdict: row.verdict as CryptoBehavioralRun["verdict"],
    harnessPath: row.harness_path,
    harnessLanguage: row.harness_language,
    executionExitCode: row.execution_exit_code,
    executionVerdict: row.execution_verdict as CryptoBehavioralRun["executionVerdict"],
    executionStdout: row.execution_stdout ?? undefined,
    executionStderr: row.execution_stderr ?? undefined,
    executionDurationMs: row.execution_duration_ms,
    tStatistic: row.t_statistic,
    pValue: row.p_value,
    meanANs: row.mean_a_ns,
    meanBNs: row.mean_b_ns,
    timingIterations: row.timing_iterations,
    observedBehavior: row.observed_behavior ?? undefined,
    expectedBehavior: row.expected_behavior ?? undefined,
    algorithmConfirmed: row.algorithm_confirmed ?? undefined,
    keyLengthBits: row.key_length_bits,
    costUsd: row.cost_usd ?? undefined,
    metadata: row.metadata_json
      ? (safeJsonParse<Record<string, unknown>>(row.metadata_json, {}) ?? {})
      : undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}
