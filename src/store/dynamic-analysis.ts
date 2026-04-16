import type Database from "better-sqlite3";
import type { DynamicAnalysisRun, DynamicAnalysisStatus } from "../types.js";
import { safeJsonParse, safeJsonStringify } from "../utils/safe-json.js";

type DynamicAnalysisRunRow = {
  dynamic_run_id: string;
  pipeline_run_id: string | null;
  fingerprint: string;
  repo: string;
  status: string;
  score: number;
  proof_value: number;
  language: string | null;
  harness_path: string | null;
  harness_language: string | null;
  seed_inputs_json: string | null;
  coverage_mode: string | null;
  coverage_summary: string | null;
  execution_exit_code: number | null;
  execution_stdout: string | null;
  execution_stderr: string | null;
  execution_verdict: string | null;
  execution_duration_ms: number | null;
  iterations: number;
  cost_usd: number | null;
  metadata_json: string | null;
  created_at: string;
  updated_at: string;
};

export function insertDynamicAnalysisRun(db: Database.Database, run: DynamicAnalysisRun): void {
  db.prepare(`
    INSERT OR REPLACE INTO dynamic_analysis_runs (
      dynamic_run_id, pipeline_run_id, fingerprint, repo, status,
      score, proof_value, language, harness_path, harness_language,
      seed_inputs_json, coverage_mode, coverage_summary,
      execution_exit_code, execution_stdout, execution_stderr,
      execution_verdict, execution_duration_ms, iterations,
      cost_usd, metadata_json, created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now')), datetime('now'))
  `).run(
    run.dynamicRunId,
    run.pipelineRunId ?? null,
    run.fingerprint,
    run.repo,
    run.status,
    run.score,
    run.proofValue,
    run.language ?? null,
    run.harnessPath ?? null,
    run.harnessLanguage ?? null,
    run.seedInputs ? safeJsonStringify(run.seedInputs) : null,
    run.coverageMode ?? null,
    run.coverageSummary ?? null,
    run.executionExitCode ?? null,
    run.executionStdout ?? null,
    run.executionStderr ?? null,
    run.executionVerdict ?? null,
    run.executionDurationMs ?? null,
    run.iterations,
    run.costUsd ?? null,
    run.metadata ? safeJsonStringify(run.metadata) : null,
    run.createdAt ?? null,
  );
}

export function getDynamicAnalysisRun(
  db: Database.Database,
  dynamicRunId: string,
): DynamicAnalysisRun | undefined {
  const row = db
    .prepare(`
    SELECT * FROM dynamic_analysis_runs WHERE dynamic_run_id = ?
  `)
    .get(dynamicRunId) as DynamicAnalysisRunRow | undefined;

  return row ? rowToDynamicAnalysisRun(row) : undefined;
}

export function getDynamicRunsForFinding(
  db: Database.Database,
  fingerprint: string,
): DynamicAnalysisRun[] {
  const rows = db
    .prepare(`
    SELECT * FROM dynamic_analysis_runs
    WHERE fingerprint = ?
    ORDER BY created_at DESC
  `)
    .all(fingerprint) as DynamicAnalysisRunRow[];

  return rows.map(rowToDynamicAnalysisRun);
}

function rowToDynamicAnalysisRun(row: DynamicAnalysisRunRow): DynamicAnalysisRun {
  return {
    dynamicRunId: row.dynamic_run_id,
    pipelineRunId: row.pipeline_run_id ?? undefined,
    fingerprint: row.fingerprint,
    repo: row.repo,
    status: (parseDynamicAnalysisStatus(row.status) ?? "error") as DynamicAnalysisStatus,
    score: row.score,
    proofValue: row.proof_value,
    language: row.language ?? undefined,
    harnessPath: row.harness_path,
    harnessLanguage: row.harness_language,
    seedInputs: row.seed_inputs_json
      ? (safeJsonParse<string[]>(row.seed_inputs_json, []) ?? [])
      : undefined,
    coverageMode: (row.coverage_mode as DynamicAnalysisRun["coverageMode"]) ?? undefined,
    coverageSummary: row.coverage_summary ?? undefined,
    executionExitCode: row.execution_exit_code,
    executionStdout: row.execution_stdout ?? undefined,
    executionStderr: row.execution_stderr ?? undefined,
    executionVerdict:
      (row.execution_verdict as DynamicAnalysisRun["executionVerdict"]) ?? undefined,
    executionDurationMs: row.execution_duration_ms,
    iterations: row.iterations,
    costUsd: row.cost_usd ?? undefined,
    metadata: row.metadata_json
      ? (safeJsonParse<Record<string, unknown>>(row.metadata_json, {}) ?? {})
      : undefined,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function parseDynamicAnalysisStatus(raw: string | null): DynamicAnalysisStatus | undefined {
  switch (raw) {
    case "confirmed":
    case "interesting":
    case "rejected":
    case "error":
      return raw;
    default:
      return undefined;
  }
}
