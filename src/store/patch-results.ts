import type Database from "better-sqlite3";
import type { PatchResult, PatchStatus } from "../types.js";
import { safeJsonParse, safeJsonStringify } from "../utils/safe-json.js";

type PatchResultRow = {
  patch_run_id: string;
  fingerprint: string;
  repo: string;
  diff: string | null;
  status: string;
  iterations: number;
  build_command: string | null;
  test_command: string | null;
  worktree_path: string | null;
  cost_usd: number | null;
  validator_log: string | null;
  history_json: string;
  created_at: string;
  updated_at: string;
};

export function insertPatchResult(
  db: Database.Database,
  result: PatchResult,
): void {
  db.prepare(`
    INSERT INTO patch_results (
      patch_run_id, fingerprint, repo, diff, status,
      iterations, build_command, test_command, worktree_path,
      cost_usd, validator_log, history_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    result.patchRunId,
    result.fingerprint,
    result.repo,
    result.diff,
    result.status,
    result.iterations,
    result.buildCommand ?? null,
    result.testCommand ?? null,
    result.worktreePath ?? null,
    result.costUsd ?? null,
    result.validatorLog ?? null,
    safeJsonStringify(result.history),
  );
}

export function getPatchResult(
  db: Database.Database,
  patchRunId: string,
): PatchResult | undefined {
  const row = db.prepare(`
    SELECT * FROM patch_results WHERE patch_run_id = ?
  `).get(patchRunId) as PatchResultRow | undefined;

  return row ? rowToPatchResult(row) : undefined;
}

export function getPatchResultsForFinding(
  db: Database.Database,
  fingerprint: string,
): PatchResult[] {
  const rows = db.prepare(`
    SELECT * FROM patch_results
    WHERE fingerprint = ?
    ORDER BY created_at DESC
  `).all(fingerprint) as PatchResultRow[];

  return rows.map(rowToPatchResult);
}

function rowToPatchResult(row: PatchResultRow): PatchResult {
  return {
    patchRunId: row.patch_run_id,
    fingerprint: row.fingerprint,
    repo: row.repo,
    diff: row.diff,
    status: (parsePatchStatus(row.status) ?? "UNKNOWN") as PatchStatus,
    iterations: row.iterations,
    buildCommand: row.build_command,
    testCommand: row.test_command,
    worktreePath: row.worktree_path,
    costUsd: row.cost_usd ?? undefined,
    validatorLog: row.validator_log ?? undefined,
    history: safeJsonParse<PatchResult["history"]>(row.history_json, []) ?? [],
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export function updatePatchResultStatus(
  db: Database.Database,
  patchRunId: string,
  status: PatchStatus,
): void {
  db.prepare(`
    UPDATE patch_results SET status = ?, updated_at = datetime('now')
    WHERE patch_run_id = ?
  `).run(status, patchRunId);
}

function parsePatchStatus(raw: string | null): PatchStatus | undefined {
  switch (raw) {
    case "APPLY_FAILED":
    case "BUILD_FAILED":
    case "STILL_VULNERABLE":
    case "TESTS_FAILED":
    case "SOUND":
    case "VERIFIED":
    case "UNKNOWN":
      return raw;
    default:
      return undefined;
  }
}
