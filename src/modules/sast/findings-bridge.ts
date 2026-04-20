/**
 * Bridge helpers for wiring the triage/verify/patch sub-modules to the
 * legacy DB-backed functions in `src/triage.ts`, `src/verify.ts`, `src/patch.ts`.
 *
 * The store layer gives us `StoredFindingRecord`, which is a superset of the
 * `Finding` shape scanners emit. Projecting down is mechanical; the resulting
 * Finding is accepted by `triageFindingsBatch`, `verifyFindingWithAgent`, etc.
 */

import type Database from "better-sqlite3";
import type { Finding, TaskId } from "../../scanners/types.js";
import { getActionableFindings, type getStoredFinding } from "../../store.js";

/** Project a StoredFindingRecord into the Finding shape the triage/verify code expects. */
export function storedToFinding(stored: ReturnType<typeof getStoredFinding>): Finding | undefined {
  if (!stored) return undefined;
  return {
    taskId: stored.taskId as TaskId,
    fingerprint: stored.fingerprint,
    ruleId: stored.ruleId,
    filePath: stored.filePath,
    startLine: stored.startLine,
    severity: stored.severity,
    message: stored.message,
    scannerConfidence: "medium",
    subcategory: [],
    likelihood: "unknown",
    impact: "unknown",
    cwe: [],
    score: 0,
  };
}

/**
 * Load findings by explicit fingerprint list, or load all actionable findings
 * for the repo when `fingerprints` is empty/undefined.
 */
export function loadFindingsForTriage(
  db: Database.Database,
  repo: string | undefined,
  fingerprints: string[] | undefined,
): Finding[] {
  const opts = fingerprints && fingerprints.length > 0 ? { fingerprints } : {};
  const stored = getActionableFindings(db, repo, { ...opts, includeFalsePositives: true });
  const out: Finding[] = [];
  for (const row of stored) {
    const f = storedToFinding(row);
    if (f) out.push(f);
  }
  return out;
}
