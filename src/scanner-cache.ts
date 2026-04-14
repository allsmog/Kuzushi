/**
 * Task result cache — avoids re-scanning unchanged files across runs.
 * Key: (task_id, config_hash, git_blob_hash, file_path)
 * Stores raw finding JSON per file for fast retrieval.
 */

import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import type Database from "better-sqlite3";
import type { Finding } from "./scanners/types.js";
import { safeJsonStringify, safeJsonParse } from "./utils/safe-json.js";

/**
 * Ensure the scanner_cache table exists.
 */
export function ensureScannerCacheSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS scanner_cache (
      task_id       TEXT NOT NULL,
      config_hash   TEXT NOT NULL,
      blob_hash     TEXT NOT NULL,
      file_path     TEXT NOT NULL,
      findings_json TEXT NOT NULL,
      created_at    TEXT NOT NULL,
      PRIMARY KEY (task_id, config_hash, blob_hash, file_path)
    )
  `);
}

/**
 * Compute a hash of the task configuration for cache keying.
 */
export function hashScannerConfig(taskId: string, config: Record<string, unknown>): string {
  const content = safeJsonStringify({ taskId, ...config });
  return createHash("sha256").update(content).digest("hex").slice(0, 16);
}

/**
 * Get the git blob hash for a file (content-addressable identifier).
 * Returns undefined if the file is not tracked or git is unavailable.
 */
export function getGitBlobHash(repoRoot: string, filePath: string): string | undefined {
  try {
    const hash = execFileSync("git", ["hash-object", filePath], {
      cwd: repoRoot,
      encoding: "utf-8",
      timeout: 5_000,
    }).trim();
    return hash || undefined;
  } catch {
    return undefined;
  }
}

/**
 * Look up cached task results for a file.
 * Returns the cached findings if found, undefined otherwise.
 */
export function getCachedFindings(
  db: Database.Database,
  taskId: string,
  configHash: string,
  blobHash: string,
  filePath: string,
): Finding[] | undefined {
  const row = db.prepare(`
    SELECT findings_json FROM scanner_cache
    WHERE task_id = ? AND config_hash = ? AND blob_hash = ? AND file_path = ?
  `).get(taskId, configHash, blobHash, filePath) as { findings_json: string } | undefined;

  if (!row) return undefined;

  const parsed = safeJsonParse<Finding[]>(row.findings_json, undefined as any);
  return Array.isArray(parsed) ? parsed : undefined;
}

/**
 * Store task results for a file in the cache.
 */
export function setCachedFindings(
  db: Database.Database,
  taskId: string,
  configHash: string,
  blobHash: string,
  filePath: string,
  findings: Finding[],
): void {
  const now = new Date().toISOString();
  db.prepare(`
    INSERT OR REPLACE INTO scanner_cache (task_id, config_hash, blob_hash, file_path, findings_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(taskId, configHash, blobHash, filePath, safeJsonStringify(findings), now);
}

/**
 * Partition files into cached (with results) and uncached (need scanning).
 */
export function partitionCachedFiles(
  db: Database.Database,
  taskId: string,
  configHash: string,
  repoRoot: string,
  filePaths: string[],
): { cached: Map<string, Finding[]>; uncached: string[] } {
  const cached = new Map<string, Finding[]>();
  const uncached: string[] = [];

  for (const filePath of filePaths) {
    const blobHash = getGitBlobHash(repoRoot, filePath);
    if (!blobHash) {
      uncached.push(filePath);
      continue;
    }

    const findings = getCachedFindings(db, taskId, configHash, blobHash, filePath);
    if (findings) {
      cached.set(filePath, findings);
    } else {
      uncached.push(filePath);
    }
  }

  return { cached, uncached };
}

/**
 * Persist task results for multiple files after scanning.
 */
export function persistScanResults(
  db: Database.Database,
  taskId: string,
  configHash: string,
  repoRoot: string,
  findingsByFile: Map<string, Finding[]>,
): void {
  const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO scanner_cache (task_id, config_hash, blob_hash, file_path, findings_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `);

  const now = new Date().toISOString();
  const transaction = db.transaction(() => {
    for (const [filePath, findings] of findingsByFile) {
      const blobHash = getGitBlobHash(repoRoot, filePath);
      if (!blobHash) continue;
      insertStmt.run(taskId, configHash, blobHash, filePath, safeJsonStringify(findings), now);
    }
  });

  transaction();
}

/**
 * Prune stale cache entries older than the given number of days.
 */
export function pruneScannerCache(db: Database.Database, maxAgeDays: number = 30): number {
  const result = db.prepare(`
    DELETE FROM scanner_cache
    WHERE created_at < datetime('now', ?)
  `).run(`-${maxAgeDays} days`);

  return result.changes;
}
