import { execFileSync } from "node:child_process";
import type Database from "better-sqlite3";
import type { ImportGraphEdge } from "./analysis-support/types.js";
import { createLogger } from "./logger.js";

const log = createLogger({ stage: "incremental" });

const EXEC_TIMEOUT_MS = 30_000;

/**
 * Get the HEAD ref from the last successful pipeline run for this repo.
 */
export function getLastSuccessfulHeadRef(db: Database.Database, repo: string): string | null {
  const row = db.prepare(
    `SELECT head_ref FROM pipeline_runs WHERE repo = ? AND status = 'complete' AND head_ref IS NOT NULL ORDER BY completed_at DESC LIMIT 1`,
  ).get(repo) as { head_ref: string } | undefined;
  return row?.head_ref ?? null;
}

/**
 * Store the current HEAD ref for this pipeline run.
 */
export function storeHeadRef(db: Database.Database, runId: string, repoRoot: string): void {
  try {
    const headRef = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf-8",
      timeout: EXEC_TIMEOUT_MS,
    }).trim();

    db.prepare(
      `UPDATE pipeline_runs SET head_ref = ? WHERE run_id = ?`,
    ).run(headRef, runId);
  } catch {
    log.warn("Failed to store HEAD ref for incremental scanning");
  }
}

/**
 * Get the current HEAD commit hash.
 */
function getCurrentHeadRef(repoRoot: string): string | null {
  try {
    return execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: repoRoot,
      encoding: "utf-8",
      timeout: EXEC_TIMEOUT_MS,
    }).trim();
  } catch {
    return null;
  }
}

/**
 * Compute files changed between a base ref and HEAD.
 * Returns relative file paths.
 */
function computeChangedFiles(repoRoot: string, baseRef: string): string[] {
  try {
    const output = execFileSync(
      "git",
      ["diff", "--name-only", `${baseRef}..HEAD`],
      { cwd: repoRoot, encoding: "utf-8", timeout: EXEC_TIMEOUT_MS },
    );
    return output
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
  } catch (error) {
    log.warn(`Failed to compute changed files from ${baseRef}: ${error}`);
    return [];
  }
}

/**
 * Build a reverse dependency map from the import graph.
 * Returns: Map<filePath, Set<files that import it>>
 */
export function buildReverseDependencyMap(
  importGraph: ImportGraphEdge[],
): Map<string, Set<string>> {
  const reverseMap = new Map<string, Set<string>>();
  for (const edge of importGraph) {
    const target = edge.toPath;
    if (!reverseMap.has(target)) {
      reverseMap.set(target, new Set());
    }
    reverseMap.get(target)!.add(edge.fromFilePath);
  }
  return reverseMap;
}

/**
 * Expand changed files with their importers (1-hop dependency propagation).
 * If A.ts changed and B.ts imports A.ts, both A.ts and B.ts are in the result.
 */
export function expandWithDependents(
  changedFiles: string[],
  importGraph: ImportGraphEdge[],
): { expanded: string[]; depExpandedCount: number } {
  const reverseMap = buildReverseDependencyMap(importGraph);
  const expandedSet = new Set(changedFiles);
  let depExpandedCount = 0;

  for (const changedFile of changedFiles) {
    const dependents = reverseMap.get(changedFile);
    if (dependents) {
      for (const dep of dependents) {
        if (!expandedSet.has(dep)) {
          expandedSet.add(dep);
          depExpandedCount++;
        }
      }
    }
  }

  if (depExpandedCount > 0) {
    log.info(`Dependency propagation: ${changedFiles.length} changed → ${expandedSet.size} total (${depExpandedCount} importers added)`);
  }

  return { expanded: [...expandedSet], depExpandedCount };
}
