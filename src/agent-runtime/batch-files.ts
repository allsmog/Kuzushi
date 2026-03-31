import { mkdirSync, writeFileSync, rmSync } from "node:fs";
import path from "node:path";

/**
 * Write batch data to `.kuzushi/batches/<runId>/<taskId>-<batchIdx>.json`.
 * Returns the absolute path to the written file so the subprocess can `Read` it.
 */
export function writeBatchFile(
  repoRoot: string,
  runId: string,
  taskId: string,
  batchIdx: number,
  data: unknown,
): string {
  const dir = path.join(repoRoot, ".kuzushi", "batches", runId);
  mkdirSync(dir, { recursive: true });
  const filePath = path.join(dir, `${taskId}-${String(batchIdx).padStart(4, "0")}.json`);
  writeFileSync(filePath, JSON.stringify(data, null, 2));
  return filePath;
}

/**
 * Remove all batch files for a given run.
 */
export function cleanupBatchFiles(repoRoot: string, runId: string): void {
  const dir = path.join(repoRoot, ".kuzushi", "batches", runId);
  rmSync(dir, { recursive: true, force: true });
}
