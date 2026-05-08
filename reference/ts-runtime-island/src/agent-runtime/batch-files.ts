import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";

/** Sanitize a path component to prevent traversal (strip slashes, .., etc.) */
function sanitizeComponent(value: string): string {
  return path.basename(value.replace(/[/\\]/g, "_"));
}

function tryChmod(target: string, mode: number): void {
  try {
    chmodSync(target, mode);
  } catch {
    // Best-effort: filesystems without POSIX perms (e.g. Windows, some
    // network mounts) will reject chmod — content still gets written.
  }
}

/**
 * Write batch data to `.kuzushi/batches/<runId>/<taskId>-<batchIdx>.json`.
 * Returns the absolute path to the written file so the subprocess can `Read` it.
 *
 * The `.kuzushi/` tree, the `batches/` subtree, and each batch file are
 * created with owner-only POSIX permissions because they routinely contain
 * source-code snippets, finding evidence, and other sensitive context.
 */
export function writeBatchFile(
  repoRoot: string,
  runId: string,
  taskId: string,
  batchIdx: number,
  data: unknown,
): string {
  const safeRunId = sanitizeComponent(runId);
  const safeTaskId = sanitizeComponent(taskId);
  const kuzushiDir = path.join(repoRoot, ".kuzushi");
  const batchesDir = path.join(kuzushiDir, "batches");
  const dir = path.join(batchesDir, safeRunId);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  tryChmod(kuzushiDir, 0o700);
  tryChmod(batchesDir, 0o700);
  tryChmod(dir, 0o700);
  const filePath = path.join(dir, `${safeTaskId}-${String(batchIdx).padStart(4, "0")}.json`);
  writeFileSync(filePath, JSON.stringify(data, null, 2), { mode: 0o600 });
  tryChmod(filePath, 0o600);
  return filePath;
}

/**
 * Remove all batch files for a given run.
 */
export function cleanupBatchFiles(repoRoot: string, runId: string): void {
  const safeRunId = sanitizeComponent(runId);
  const dir = path.join(repoRoot, ".kuzushi", "batches", safeRunId);
  rmSync(dir, { recursive: true, force: true });
}
