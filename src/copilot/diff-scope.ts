/**
 * Diff scope helper — Phase D.3.
 *
 * Given a git ref (e.g. "main", "HEAD~5", "v1.2.0"), returns the list of
 * repo-relative file paths that differ from HEAD. Used by the interactive
 * `/since <ref>` view to scope findings + threat elements to just what
 * the operator changed.
 *
 * Runs `git diff --name-only <ref>...HEAD` so the output is symmetric
 * (files changed on either side of the divergence point) — matches the
 * behaviour of `kuzushi scan --since <ref>`.
 *
 * Returns an empty list on error (bad ref, not a repo, git missing) so
 * the shell view can render "no changed files" rather than crashing.
 */

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";

export interface DiffScope {
  /** The git ref the operator passed. */
  ref: string;
  /** Absolute path of the repo root we ran git inside. */
  repoRoot: string;
  /** Repo-relative paths of files that differ. */
  changedFiles: string[];
  /** When true, `git` ran cleanly. `error` carries the message otherwise. */
  ok: boolean;
  error?: string;
}

/**
 * Compute the diff scope. Never throws — always returns a `DiffScope`
 * so the shell has a consistent surface to render against.
 */
export function computeDiffScope(repoRoot: string, ref: string): DiffScope {
  const trimmed = ref.trim();
  if (!trimmed) {
    return { ref, repoRoot, changedFiles: [], ok: false, error: "empty ref" };
  }
  if (!existsSync(path.join(repoRoot, ".git"))) {
    return {
      ref,
      repoRoot,
      changedFiles: [],
      ok: false,
      error: `not a git repo: ${repoRoot}`,
    };
  }
  try {
    const raw = execFileSync("git", ["diff", "--name-only", `${trimmed}...HEAD`], {
      cwd: repoRoot,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    const changedFiles = raw
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    return { ref, repoRoot, changedFiles, ok: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ref, repoRoot, changedFiles: [], ok: false, error: message };
  }
}

/**
 * Filter a collection of objects to those whose `.filePath` matches any
 * entry in `changedFiles`. Exact match only — the caller is responsible
 * for passing paths in the same form (repo-relative or absolute).
 */
export function filterByChangedFiles<T extends { filePath?: string }>(
  items: ReadonlyArray<T>,
  changedFiles: ReadonlyArray<string>,
): T[] {
  if (changedFiles.length === 0) return [];
  const set = new Set(changedFiles);
  return items.filter((item) => (item.filePath ? set.has(item.filePath) : false));
}
