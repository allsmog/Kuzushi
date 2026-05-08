import { execFileSync } from "node:child_process";
import { realpathSync } from "node:fs";
import path from "node:path";

/**
 * Resolve a user-provided repo path into a scope for a run.
 *
 * `root` is the user's target — the absolute path they actually pointed at.
 * That is what config loading, DB persistence, and `.kuzushi/` artifacts
 * anchor on, so the scan stays scoped to what the operator asked for.
 *
 * `gitRoot` is the enclosing git toplevel **only when different from
 * `root`**. It is kept as a separate escape hatch for operations that
 * genuinely need to reach beyond the target (e.g. cross-service taint
 * analysis, git diff base resolution). Most callers should use `root`.
 */
export function resolveRepo(repoPath: string): {
  root: string;
  name: string;
  gitRoot?: string;
} {
  const absPath = path.resolve(repoPath);
  const name = path.basename(absPath);
  try {
    const gitToplevel = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: absPath,
      encoding: "utf-8",
    }).trim();
    const gitRoot = path.resolve(gitToplevel);
    // Compare via realpath on both sides so symlink-normalized paths
    // (notably macOS /var → /private/var) don't falsely split apart.
    if (canonical(gitRoot) === canonical(absPath)) {
      return { root: absPath, name };
    }
    return { root: absPath, name, gitRoot };
  } catch {
    return { root: absPath, name };
  }
}

function canonical(p: string): string {
  try {
    return realpathSync(p);
  } catch {
    return p;
  }
}

export function parseCommaSeparatedList(raw: string): string[] {
  return raw
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
}

export function isShutdownCapableRuntime(
  runtime: unknown,
): runtime is { shutdown: () => Promise<void> | void } {
  return (
    typeof runtime === "object" &&
    runtime !== null &&
    typeof (runtime as { shutdown?: unknown }).shutdown === "function"
  );
}
