import { execFileSync } from "node:child_process";
import path from "node:path";

export function resolveRepo(repoPath: string): { root: string; name: string } {
  const absPath = path.resolve(repoPath);
  try {
    const root = execFileSync("git", ["rev-parse", "--show-toplevel"], {
      cwd: absPath,
      encoding: "utf-8",
    }).trim();
    return { root, name: path.basename(absPath) };
  } catch {
    return { root: absPath, name: path.basename(absPath) };
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
