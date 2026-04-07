import { readdir } from "node:fs/promises";
import path from "node:path";

export const DEFAULT_IGNORED_DIRS = new Set([
  ".git",
  ".kuzushi",
  "node_modules",
  "dist",
  "coverage",
  "vendor",
  "target",
  "build",
  ".next",
  "__pycache__",
  ".venv",
  "venv",
]);

export interface RepoWalkEntry {
  relPath: string;
  kind: "file" | "dir";
  depth: number;
}

export interface RepoWalkOptions {
  maxDepth?: number;
  maxEntries?: number;
  ignoredDirs?: ReadonlySet<string>;
}

export async function walkRepo(
  repoRoot: string,
  options: RepoWalkOptions = {},
): Promise<RepoWalkEntry[]> {
  const maxDepth = options.maxDepth ?? 5;
  const maxEntries = options.maxEntries ?? 4000;
  const ignoredDirs = options.ignoredDirs ?? DEFAULT_IGNORED_DIRS;
  const entries: RepoWalkEntry[] = [];
  const stack: Array<{ relDir: string; depth: number }> = [{ relDir: "", depth: 0 }];

  while (stack.length > 0 && entries.length < maxEntries) {
    const next = stack.pop();
    if (!next) break;

    const absDir = path.join(repoRoot, next.relDir);
    let dirEntries;
    try {
      dirEntries = await readdir(absDir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of dirEntries.sort((a, b) => a.name.localeCompare(b.name))) {
      if (entries.length >= maxEntries) {
        break;
      }

      const relPath = next.relDir ? `${next.relDir}/${entry.name}` : entry.name;
      if (entry.isDirectory()) {
        if (ignoredDirs.has(entry.name)) {
          continue;
        }

        entries.push({ relPath, kind: "dir", depth: next.depth + 1 });
        if (next.depth < maxDepth) {
          stack.push({ relDir: relPath, depth: next.depth + 1 });
        }
        continue;
      }

      if (entry.isFile()) {
        entries.push({ relPath, kind: "file", depth: next.depth + 1 });
      }
    }
  }

  return entries;
}
