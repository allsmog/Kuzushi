import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORED_DIRS } from "../../repo-walk.js";
import { normalizePromptPath, readFirstSnippet } from "../helpers.js";
import type { DiscoveryAdapter, RawDiscoveryNode } from "./types.js";

export class NativeAdapter implements DiscoveryAdapter {
  readonly id = "native";

  async discover(repoRoot: string, _maxDepth: number): Promise<RawDiscoveryNode[]> {
    const nodes: RawDiscoveryNode[] = [];

    // Look for SConstruct at root or depth <=2
    const sconstructPaths = await findSConstructFiles(repoRoot, 2);

    for (const relPath of sconstructPaths) {
      const dir = path.dirname(relPath);
      const absDir = dir === "." ? repoRoot : path.resolve(repoRoot, dir);
      const readme = await readFirstSnippet(absDir);
      const normalizedDir = normalizePromptPath(dir);

      nodes.push({
        path: normalizedDir,
        name: normalizedDir === "." ? "native-root" : path.basename(dir),
        language: "C/C++",
        buildSystem: "SConstruct",
        description: readme?.snippet ?? "",
        evidence: ["SConstruct"],
        isContainer: false,
        childPaths: [],
      });
    }

    return nodes;
  }
}

async function findSConstructFiles(repoRoot: string, maxDepth: number): Promise<string[]> {
  const results: string[] = [];
  await walkForSConstruct(repoRoot, repoRoot, 0, maxDepth, results);
  return results.sort();
}

async function walkForSConstruct(
  repoRoot: string,
  currentDir: string,
  depth: number,
  maxDepth: number,
  results: string[],
): Promise<void> {
  if (depth > maxDepth) return;

  if (existsSync(path.join(currentDir, "SConstruct"))) {
    results.push(normalizePromptPath(path.relative(repoRoot, path.join(currentDir, "SConstruct"))));
  }

  if (depth >= maxDepth) return;

  let entries;
  try {
    entries = await readdir(currentDir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith(".") || DEFAULT_IGNORED_DIRS.has(entry.name)) continue;
    await walkForSConstruct(
      repoRoot,
      path.join(currentDir, entry.name),
      depth + 1,
      maxDepth,
      results,
    );
  }
}
