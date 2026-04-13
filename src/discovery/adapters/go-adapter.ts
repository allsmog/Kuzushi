import { readdir } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORED_DIRS } from "../../repo-walk.js";
import type { DiscoveryAdapter, RawDiscoveryNode } from "./types.js";
import {
  collectManifestDirectories,
  dedupeStrings,
  normalizePromptPath,
  normalizeWorkspaceMember,
  readFirstSnippet,
  readText,
} from "../helpers.js";

export class GoAdapter implements DiscoveryAdapter {
  readonly id = "go";

  async discover(repoRoot: string, maxDepth: number): Promise<RawDiscoveryNode[]> {
    const nodes: RawDiscoveryNode[] = [];

    // Find all go.work files (root + nested)
    const goWorkFiles = await findGoWorkFiles(repoRoot, maxDepth);
    const claimedByGoWork = new Set<string>();

    for (const goWorkRelDir of goWorkFiles) {
      const goWorkAbsDir = path.resolve(repoRoot, goWorkRelDir);
      const goWorkPatterns = await readGoWorkPatterns(goWorkAbsDir);
      if (goWorkPatterns.length === 0) continue;

      const childPaths: string[] = [];

      for (const pattern of goWorkPatterns) {
        // Patterns in go.work are relative to the go.work file
        const targetRelToRepo = goWorkRelDir === "."
          ? pattern
          : normalizePromptPath(`${goWorkRelDir}/${pattern}`);
        const absPath = path.resolve(repoRoot, targetRelToRepo);
        const goMod = await readText(path.join(absPath, "go.mod"));
        if (!goMod) continue;

        claimedByGoWork.add(targetRelToRepo);
        childPaths.push(targetRelToRepo);

        const name = parseGoModuleName(goMod) ?? path.basename(targetRelToRepo);
        const readme = await readFirstSnippet(absPath);

        nodes.push({
          path: targetRelToRepo,
          name,
          language: "Go",
          buildSystem: "go.mod",
          description: readme?.snippet ?? "",
          evidence: ["go.mod"],
          isContainer: false,
          childPaths: [],
        });
      }

      if (childPaths.length > 0) {
        nodes.push({
          path: goWorkRelDir,
          name: goWorkRelDir === "." ? "go-workspace" : path.basename(goWorkRelDir),
          language: "Go",
          buildSystem: "go.work",
          description: "",
          evidence: ["go.work"],
          isContainer: true,
          containerKind: "go-workspace",
          childPaths,
        });
      }
    }

    // Walk for standalone go.mod files not claimed by any go.work
    const allGoModDirs = await collectManifestDirectories(repoRoot, "go.mod", maxDepth);
    for (const dir of allGoModDirs) {
      if (claimedByGoWork.has(dir)) continue;
      // Skip dirs that are go.work roots themselves
      if (goWorkFiles.includes(dir)) continue;

      const absPath = path.resolve(repoRoot, dir);
      const goMod = await readText(path.join(absPath, "go.mod"));
      if (!goMod) continue;

      const name = parseGoModuleName(goMod) ?? path.basename(dir);
      const readme = await readFirstSnippet(absPath);

      nodes.push({
        path: dir,
        name,
        language: "Go",
        buildSystem: "go.mod",
        description: readme?.snippet ?? "",
        evidence: ["go.mod"],
        isContainer: false,
        childPaths: [],
      });
    }

    return nodes;
  }
}

// ── go.work discovery ─────────────────────────────────────────────────

async function findGoWorkFiles(repoRoot: string, maxDepth: number): Promise<string[]> {
  const results: string[] = [];
  await walkForGoWork(repoRoot, repoRoot, 0, maxDepth, results);
  return results.sort();
}

async function walkForGoWork(
  repoRoot: string,
  currentDir: string,
  depth: number,
  maxDepth: number,
  results: string[],
): Promise<void> {
  if (depth > maxDepth) return;

  const goWorkContent = await readText(path.join(currentDir, "go.work"));
  if (goWorkContent) {
    results.push(normalizePromptPath(path.relative(repoRoot, currentDir)));
  }

  let entries;
  try {
    entries = await readdir(currentDir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith(".") || DEFAULT_IGNORED_DIRS.has(entry.name)) continue;
    await walkForGoWork(repoRoot, path.join(currentDir, entry.name), depth + 1, maxDepth, results);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────

async function readGoWorkPatterns(goWorkDir: string): Promise<string[]> {
  const raw = await readText(path.join(goWorkDir, "go.work"));
  if (!raw) return [];

  const patterns: string[] = [];
  const lines = raw.split("\n");
  let inUseBlock = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("//")) continue;

    if (trimmed === "use (" || trimmed.startsWith("use(")) {
      inUseBlock = true;
      continue;
    }
    if (inUseBlock && trimmed === ")") {
      inUseBlock = false;
      continue;
    }

    if (inUseBlock) {
      const member = normalizeWorkspaceMember(trimmed);
      if (member) patterns.push(member);
      continue;
    }

    if (trimmed.startsWith("use ")) {
      const member = normalizeWorkspaceMember(trimmed.slice(4));
      if (member) patterns.push(member);
    }
  }

  return dedupeStrings(patterns);
}

function parseGoModuleName(goModContent: string): string | null {
  const match = goModContent.match(/^\s*module\s+(\S+)/m);
  if (!match?.[1]) return null;
  return match[1].split("/").pop() ?? match[1];
}
