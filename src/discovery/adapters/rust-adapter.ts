import { readdir } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORED_DIRS } from "../../repo-walk.js";
import {
  collectManifestDirectories,
  dedupeStrings,
  matchesWorkspacePattern,
  normalizePromptPath,
  normalizeWorkspacePattern,
  parseTomlStringArray,
  readFirstSnippet,
  readText,
} from "../helpers.js";
import type { DiscoveryAdapter, RawDiscoveryNode } from "./types.js";

export class RustAdapter implements DiscoveryAdapter {
  readonly id = "rust";

  async discover(repoRoot: string, maxDepth: number): Promise<RawDiscoveryNode[]> {
    const nodes: RawDiscoveryNode[] = [];

    // Find all Cargo workspace roots (root + nested)
    const workspaceRoots = await findCargoWorkspaceRoots(repoRoot, maxDepth);
    const claimedByWorkspace = new Set<string>();

    // All Cargo.toml dirs in the repo
    const allCargoDirs = await collectManifestDirectories(repoRoot, "Cargo.toml", maxDepth);

    for (const wsRelDir of workspaceRoots) {
      const wsAbsDir = path.resolve(repoRoot, wsRelDir);
      const cargoContent = await readText(path.join(wsAbsDir, "Cargo.toml"));
      const { includePatterns, excludePatterns } = parseCargoWorkspace(cargoContent);

      const childPaths: string[] = [];

      for (const candidate of allCargoDirs) {
        if (candidate === wsRelDir) continue; // skip workspace root itself
        // Candidate must be under this workspace root
        if (wsRelDir !== "." && !candidate.startsWith(`${wsRelDir}/`)) continue;

        const relToWs = wsRelDir === "." ? candidate : candidate.slice(wsRelDir.length + 1);
        if (matchesCargo(relToWs, includePatterns, excludePatterns)) {
          childPaths.push(candidate);
          claimedByWorkspace.add(candidate);
        }
      }

      for (const childPath of childPaths) {
        const absPath = path.resolve(repoRoot, childPath);
        const cargo = await readText(path.join(absPath, "Cargo.toml"));
        const name = parseCrateNameFromToml(cargo) ?? path.basename(childPath);
        const readme = await readFirstSnippet(absPath);

        nodes.push({
          path: childPath,
          name,
          language: "Rust",
          buildSystem: "Cargo.toml",
          description: readme?.snippet ?? "",
          evidence: ["Cargo.toml"],
          isContainer: false,
          childPaths: [],
        });
      }

      if (childPaths.length > 0) {
        nodes.push({
          path: wsRelDir,
          name:
            parseCrateNameFromToml(cargoContent) ??
            (wsRelDir === "." ? "rust-workspace" : path.basename(wsRelDir)),
          language: "Rust",
          buildSystem: "Cargo.toml",
          description: "",
          evidence: ["Cargo.toml [workspace]"],
          isContainer: true,
          containerKind: "cargo-workspace",
          childPaths,
        });
      }

      claimedByWorkspace.add(wsRelDir);
    }

    // Walk for standalone Cargo.toml files not under any workspace
    for (const dir of allCargoDirs) {
      if (claimedByWorkspace.has(dir)) continue;

      const absPath = path.resolve(repoRoot, dir);
      const cargo = await readText(path.join(absPath, "Cargo.toml"));
      if (!cargo || !cargo.includes("[package]")) continue;

      const name = parseCrateNameFromToml(cargo) ?? path.basename(dir);
      const readme = await readFirstSnippet(absPath);

      nodes.push({
        path: dir,
        name,
        language: "Rust",
        buildSystem: "Cargo.toml",
        description: readme?.snippet ?? "",
        evidence: ["Cargo.toml"],
        isContainer: false,
        childPaths: [],
      });
    }

    return nodes;
  }
}

// ── Cargo workspace discovery ─────────────────────────────────────────

async function findCargoWorkspaceRoots(repoRoot: string, maxDepth: number): Promise<string[]> {
  const results: string[] = [];
  await walkForCargoWorkspace(repoRoot, repoRoot, 0, maxDepth, results);
  return results.sort();
}

async function walkForCargoWorkspace(
  repoRoot: string,
  currentDir: string,
  depth: number,
  maxDepth: number,
  results: string[],
): Promise<void> {
  if (depth > maxDepth) return;

  const cargo = await readText(path.join(currentDir, "Cargo.toml"));
  if (cargo && cargo.includes("[workspace]")) {
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
    await walkForCargoWorkspace(
      repoRoot,
      path.join(currentDir, entry.name),
      depth + 1,
      maxDepth,
      results,
    );
  }
}

// ── Helpers ───────────────────────────────────────────────────────────

function parseCargoWorkspace(cargoContent: string): {
  includePatterns: string[];
  excludePatterns: string[];
} {
  const includePatterns: string[] = [];
  const excludePatterns: string[] = [];

  const membersMatch = cargoContent.match(/members\s*=\s*\[([\s\S]*?)\]/m);
  if (membersMatch) {
    includePatterns.push(...parseTomlStringArray(membersMatch[1]));
  }

  const excludeMatch = cargoContent.match(/exclude\s*=\s*\[([\s\S]*?)\]/m);
  if (excludeMatch) {
    excludePatterns.push(...parseTomlStringArray(excludeMatch[1]));
  }

  return {
    includePatterns: dedupeStrings(includePatterns),
    excludePatterns: dedupeStrings(excludePatterns),
  };
}

function matchesCargo(
  candidate: string,
  includePatterns: string[],
  excludePatterns: string[],
): boolean {
  const included = includePatterns.some((p) =>
    matchesWorkspacePattern(candidate, normalizeWorkspacePattern(p)),
  );
  if (!included) return false;

  const excluded = excludePatterns.some((p) =>
    matchesWorkspacePattern(candidate, normalizeWorkspacePattern(p)),
  );
  return !excluded;
}

function parseCrateNameFromToml(cargoContent: string): string | null {
  const match = cargoContent.match(/^\s*name\s*=\s*"([^"]+)"/m);
  return match?.[1] ?? null;
}
