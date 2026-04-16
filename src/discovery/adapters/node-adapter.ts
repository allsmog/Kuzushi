import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import path from "node:path";
import YAML from "yaml";
import { DEFAULT_IGNORED_DIRS } from "../../repo-walk.js";
import {
  collectManifestDirectories,
  dedupeStrings,
  matchesWorkspacePattern,
  normalizePromptPath,
  normalizeWorkspacePattern,
  readFirstSnippet,
  readJson,
  readText,
} from "../helpers.js";
import type { DiscoveryAdapter, RawDiscoveryNode } from "./types.js";

export class NodeAdapter implements DiscoveryAdapter {
  readonly id = "node";

  async discover(repoRoot: string, maxDepth: number): Promise<RawDiscoveryNode[]> {
    const nodes: RawDiscoveryNode[] = [];

    // Find all workspace roots (root + nested pnpm-workspace.yaml / package.json workspaces)
    const workspaceRoots = await findNodeWorkspaceRoots(repoRoot, maxDepth);

    // All package.json dirs in the repo (collected once, reused across workspaces)
    const allCandidates = await collectManifestDirectories(repoRoot, "package.json", maxDepth);

    // Track which candidates are claimed by any workspace
    const claimedPaths = new Set<string>();

    for (const wsRoot of workspaceRoots) {
      const wsAbsPath = path.resolve(repoRoot, wsRoot.relPath);
      const wsRelPath = wsRoot.relPath;

      // Resolve patterns relative to the workspace root
      const childPaths: string[] = [];
      for (const candidate of allCandidates) {
        if (candidate === wsRelPath) continue; // skip the workspace root itself

        // Candidate must be under this workspace root
        if (wsRelPath !== "." && !candidate.startsWith(`${wsRelPath}/`)) continue;

        // Strip workspace prefix to match against workspace-relative patterns
        const relToWs = wsRelPath === "." ? candidate : candidate.slice(wsRelPath.length + 1);

        if (matchesAnyPattern(relToWs, wsRoot.patterns)) {
          childPaths.push(candidate);
          claimedPaths.add(candidate);
        }
      }

      // Build child nodes
      for (const childPath of childPaths) {
        const absPath = path.resolve(repoRoot, childPath);
        const pkg = await readJson(path.join(absPath, "package.json"));
        const name = typeof pkg?.["name"] === "string" ? pkg["name"] : path.basename(childPath);
        const language = await detectNodeLanguage(absPath, pkg);
        const readme = await readFirstSnippet(absPath);

        nodes.push({
          path: childPath,
          name,
          language,
          buildSystem: "package.json",
          description: readme?.snippet ?? "",
          evidence: ["package.json"],
          isContainer: false,
          childPaths: [],
        });
      }

      // Container node for this workspace
      if (childPaths.length > 0) {
        nodes.push({
          path: wsRelPath,
          name: wsRoot.name,
          language: "JavaScript",
          buildSystem: "package.json",
          description: "",
          evidence: wsRoot.evidence,
          isContainer: true,
          containerKind: "workspace-root",
          childPaths,
        });
      }
    }

    // If no workspaces found at all, check root for a standalone app
    if (workspaceRoots.length === 0) {
      const rootNode = await buildStandaloneNode(repoRoot, ".");
      if (rootNode) {
        nodes.push(rootNode);
      }
    }

    return nodes;
  }
}

// ── Workspace root discovery ──────────────────────────────────────────

interface NodeWorkspaceRoot {
  relPath: string; // repo-relative path to the workspace root dir
  name: string;
  patterns: string[]; // workspace glob patterns
  evidence: string[];
}

/**
 * Walk the repo for Node workspace roots: any directory containing
 * pnpm-workspace.yaml or package.json with a `workspaces` field.
 */
async function findNodeWorkspaceRoots(
  repoRoot: string,
  maxDepth: number,
): Promise<NodeWorkspaceRoot[]> {
  const roots: NodeWorkspaceRoot[] = [];
  await walkForNodeWorkspaces(repoRoot, repoRoot, 0, maxDepth, roots);
  // Sort shallowest first so parent workspaces are processed first
  roots.sort((a, b) => {
    const aDepth = a.relPath === "." ? 0 : a.relPath.split("/").length;
    const bDepth = b.relPath === "." ? 0 : b.relPath.split("/").length;
    return aDepth - bDepth;
  });
  return roots;
}

async function walkForNodeWorkspaces(
  repoRoot: string,
  currentDir: string,
  depth: number,
  maxDepth: number,
  results: NodeWorkspaceRoot[],
): Promise<void> {
  if (depth > maxDepth) return;

  const relPath = normalizePromptPath(path.relative(repoRoot, currentDir));
  const patterns = await readNodeWorkspacePatterns(currentDir);

  if (patterns.length > 0) {
    const evidence: string[] = [];
    if (existsSync(path.join(currentDir, "pnpm-workspace.yaml"))) {
      evidence.push("pnpm-workspace.yaml");
    }
    const pkg = await readJson(path.join(currentDir, "package.json"));
    if (pkg?.["workspaces"]) {
      evidence.push("package.json workspaces");
    }

    results.push({
      relPath,
      name: typeof pkg?.["name"] === "string" ? pkg["name"] : path.basename(currentDir),
      patterns,
      evidence,
    });
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
    await walkForNodeWorkspaces(
      repoRoot,
      path.join(currentDir, entry.name),
      depth + 1,
      maxDepth,
      results,
    );
  }
}

// ── Helpers ───────────────────────────────────────────────────────────

async function readNodeWorkspacePatterns(dir: string): Promise<string[]> {
  const patterns: string[] = [];

  const pnpmWorkspaceRaw = await readText(path.join(dir, "pnpm-workspace.yaml"));
  if (pnpmWorkspaceRaw) {
    try {
      const parsed = YAML.parse(pnpmWorkspaceRaw) as { packages?: unknown } | null;
      if (Array.isArray(parsed?.packages)) {
        for (const entry of parsed.packages) {
          if (typeof entry === "string" && entry.trim()) {
            patterns.push(entry.trim());
          }
        }
      }
    } catch {
      // Ignore malformed workspace files during detection.
    }
  }

  const packageJson = await readJson(path.join(dir, "package.json"));
  const workspaces = packageJson?.["workspaces"];
  if (Array.isArray(workspaces)) {
    for (const entry of workspaces) {
      if (typeof entry === "string" && entry.trim()) {
        patterns.push(entry.trim());
      }
    }
  } else if (
    workspaces &&
    typeof workspaces === "object" &&
    Array.isArray((workspaces as { packages?: unknown }).packages)
  ) {
    for (const entry of (workspaces as { packages: unknown[] }).packages) {
      if (typeof entry === "string" && entry.trim()) {
        patterns.push(entry.trim());
      }
    }
  }

  return dedupeStrings(patterns);
}

function matchesAnyPattern(candidate: string, patterns: string[]): boolean {
  let included = false;
  for (const rawPattern of patterns) {
    const exclude = rawPattern.startsWith("!");
    const pattern = normalizeWorkspacePattern(exclude ? rawPattern.slice(1) : rawPattern);
    if (!pattern) continue;
    if (matchesWorkspacePattern(candidate, pattern)) {
      included = !exclude;
    }
  }
  return included;
}

async function detectNodeLanguage(
  absPath: string,
  pkg: Record<string, unknown> | null,
): Promise<string> {
  if (existsSync(path.join(absPath, "tsconfig.json"))) return "TypeScript";
  const allDeps = { ...asRecord(pkg?.["dependencies"]), ...asRecord(pkg?.["devDependencies"]) };
  if ("typescript" in allDeps) return "TypeScript";
  return "JavaScript";
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

async function buildStandaloneNode(
  repoRoot: string,
  relPath: string,
): Promise<RawDiscoveryNode | null> {
  const absPath = path.resolve(repoRoot, relPath);
  const pkg = await readJson(path.join(absPath, "package.json"));
  if (!pkg) return null;

  const hasMain = typeof pkg["main"] === "string";
  const hasBin = pkg["bin"] !== undefined;
  const hasStart =
    typeof (pkg["scripts"] as Record<string, unknown> | undefined)?.["start"] === "string";
  if (!hasMain && !hasBin && !hasStart) return null;

  const name = typeof pkg["name"] === "string" ? pkg["name"] : path.basename(relPath);
  const language = await detectNodeLanguage(absPath, pkg);
  const readme = await readFirstSnippet(absPath);

  return {
    path: normalizePromptPath(relPath),
    name,
    language,
    buildSystem: "package.json",
    description: readme?.snippet ?? "",
    evidence: ["package.json"],
    isContainer: false,
    childPaths: [],
  };
}
