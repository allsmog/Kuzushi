import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORED_DIRS } from "../../repo-walk.js";
import type { DiscoveryAdapter, RawDiscoveryNode } from "./types.js";
import { normalizePromptPath, readFirstSnippet, readText } from "../helpers.js";

const SKIP_DIRS = new Set([
  "test",
  "tests",
  "testdata",
  "mock",
  "mocks",
  "fixture",
  "fixtures",
  "third_party",
  "vendor",
  "tools",
  "examples",
  "example",
]);

const PRODUCTION_RULE_PATTERNS = [
  /\b(?:cc_binary|cc_library|cc_shared_library)\s*\(/,
  /\b(?:go_binary|go_library)\s*\(/,
  /\b(?:java_binary|java_library)\s*\(/,
  /\b(?:py_binary|py_library)\s*\(/,
  /\b(?:rust_binary|rust_library)\s*\(/,
  /\b(?:sh_binary|sh_library)\s*\(/,
  /\b(?:proto_library|grpc_library)\s*\(/,
  /\bgenrule\s*\(/,
];

const TEST_ONLY_PATTERNS = [
  /\b(?:cc_test|go_test|java_test|py_test|rust_test|sh_test)\s*\(/,
];

/**
 * When a subtree has more than this many BUILD packages, collapse them
 * into a single module at the subtree root. Prevents explosion in giant
 * native trees (e.g., src/cpp/ with 200+ BUILD files).
 */
const SUBTREE_COLLAPSE_THRESHOLD = 15;

export class BazelAdapter implements DiscoveryAdapter {
  readonly id = "bazel";

  async discover(repoRoot: string, maxDepth: number): Promise<RawDiscoveryNode[]> {
    const nodes: RawDiscoveryNode[] = [];

    // Check for workspace markers at root
    const workspaceFile = findWorkspaceFile(repoRoot);
    if (!workspaceFile) return nodes;

    // Walk for BUILD / BUILD.bazel files
    const buildFiles = await findBuildFiles(repoRoot, maxDepth);

    // Collect all valid production packages
    interface BazelPackage {
      dir: string;
      language: string;
      buildFileName: string;
    }
    const packages: BazelPackage[] = [];

    for (const buildRelPath of buildFiles) {
      const buildDir = path.dirname(buildRelPath);
      if (buildDir === ".") continue; // skip root BUILD file

      // Skip test/vendor/etc directories
      const parts = buildDir.split("/");
      if (parts.some((p) => SKIP_DIRS.has(p))) continue;

      const absPath = path.resolve(repoRoot, buildRelPath);
      const content = await readText(absPath);
      if (!content) continue;

      // Only include packages with production rules
      const hasProduction = PRODUCTION_RULE_PATTERNS.some((p) => p.test(content));
      const hasTestOnly = TEST_ONLY_PATTERNS.some((p) => p.test(content));
      if (!hasProduction && hasTestOnly) continue;
      if (!hasProduction && !hasTestOnly) continue;

      packages.push({
        dir: buildDir,
        language: inferLanguageFromBuild(content),
        buildFileName: path.basename(buildRelPath),
      });
    }

    // Collapse dense subtrees: group packages by their depth-1 prefix,
    // and if any prefix has too many packages, replace them with one
    // module at the prefix root.
    const collapsed = collapseDenseSubtrees(packages);

    const childPaths: string[] = [];
    for (const pkg of collapsed) {
      const parts = pkg.dir.split("/");
      const readme = await readFirstSnippet(path.resolve(repoRoot, pkg.dir));

      childPaths.push(pkg.dir);
      nodes.push({
        path: pkg.dir,
        name: parts[parts.length - 1],
        language: pkg.language,
        buildSystem: pkg.buildFileName,
        description: readme?.snippet ?? "",
        evidence: [pkg.buildFileName],
        isContainer: false,
        childPaths: [],
      });
    }

    // Container node for the workspace
    if (childPaths.length > 0) {
      nodes.push({
        path: ".",
        name: "bazel-workspace",
        language: "unknown",
        buildSystem: workspaceFile,
        description: "",
        evidence: [workspaceFile],
        isContainer: true,
        containerKind: "bazel-workspace",
        childPaths,
      });
    }

    return nodes;
  }
}

interface BazelPackage {
  dir: string;
  language: string;
  buildFileName: string;
}

/**
 * Group packages by their depth-1 subtree prefix. If a subtree has more
 * than SUBTREE_COLLAPSE_THRESHOLD packages, collapse them into a single
 * module at the subtree root. Picks the dominant language from children.
 */
function collapseDenseSubtrees(packages: BazelPackage[]): BazelPackage[] {
  // Group by depth-1 prefix (first path segment)
  const byPrefix = new Map<string, BazelPackage[]>();
  for (const pkg of packages) {
    const parts = pkg.dir.split("/");
    // Use depth-2 prefix if available (e.g., "src/cpp"), else depth-1
    const prefix = parts.length >= 2 ? `${parts[0]}/${parts[1]}` : parts[0];
    const group = byPrefix.get(prefix) ?? [];
    group.push(pkg);
    byPrefix.set(prefix, group);
  }

  const result: BazelPackage[] = [];
  for (const [prefix, group] of byPrefix) {
    if (group.length <= SUBTREE_COLLAPSE_THRESHOLD) {
      // Small subtree — keep individual packages
      result.push(...group);
    } else {
      // Dense subtree — collapse to prefix root
      const dominantLang = pickDominantLanguage(group);
      result.push({
        dir: prefix,
        language: dominantLang,
        buildFileName: group[0].buildFileName,
      });
    }
  }

  return result;
}

function pickDominantLanguage(packages: BazelPackage[]): string {
  const counts = new Map<string, number>();
  for (const pkg of packages) {
    counts.set(pkg.language, (counts.get(pkg.language) ?? 0) + 1);
  }
  let best = "unknown";
  let bestCount = 0;
  for (const [lang, count] of counts) {
    if (count > bestCount || (count === bestCount && lang !== "unknown")) {
      best = lang;
      bestCount = count;
    }
  }
  return best;
}

function findWorkspaceFile(repoRoot: string): string | null {
  for (const name of ["WORKSPACE.bazel", "WORKSPACE", "MODULE.bazel"]) {
    if (existsSync(path.join(repoRoot, name))) return name;
  }
  return null;
}

function inferLanguageFromBuild(content: string): string {
  if (/\bcc_(?:binary|library)\s*\(/.test(content)) return "C++";
  if (/\bgo_(?:binary|library)\s*\(/.test(content)) return "Go";
  if (/\bjava_(?:binary|library)\s*\(/.test(content)) return "Java";
  if (/\bpy_(?:binary|library)\s*\(/.test(content)) return "Python";
  if (/\brust_(?:binary|library)\s*\(/.test(content)) return "Rust";
  return "unknown";
}

async function findBuildFiles(repoRoot: string, maxDepth: number): Promise<string[]> {
  const results: string[] = [];
  await walkForBuild(repoRoot, repoRoot, 0, maxDepth, results);
  return results.sort();
}

const WORKSPACE_MARKERS = ["WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel"];

async function walkForBuild(
  repoRoot: string,
  currentDir: string,
  depth: number,
  maxDepth: number,
  results: string[],
): Promise<void> {
  if (depth > maxDepth) return;

  let entries;
  try {
    entries = await readdir(currentDir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry.isFile() && (entry.name === "BUILD" || entry.name === "BUILD.bazel")) {
      results.push(normalizePromptPath(path.relative(repoRoot, path.join(currentDir, entry.name))));
    }
    if (entry.isDirectory()) {
      if (entry.name.startsWith(".") || DEFAULT_IGNORED_DIRS.has(entry.name)) continue;
      const childDir = path.join(currentDir, entry.name);
      // Stop at nested WORKSPACE boundaries — those are separate Bazel workspaces
      if (depth > 0 && hasNestedWorkspace(childDir)) continue;
      await walkForBuild(repoRoot, childDir, depth + 1, maxDepth, results);
    }
  }
}

function hasNestedWorkspace(dir: string): boolean {
  return WORKSPACE_MARKERS.some((name) => existsSync(path.join(dir, name)));
}
