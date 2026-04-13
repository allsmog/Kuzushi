import { existsSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { DEFAULT_IGNORED_DIRS } from "../repo-walk.js";
import type { DiscoveredModule, ModuleKind } from "./types.js";

const MAX_WALK_DEPTH = 8;

const README_FILES = ["README.md", "README", "CLAUDE.md"] as const;
const BUILD_FILES = [
  "package.json",
  "pnpm-workspace.yaml",
  "Cargo.toml",
  "go.mod",
  "go.work",
  "settings.gradle",
  "settings.gradle.kts",
  "build.gradle",
  "build.gradle.kts",
  "WORKSPACE",
  "WORKSPACE.bazel",
  "MODULE.bazel",
  "pom.xml",
  "SConstruct",
] as const;

// ── Module name / path helpers ────────────────────────────────────────

export function normalizeModuleName(rawName: string): string {
  const trimmed = rawName.trim().toLowerCase();
  const normalized = trimmed.replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
  return normalized || "module";
}

export function resolveModuleDirectory(monorepoRoot: string, modulePath: string): string {
  const trimmed = modulePath.trim();
  if (!trimmed) {
    throw new Error("module path must not be empty");
  }
  if (path.isAbsolute(trimmed)) {
    throw new Error(`module path "${trimmed}" must be relative to the monorepo root`);
  }

  const resolved = path.resolve(monorepoRoot, trimmed);
  const normalizedRoot = path.resolve(monorepoRoot);
  if (resolved !== normalizedRoot && !resolved.startsWith(`${normalizedRoot}${path.sep}`)) {
    throw new Error(`module path "${trimmed}" escapes the monorepo root`);
  }
  if (!existsSync(resolved)) {
    throw new Error(`module path "${trimmed}" does not exist`);
  }

  return resolved;
}

export function normalizePromptPath(value: string): string {
  const normalized = value.replace(/\\/g, "/").replace(/^\.\/+/, "").replace(/\/+/g, "/");
  return normalized === "" ? "." : normalized.replace(/\/$/, "") || ".";
}

export function compareModulePaths(left: string, right: string): number {
  const leftDepth = left === "." ? 0 : left.split("/").length;
  const rightDepth = right === "." ? 0 : right.split("/").length;
  if (leftDepth !== rightDepth) {
    return leftDepth - rightDepth;
  }
  return left.localeCompare(right);
}

export function isNestedModulePath(parentPath: string, childPath: string): boolean {
  return childPath !== parentPath && childPath.startsWith(`${parentPath}/`);
}

export function rejectOverlappingModules(modules: DiscoveredModule[]): void {
  const sorted = [...modules]
    .map((module) => normalizePromptPath(module.path))
    .sort(compareModulePaths);

  for (let i = 0; i < sorted.length; i += 1) {
    for (let j = i + 1; j < sorted.length; j += 1) {
      if (isNestedModulePath(sorted[i], sorted[j])) {
        throw new Error(
          `overlapping module roots are not supported: "${sorted[i]}" and "${sorted[j]}"`,
        );
      }
    }
  }
}

// ── File reading helpers ──────────────────────────────────────────────

export async function readText(absolutePath: string): Promise<string> {
  try {
    return await readFile(absolutePath, "utf-8");
  } catch {
    return "";
  }
}

export async function readJson(absolutePath: string): Promise<Record<string, unknown> | null> {
  const raw = await readText(absolutePath);
  if (!raw) {
    return null;
  }

  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

export async function readFirstSnippet(
  rootPath: string,
  names: readonly string[] = README_FILES,
): Promise<{ path: string; snippet: string } | null> {
  for (const name of names) {
    const absolutePath = path.join(rootPath, name);
    if (!existsSync(absolutePath)) {
      continue;
    }
    const snippet = await readSnippet(absolutePath);
    if (snippet) {
      return { path: name, snippet };
    }
  }
  return null;
}

export async function readSnippet(absolutePath: string): Promise<string | null> {
  try {
    const raw = await readFile(absolutePath, "utf-8");
    const normalized = raw
      .replace(/\r/g, "")
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .slice(0, 3)
      .join(" ")
      .trim();
    return normalized || null;
  } catch {
    return null;
  }
}

export function dedupeStrings(values: Iterable<string>): string[] {
  const result: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = value.trim();
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    result.push(normalized);
  }
  return result;
}

// ── Build system / language detection ─────────────────────────────────

export async function detectBuildFiles(rootPath: string): Promise<string[]> {
  const present: string[] = [];
  for (const fileName of BUILD_FILES) {
    if (existsSync(path.join(rootPath, fileName))) {
      present.push(fileName);
    }
  }
  return present;
}

export async function detectLanguage(rootPath: string, buildFiles: string[] = []): Promise<string> {
  if (buildFiles.includes("Cargo.toml")) return "Rust";
  if (buildFiles.includes("go.mod") || buildFiles.includes("go.work")) return "Go";
  if (buildFiles.includes("pom.xml") || buildFiles.includes("build.gradle") || buildFiles.includes("build.gradle.kts")) {
    return "Java";
  }
  if (buildFiles.includes("SConstruct")) return "C/C++";
  if (buildFiles.includes("package.json") || buildFiles.includes("pnpm-workspace.yaml")) {
    const packageJson = await readText(path.join(rootPath, "package.json"));
    if (packageJson.includes("\"typescript\"")) {
      return "TypeScript";
    }
    return "JavaScript";
  }
  return "unknown";
}

/**
 * Build a DiscoveredModule from a manual name:path spec or config entry.
 * Replaces the old inspectModuleRoot() for manual/config module creation.
 */
export async function buildManualModule(
  monorepoRoot: string,
  name: string,
  modulePath: string,
  moduleKind: ModuleKind = "standalone",
  evidenceTag = "manual",
): Promise<DiscoveredModule> {
  const absolutePath = resolveModuleDirectory(monorepoRoot, modulePath);
  const buildFiles = await detectBuildFiles(absolutePath);
  const language = await detectLanguage(absolutePath, buildFiles);
  const readme = await readFirstSnippet(absolutePath);

  return {
    name: normalizeModuleName(name),
    path: modulePath,
    description: readme?.snippet ?? "Manual module scan unit",
    language,
    buildSystem: buildFiles[0],
    moduleKind,
    discoveryEvidence: [evidenceTag],
  };
}

// ── Glob pattern helpers (used by adapters) ───────────────────────────

export function normalizeWorkspacePattern(rawPattern: string): string {
  const normalized = normalizePromptPath(rawPattern.replace(/^\.\/+/, ""));
  return normalized === "" ? "." : normalized;
}

export function normalizeWorkspaceMember(raw: string): string | null {
  const trimmed = raw.replace(/^["']|["']$/g, "").trim();
  if (!trimmed) {
    return null;
  }
  return normalizeWorkspacePattern(trimmed);
}

export function matchesWorkspacePattern(modulePath: string, pattern: string): boolean {
  if (pattern === ".") {
    return modulePath === ".";
  }

  const regex = globPatternToRegExp(pattern);
  return regex.test(modulePath);
}

export function globPatternToRegExp(pattern: string): RegExp {
  let source = "^";
  for (let index = 0; index < pattern.length; index += 1) {
    const char = pattern[index];
    if (char === "*") {
      const isDoubleStar = pattern[index + 1] === "*";
      if (isDoubleStar) {
        source += ".*";
        index += 1;
      } else {
        source += "[^/]+";
      }
      continue;
    }
    if (char === "?") {
      source += "[^/]";
      continue;
    }
    if (char === "/") {
      source += "/";
      continue;
    }
    source += escapeRegExp(char);
  }
  source += "$";
  return new RegExp(source);
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function parseTomlStringArray(body: string): string[] {
  const values: string[] = [];
  const regex = /"([^"]+)"|'([^']+)'/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(body)) !== null) {
    const value = match[1] || match[2];
    if (value.trim()) {
      values.push(value.trim());
    }
  }
  return values;
}

// ── Manifest directory walking ────────────────────────────────────────

export type ManifestFile = "package.json" | "go.mod" | "Cargo.toml";

export async function collectManifestDirectories(
  monorepoRoot: string,
  manifestFile: ManifestFile,
  maxDepth = MAX_WALK_DEPTH,
): Promise<string[]> {
  const matches = new Set<string>();
  await walkForManifest(monorepoRoot, monorepoRoot, manifestFile, 0, matches, maxDepth);
  return [...matches].sort(compareModulePaths);
}

async function walkForManifest(
  monorepoRoot: string,
  currentDir: string,
  manifestFile: ManifestFile,
  depth: number,
  matches: Set<string>,
  maxDepth: number,
): Promise<void> {
  if (depth > maxDepth) {
    return;
  }

  if (existsSync(path.join(currentDir, manifestFile))) {
    matches.add(normalizePromptPath(path.relative(monorepoRoot, currentDir)));
  }

  let entries;
  try {
    entries = await readdir(currentDir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const entry of entries) {
    if (!entry.isDirectory()) {
      continue;
    }
    if (entry.name.startsWith(".") || DEFAULT_IGNORED_DIRS.has(entry.name)) {
      continue;
    }
    await walkForManifest(
      monorepoRoot,
      path.join(currentDir, entry.name),
      manifestFile,
      depth + 1,
      matches,
      maxDepth,
    );
  }
}
