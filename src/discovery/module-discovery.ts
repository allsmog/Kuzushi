import { existsSync } from "node:fs";
import { readFile, readdir, stat } from "node:fs/promises";
import path from "node:path";
import { runStructuredAgentQuery } from "../agent-runtime/execution.js";
import type { AgentRuntime } from "../agent-runtime/types.js";
import { DEFAULT_IGNORED_DIRS, walkRepo } from "../repo-walk.js";
import { toErrorMessage } from "../utils.js";
import type { DiscoveredModule, DiscoveryOptions, DiscoveryResult } from "./types.js";

const DEFAULT_MAX_MODULES = 30;
const DEFAULT_MAX_DEPTH = 4;
const DEFAULT_CLUSTER_THRESHOLD = 50;
const CLUSTER_DETECTION_DEPTH = 2;
const MAX_SNIPPET_CHARS = 500;
const MAX_TREE_LINES = 160;
const ROOT_DISCOVERY_DEPTH = 3;
const MONOREPO_DETECTION_MAX_ENTRIES = 500;
const MONOREPO_FANOUT_THRESHOLD = 5;

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
] as const;

const PASS1_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["reasoning", "modules"],
  properties: {
    reasoning: { type: "string" },
    modules: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name", "path", "description", "language", "needsClustering", "priority"],
        properties: {
          name: { type: "string" },
          path: { type: "string" },
          description: { type: "string" },
          language: { type: "string" },
          buildSystem: { type: "string" },
          needsClustering: { type: "boolean" },
          priority: { type: "string", enum: ["critical", "high", "medium", "low"] },
          securitySignals: { type: "array", items: { type: "string" } },
        },
      },
    },
  },
} as const;

const PASS2_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["reasoning", "clusters"],
  properties: {
    reasoning: { type: "string" },
    clusters: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["name", "path", "description", "language"],
        properties: {
          name: { type: "string" },
          path: { type: "string" },
          description: { type: "string" },
          language: { type: "string" },
          buildSystem: { type: "string" },
        },
      },
    },
  },
} as const;

interface ModuleDiscoveryCandidate extends DiscoveredModule {
  needsClustering?: boolean;
}

interface HeuristicModuleSnapshot {
  rootSummary: string[];
  topLevelDirs: Array<{
    name: string;
    subdirCount: number;
    rootFiles: string[];
    docSnippets: Array<{ path: string; snippet: string }>;
  }>;
  workspaceHints: string[];
  treeLines: string[];
}

interface ClusterSnapshot {
  module: ModuleDiscoveryCandidate;
  summaryLines: string[];
  childDirs: Array<{ name: string; relPath: string; subdirCount: number; buildFiles: string[] }>;
  treeLines: string[];
}

export async function discoverModules(
  monorepoRoot: string,
  runtime: AgentRuntime,
  options: DiscoveryOptions = {},
): Promise<DiscoveryResult> {
  const model = options.model?.trim();
  if (!model) {
    throw new Error("A discovery model is required for module discovery.");
  }

  const maxModules = options.maxModules ?? DEFAULT_MAX_MODULES;
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const clusterThreshold = options.clusterThreshold ?? DEFAULT_CLUSTER_THRESHOLD;

  const snapshot = await buildHeuristicSnapshot(monorepoRoot);
  const pass1 = await runStructuredAgentQuery({
    prompt: buildPass1Prompt(monorepoRoot, snapshot, maxModules, clusterThreshold),
    cwd: monorepoRoot,
    model,
    allowedTools: [],
    runtimeOptions: { runtime, thinkingDisabled: true },
    schema: PASS1_SCHEMA,
    strict: true,
    retryInvalidStructuredOutput: 1,
  });

  if (pass1.executionError) {
    throw new Error(`module discovery failed: ${pass1.executionError}`);
  }

  const pass1Result = normalizePass1Result(pass1.structuredOutput, monorepoRoot, maxModules);
  let modules: DiscoveredModule[] = pass1Result.modules.map((module) => ({
    name: module.name,
    path: module.path,
    description: module.description,
    language: module.language,
    buildSystem: module.buildSystem,
    isParent: module.needsClustering ? true : undefined,
    priority: module.priority,
    securitySignals: module.securitySignals,
  }));
  let costUsd = pass1.costUsd;
  const reasoningParts = [pass1Result.reasoning];

  // Heuristic override: walk each module to detect deep fan-out that the LLM may
  // have missed when setting needsClustering. A module with many directories at
  // any depth (not just immediate children) should be clustered.
  for (const module of pass1Result.modules) {
    if (!module.needsClustering) {
      const moduleRoot = resolveModuleDirectory(monorepoRoot, module.path);
      const deepEntries = await walkRepo(moduleRoot, {
        maxDepth: CLUSTER_DETECTION_DEPTH,
        maxEntries: 500,
        ignoredDirs: DEFAULT_IGNORED_DIRS,
      });
      const dirCount = deepEntries.filter((e) => e.kind === "dir").length;
      if (dirCount >= clusterThreshold) {
        module.needsClustering = true;
      }
    }
    if (!module.needsClustering) {
      continue;
    }

    const snapshotForModule = await buildClusterSnapshot(monorepoRoot, module, maxDepth, clusterThreshold);
    if (!snapshotForModule || snapshotForModule.childDirs.length === 0) {
      continue;
    }

    const pass2 = await runStructuredAgentQuery({
      prompt: buildPass2Prompt(monorepoRoot, snapshotForModule, maxModules),
      cwd: monorepoRoot,
      model,
      allowedTools: [],
      runtimeOptions: { runtime, thinkingDisabled: true },
      schema: PASS2_SCHEMA,
      strict: true,
      retryInvalidStructuredOutput: 1,
    });

    if (pass2.executionError) {
      throw new Error(`module clustering failed for ${module.name}: ${pass2.executionError}`);
    }

    const pass2Result = normalizePass2Result(pass2.structuredOutput, monorepoRoot, module, maxModules);
    modules = modules.concat(pass2Result.clusters);
    costUsd += pass2.costUsd;
    reasoningParts.push(pass2Result.reasoning);
  }

  modules = dedupeAndSortModules(modules).slice(0, maxModules);

  return {
    modules,
    costUsd,
    reasoning: reasoningParts.filter(Boolean).join("\n\n"),
  };
}

export async function inspectModuleRoot(
  monorepoRoot: string,
  modulePath: string,
): Promise<Omit<DiscoveredModule, "name" | "path">> {
  const absolutePath = resolveModuleDirectory(monorepoRoot, modulePath);
  const buildFiles = await detectBuildFiles(absolutePath);
  const language = await detectLanguage(absolutePath, buildFiles);
  const readme = await readFirstSnippet(absolutePath, README_FILES);

  return {
    description: readme?.snippet ?? "Manual module scan unit",
    language,
    buildSystem: buildFiles[0],
  };
}

export async function looksLikeMonorepo(rootPath: string): Promise<boolean> {
  const workspaceHints = await detectWorkspaceHints(rootPath);
  if (workspaceHints.length > 0) {
    return true;
  }

  const entries = await walkRepo(rootPath, {
    maxDepth: 2,
    maxEntries: MONOREPO_DETECTION_MAX_ENTRIES,
    ignoredDirs: DEFAULT_IGNORED_DIRS,
  });

  const topLevelDirs = new Set<string>();
  const buildBearingTopLevelDirs = new Set<string>();
  const secondLevelDirCounts = new Map<string, number>();

  for (const entry of entries) {
    const segments = entry.relPath.split("/");
    const topLevel = segments[0];
    if (!topLevel || DEFAULT_IGNORED_DIRS.has(topLevel)) {
      continue;
    }

    if (entry.kind === "dir" && entry.depth === 1) {
      topLevelDirs.add(topLevel);
      continue;
    }

    if (segments.length < 2) {
      continue;
    }

    topLevelDirs.add(topLevel);

    if (entry.kind === "dir" && entry.depth === 2) {
      secondLevelDirCounts.set(topLevel, (secondLevelDirCounts.get(topLevel) ?? 0) + 1);
      continue;
    }

    if (entry.kind === "file" && BUILD_FILES.includes(path.basename(entry.relPath) as typeof BUILD_FILES[number])) {
      buildBearingTopLevelDirs.add(topLevel);
    }
  }

  if (buildBearingTopLevelDirs.size >= 2) {
    return true;
  }

  const fanoutTopLevelDirs = [...secondLevelDirCounts.values()]
    .filter((count) => count >= MONOREPO_FANOUT_THRESHOLD)
    .length;

  return topLevelDirs.size >= 4 && fanoutTopLevelDirs >= 2;
}

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

function normalizePass1Result(
  raw: unknown,
  monorepoRoot: string,
  maxModules: number,
): { reasoning: string; modules: ModuleDiscoveryCandidate[] } {
  const record = coerceRecord(raw);
  const reasoning = asString(record.reasoning) ?? "";
  const modules = Array.isArray(record.modules)
    ? record.modules
      .map((entry) => normalizePass1Module(entry, monorepoRoot))
      .filter((entry): entry is ModuleDiscoveryCandidate => entry !== null)
      .slice(0, maxModules)
    : [];

  return { reasoning, modules };
}

function normalizePass2Result(
  raw: unknown,
  monorepoRoot: string,
  parentModule: ModuleDiscoveryCandidate,
  maxModules: number,
): { reasoning: string; clusters: DiscoveredModule[] } {
  const record = coerceRecord(raw);
  const reasoning = asString(record.reasoning) ?? "";
  const clusters = Array.isArray(record.clusters)
    ? record.clusters
      .map((entry) => normalizeClusterModule(entry, monorepoRoot, parentModule))
      .filter((entry): entry is DiscoveredModule => entry !== null)
      .slice(0, maxModules)
    : [];

  return { reasoning, clusters };
}

function normalizePass1Module(raw: unknown, monorepoRoot: string): ModuleDiscoveryCandidate | null {
  const record = coerceRecord(raw);
  const name = normalizeModuleName(asString(record.name) ?? "");
  const modulePath = sanitizeDiscoveredPath(asString(record.path), monorepoRoot);
  if (!modulePath) {
    return null;
  }

  const rawPriority = asString(record.priority);
  const priority = (rawPriority === "critical" || rawPriority === "high" || rawPriority === "medium" || rawPriority === "low")
    ? rawPriority
    : undefined;

  const securitySignals = Array.isArray(record.securitySignals)
    ? record.securitySignals.filter((s): s is string => typeof s === "string").slice(0, 5)
    : undefined;

  return {
    name,
    path: modulePath,
    description: asString(record.description) ?? "",
    language: asString(record.language) ?? "unknown",
    buildSystem: asString(record.buildSystem) ?? undefined,
    needsClustering: record.needsClustering === true,
    priority,
    securitySignals: securitySignals?.length ? securitySignals : undefined,
  };
}

function normalizeClusterModule(
  raw: unknown,
  monorepoRoot: string,
  parentModule: ModuleDiscoveryCandidate,
): DiscoveredModule | null {
  const record = coerceRecord(raw);
  const name = normalizeModuleName(asString(record.name) ?? "");
  const modulePath = sanitizeDiscoveredPath(asString(record.path), monorepoRoot);
  if (!modulePath || modulePath === parentModule.path) {
    return null;
  }

  const parentAbs = path.resolve(monorepoRoot, parentModule.path);
  const candidateAbs = path.resolve(monorepoRoot, modulePath);
  if (candidateAbs !== parentAbs && !candidateAbs.startsWith(`${parentAbs}${path.sep}`)) {
    return null;
  }

  return {
    name,
    path: modulePath,
    description: asString(record.description) ?? "",
    language: asString(record.language) ?? "unknown",
    buildSystem: asString(record.buildSystem) ?? undefined,
    parentModule: parentModule.name,
  };
}

async function buildHeuristicSnapshot(monorepoRoot: string): Promise<HeuristicModuleSnapshot> {
  const entries = await walkRepo(monorepoRoot, {
    maxDepth: ROOT_DISCOVERY_DEPTH,
    maxEntries: 2000,
    ignoredDirs: DEFAULT_IGNORED_DIRS,
  });

  const treeLines = formatTreeLines(entries, MAX_TREE_LINES);
  const rootSummary = await summarizeRootFiles(monorepoRoot);
  const topLevelDirs = await collectTopLevelDirs(monorepoRoot);
  const workspaceHints = await detectWorkspaceHints(monorepoRoot);

  return {
    rootSummary,
    topLevelDirs,
    workspaceHints,
    treeLines,
  };
}

async function buildClusterSnapshot(
  monorepoRoot: string,
  module: ModuleDiscoveryCandidate,
  maxDepth: number,
  clusterThreshold: number,
): Promise<ClusterSnapshot | null> {
  const moduleRoot = resolveModuleDirectory(monorepoRoot, module.path);
  const childDirs = await collectImmediateChildDirs(moduleRoot, module.path);
  if (childDirs.length === 0) {
    return null;
  }

  // The LLM already decided this module needs clustering in Pass 1 (needsClustering=true).
  // Only bail if there are truly no children to cluster — don't second-guess the LLM with
  // a shallow immediate-child count, since the real service layer may be several levels deep
  // (e.g., product/ → src/ → services/ → 190 microservices).

  const entries = await walkRepo(moduleRoot, {
    maxDepth: maxDepth,
    maxEntries: 2000,
    ignoredDirs: DEFAULT_IGNORED_DIRS,
  });

  const treeLines = formatTreeLines(entries, MAX_TREE_LINES);
  const summaryLines = await summarizeRootFiles(moduleRoot, module.path);

  return {
    module,
    summaryLines,
    childDirs,
    treeLines,
  };
}

async function summarizeRootFiles(rootPath: string, relPrefix = "."): Promise<string[]> {
  const lines: string[] = [];

  for (const fileName of [...README_FILES, ...BUILD_FILES]) {
    const absolutePath = path.join(rootPath, fileName);
    if (!existsSync(absolutePath)) {
      continue;
    }

    if (README_FILES.includes(fileName as typeof README_FILES[number])) {
      const snippet = await readSnippet(absolutePath);
      if (snippet) {
        lines.push(`${normalizePromptPath(path.join(relPrefix, fileName))}: ${snippet}`);
      }
      continue;
    }

    lines.push(`${normalizePromptPath(path.join(relPrefix, fileName))}: present`);
  }

  return lines;
}

async function collectTopLevelDirs(monorepoRoot: string): Promise<HeuristicModuleSnapshot["topLevelDirs"]> {
  let entries;
  try {
    entries = await readdir(monorepoRoot, { withFileTypes: true });
  } catch {
    return [];
  }

  const results: HeuristicModuleSnapshot["topLevelDirs"] = [];
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isDirectory() || DEFAULT_IGNORED_DIRS.has(entry.name) || entry.name.startsWith(".")) {
      continue;
    }

    const absolutePath = path.join(monorepoRoot, entry.name);
    const rootFiles = await listRootFiles(absolutePath);
    const docSnippets = await Promise.all(
      README_FILES.map(async (fileName) => {
        const snippet = await readSnippet(path.join(absolutePath, fileName));
        return snippet ? { path: `${entry.name}/${fileName}`, snippet } : null;
      }),
    );

    results.push({
      name: entry.name,
      subdirCount: await countImmediateSubdirs(absolutePath),
      rootFiles,
      docSnippets: docSnippets.filter((value): value is NonNullable<typeof value> => value !== null),
    });
  }

  return results;
}

async function collectImmediateChildDirs(
  rootPath: string,
  rootRelPath: string,
): Promise<ClusterSnapshot["childDirs"]> {
  let entries;
  try {
    entries = await readdir(rootPath, { withFileTypes: true });
  } catch {
    return [];
  }

  const results: ClusterSnapshot["childDirs"] = [];
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    if (!entry.isDirectory() || DEFAULT_IGNORED_DIRS.has(entry.name) || entry.name.startsWith(".")) {
      continue;
    }

    const absolutePath = path.join(rootPath, entry.name);
    results.push({
      name: entry.name,
      relPath: normalizePromptPath(path.join(rootRelPath, entry.name)),
      subdirCount: await countImmediateSubdirs(absolutePath),
      buildFiles: await detectBuildFiles(absolutePath),
    });
  }

  return results;
}

async function detectWorkspaceHints(monorepoRoot: string): Promise<string[]> {
  const hints: string[] = [];

  if (existsSync(path.join(monorepoRoot, "pnpm-workspace.yaml"))) {
    hints.push("pnpm-workspace.yaml present");
  }

  const packageJson = await readText(path.join(monorepoRoot, "package.json"));
  if (packageJson.includes("\"workspaces\"")) {
    hints.push("package.json declares workspaces");
  }

  const cargoToml = await readText(path.join(monorepoRoot, "Cargo.toml"));
  if (cargoToml.includes("[workspace]")) {
    hints.push("Cargo workspace present");
  }

  if (existsSync(path.join(monorepoRoot, "go.work"))) {
    hints.push("go.work present");
  }

  if (existsSync(path.join(monorepoRoot, "settings.gradle")) || existsSync(path.join(monorepoRoot, "settings.gradle.kts"))) {
    hints.push("Gradle multi-project settings present");
  }

  if (existsSync(path.join(monorepoRoot, "WORKSPACE")) || existsSync(path.join(monorepoRoot, "MODULE.bazel"))) {
    hints.push("Bazel workspace present");
  }

  return hints;
}

async function detectBuildFiles(rootPath: string): Promise<string[]> {
  const present: string[] = [];
  for (const fileName of BUILD_FILES) {
    if (existsSync(path.join(rootPath, fileName))) {
      present.push(fileName);
    }
  }
  return present;
}

async function detectLanguage(rootPath: string, buildFiles: string[] = []): Promise<string> {
  if (buildFiles.includes("Cargo.toml")) return "Rust";
  if (buildFiles.includes("go.mod") || buildFiles.includes("go.work")) return "Go";
  if (buildFiles.includes("pom.xml") || buildFiles.includes("build.gradle") || buildFiles.includes("build.gradle.kts")) {
    return "Java";
  }
  if (buildFiles.includes("package.json") || buildFiles.includes("pnpm-workspace.yaml")) {
    const packageJson = await readText(path.join(rootPath, "package.json"));
    if (packageJson.includes("\"typescript\"")) {
      return "TypeScript";
    }
    return "JavaScript";
  }

  const entries = await walkRepo(rootPath, {
    maxDepth: 2,
    maxEntries: 200,
    ignoredDirs: DEFAULT_IGNORED_DIRS,
  });
  const extensions = new Set(
    entries
      .filter((entry) => entry.kind === "file")
      .map((entry) => path.extname(entry.relPath).toLowerCase()),
  );

  if (extensions.has(".ts") || extensions.has(".tsx")) return "TypeScript";
  if (extensions.has(".js") || extensions.has(".jsx")) return "JavaScript";
  if (extensions.has(".py")) return "Python";
  if (extensions.has(".go")) return "Go";
  if (extensions.has(".rs")) return "Rust";
  if (extensions.has(".java") || extensions.has(".kt")) return "Java";
  return "unknown";
}

function buildPass1Prompt(
  monorepoRoot: string,
  snapshot: HeuristicModuleSnapshot,
  maxModules: number,
  clusterThreshold: number,
): string {
  return [
    "You are identifying security-relevant scan units inside a large monorepo.",
    "Each module should be something a security team would threat-model independently.",
    "Return only contiguous directory roots relative to the monorepo root.",
    "Do not emit non-contiguous sibling groups.",
    `Return at most ${maxModules} top-level modules.`,
    `Set needsClustering=true for modules that are broad enough to merit deeper sub-clustering. This includes modules with many services at ANY depth (not just immediate children) — for example a product with 10 top-level dirs where one of them contains 100+ service directories nested 2-3 levels deep. If the tree sample shows a large fan-out of services anywhere under a module, mark it for clustering.`,
    "",
    "For each module, assign a security priority:",
    "  critical — auth, crypto, secrets/key management, payment, code execution, privilege escalation surface",
    "  high     — DB access, user input processing, webhooks, external API calls, file I/O, session management",
    "  medium   — internal services, background jobs, config management, logging",
    "  low      — UI-only components, docs, test infra, CLI tooling, build scripts, dev tooling",
    "Also list 1-3 concise securitySignals that explain the priority (e.g. \"handles OAuth tokens\", \"executes user-supplied code\").",
    "",
    `Monorepo root: ${monorepoRoot}`,
    "",
    "## Workspace hints",
    ...(snapshot.workspaceHints.length > 0 ? snapshot.workspaceHints.map((line) => `- ${line}`) : ["- none"]),
    "",
    "## Root summary",
    ...(snapshot.rootSummary.length > 0 ? snapshot.rootSummary.map((line) => `- ${line}`) : ["- none"]),
    "",
    "## Top-level directories",
    ...snapshot.topLevelDirs.flatMap((dir) => {
      const lines = [
        `- ${dir.name}: immediateSubdirs=${dir.subdirCount}; rootFiles=${dir.rootFiles.join(", ") || "none"}`,
      ];
      for (const doc of dir.docSnippets) {
        lines.push(`  ${doc.path}: ${doc.snippet}`);
      }
      return lines;
    }),
    "",
    "## Repository tree sample",
    ...snapshot.treeLines,
    "",
    "Return JSON matching the schema exactly.",
  ].join("\n");
}

function buildPass2Prompt(
  monorepoRoot: string,
  snapshot: ClusterSnapshot,
  maxModules: number,
): string {
  return [
    "You are clustering one large monorepo product into focused security scan units.",
    "Each cluster must be a single contiguous directory root relative to the monorepo root.",
    "Do not return the parent module itself and do not return overlapping aliases for the same exact directory.",
    `Return 3-${Math.min(15, maxModules)} clusters only when they are security-coherent domains.`,
    "",
    `Monorepo root: ${monorepoRoot}`,
    `Parent module: ${snapshot.module.name} (${snapshot.module.path})`,
    `Parent description: ${snapshot.module.description}`,
    "",
    "## Parent summary",
    ...(snapshot.summaryLines.length > 0 ? snapshot.summaryLines.map((line) => `- ${line}`) : ["- none"]),
    "",
    "## Immediate child directories",
    ...snapshot.childDirs.map((entry) => (
      `- ${entry.relPath}: immediateSubdirs=${entry.subdirCount}; buildFiles=${entry.buildFiles.join(", ") || "none"}`
    )),
    "",
    "## Tree sample",
    ...snapshot.treeLines,
    "",
    "Return JSON matching the schema exactly.",
  ].join("\n");
}

function sanitizeDiscoveredPath(rawPath: string | undefined, monorepoRoot: string): string | null {
  const trimmed = rawPath?.trim();
  if (!trimmed || path.isAbsolute(trimmed)) {
    return null;
  }

  const resolved = path.resolve(monorepoRoot, trimmed);
  const normalizedRoot = path.resolve(monorepoRoot);
  if (resolved !== normalizedRoot && !resolved.startsWith(`${normalizedRoot}${path.sep}`)) {
    return null;
  }

  if (!existsSync(resolved)) {
    return null;
  }

  return normalizePromptPath(path.relative(monorepoRoot, resolved));
}

function dedupeAndSortModules(modules: DiscoveredModule[]): DiscoveredModule[] {
  const byKey = new Map<string, DiscoveredModule>();

  for (const module of modules) {
    const normalized: DiscoveredModule = {
      ...module,
      name: normalizeModuleName(module.name),
      path: normalizePromptPath(module.path),
      description: module.description.trim(),
      language: module.language.trim() || "unknown",
      buildSystem: module.buildSystem?.trim() || undefined,
      isParent: module.isParent === true ? true : undefined,
      parentModule: module.parentModule?.trim() || undefined,
    };
    const key = `${normalized.name}::${normalized.path}`;
    if (!byKey.has(key)) {
      byKey.set(key, normalized);
    }
  }

  return [...byKey.values()].sort((left, right) => {
    const leftDepth = left.path.split("/").length;
    const rightDepth = right.path.split("/").length;
    if (leftDepth !== rightDepth) {
      return leftDepth - rightDepth;
    }
    return left.name.localeCompare(right.name);
  });
}

function formatTreeLines(
  entries: Array<{ relPath: string; kind: "file" | "dir"; depth: number }>,
  maxLines: number,
): string[] {
  return entries
    .filter((entry) => entry.kind === "dir" || entry.depth <= 2)
    .slice(0, maxLines)
    .map((entry) => `${"  ".repeat(Math.max(0, entry.depth - 1))}- ${entry.relPath}${entry.kind === "dir" ? "/" : ""}`);
}

async function listRootFiles(rootPath: string, max = 12): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(rootPath, { withFileTypes: true });
  } catch {
    return [];
  }
  return entries
    .filter((e) => e.isFile() && !e.name.startsWith("."))
    .map((e) => e.name)
    .sort()
    .slice(0, max);
}

async function countImmediateSubdirs(rootPath: string): Promise<number> {
  let entries;
  try {
    entries = await readdir(rootPath, { withFileTypes: true });
  } catch {
    return 0;
  }

  return entries.filter((entry) => entry.isDirectory() && !DEFAULT_IGNORED_DIRS.has(entry.name) && !entry.name.startsWith(".")).length;
}

async function readFirstSnippet(rootPath: string, fileNames: readonly string[]): Promise<{ path: string; snippet: string } | undefined> {
  for (const fileName of fileNames) {
    const absolutePath = path.join(rootPath, fileName);
    const snippet = await readSnippet(absolutePath);
    if (snippet) {
      return { path: fileName, snippet };
    }
  }
  return undefined;
}

async function readSnippet(filePath: string): Promise<string | undefined> {
  const content = await readText(filePath);
  if (!content) {
    return undefined;
  }

  return content
    .replace(/\s+/g, " ")
    .replace(/[`#>*_-]+/g, " ")
    .trim()
    .slice(0, MAX_SNIPPET_CHARS);
}

async function readText(filePath: string): Promise<string> {
  try {
    return await readFile(filePath, "utf-8");
  } catch {
    return "";
  }
}

function normalizePromptPath(filePath: string): string {
  return filePath.replace(/\\/g, "/").replace(/^\.\/+/, "").replace(/^$/, ".");
}

function asString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed || undefined;
}

function coerceRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object") {
    return {};
  }
  return value as Record<string, unknown>;
}

export function formatDiscoveryError(error: unknown): string {
  return toErrorMessage(error);
}
