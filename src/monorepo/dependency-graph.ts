/**
 * Phase 0 — Build a module dependency graph from workspace manifests.
 *
 * Parses pnpm-workspace.yaml, package.json workspaces, go.work, and
 * Cargo.toml workspace members to build an adjacency list of which
 * modules depend on which. Ranks modules by in-degree (how many other
 * modules depend on them). Pure filesystem analysis — zero LLM cost.
 */

import { readFile } from "node:fs/promises";
import path from "node:path";
import type { DiscoveredModule, DiscoveredProduct } from "../discovery/types.js";
import type {
  ModuleDependencyGraph,
  ModuleDependencyNode,
  ModuleInteractionEdge,
} from "./types.js";

/**
 * Build a dependency graph for the given modules within a monorepo.
 *
 * Uses discovery evidence to decide which manifest parsers to run per module.
 * Returns an adjacency list with per-module in-degree ranking.
 */
export async function buildDependencyGraph(
  monorepoRoot: string,
  modules: DiscoveredModule[],
  products?: DiscoveredProduct[],
): Promise<ModuleDependencyGraph> {
  const modulesByPackageName = new Map<string, string>();

  for (const m of modules) {
    modulesByPackageName.set(m.name, m.path);
  }

  // Phase 1: Resolve package names from manifests (npm packages often have
  // different names from their directory names, e.g., "@n8n/core" vs "core")
  for (const m of modules) {
    const absPath = path.resolve(monorepoRoot, m.path);
    const pkgName = await readPackageName(absPath);
    if (pkgName) {
      modulesByPackageName.set(pkgName, m.path);
    }
  }

  // Phase 2: Parse each module's dependencies and match against siblings
  const dependsOn = new Map<string, Set<string>>();
  const dependedOnBy = new Map<string, Set<string>>();

  for (const m of modules) {
    dependsOn.set(m.path, new Set());
    dependedOnBy.set(m.path, new Set());
  }

  for (const m of modules) {
    const absPath = path.resolve(monorepoRoot, m.path);
    const deps = await resolveModuleDeps(absPath, m);

    for (const dep of deps) {
      const siblingPath = modulesByPackageName.get(dep);
      if (siblingPath && siblingPath !== m.path) {
        dependsOn.get(m.path)!.add(siblingPath);
        dependedOnBy.get(siblingPath)!.add(m.path);
      }
    }
  }

  // Phase 3: Compute rankings
  const nodes = new Map<string, ModuleDependencyNode>();
  const rankedModules = modules
    .map((m) => ({
      moduleId: m.path,
      modulePath: m.path,
      inDegree: dependedOnBy.get(m.path)?.size ?? 0,
      outDegree: dependsOn.get(m.path)?.size ?? 0,
    }))
    .sort((a, b) => b.inDegree - a.inDegree);

  for (let i = 0; i < rankedModules.length; i++) {
    const rm = rankedModules[i];
    nodes.set(rm.moduleId, { ...rm, dependencyRank: i });
  }

  return { dependsOn, dependedOnBy, nodes };
}

// ── Manifest Parsers ───────────────────────────────────────────────────

export async function readPackageName(moduleDir: string): Promise<string | null> {
  const pkgPath = path.join(moduleDir, "package.json");
  try {
    const raw = await readFile(pkgPath, "utf-8");
    const pkg = JSON.parse(raw);
    return typeof pkg.name === "string" ? pkg.name : null;
  } catch {
    return null;
  }
}

export async function resolveModuleDeps(
  moduleDir: string,
  module: DiscoveredModule,
): Promise<string[]> {
  const deps: string[] = [];
  const evidence = module.discoveryEvidence ?? [];
  const lang = module.language?.toLowerCase() ?? "";

  // npm/yarn/pnpm package.json dependencies
  if (
    evidence.some((e) => e.includes("package.json")) ||
    lang === "javascript" ||
    lang === "typescript"
  ) {
    deps.push(...(await parsePackageJsonDeps(moduleDir)));
  }

  // go.mod require directives
  if (evidence.some((e) => e.includes("go.mod")) || lang === "go") {
    deps.push(...(await parseGoModDeps(moduleDir)));
  }

  // Cargo.toml path dependencies
  if (evidence.some((e) => e.includes("Cargo.toml")) || lang === "rust") {
    deps.push(...(await parseCargoDeps(moduleDir)));
  }

  // .csproj ProjectReference elements
  if (
    module.moduleKind === "solution-project" ||
    evidence.some((e) => e.includes(".csproj") || e.includes(".vcxproj"))
  ) {
    deps.push(...(await parseCsprojReferences(moduleDir)));
  }

  return deps;
}

export async function parsePackageJsonDeps(moduleDir: string): Promise<string[]> {
  const pkgPath = path.join(moduleDir, "package.json");
  try {
    const raw = await readFile(pkgPath, "utf-8");
    const pkg = JSON.parse(raw);
    const allDeps: string[] = [];
    for (const field of ["dependencies", "devDependencies", "peerDependencies"]) {
      const section = pkg[field];
      if (section && typeof section === "object") {
        allDeps.push(...Object.keys(section));
      }
    }
    return allDeps;
  } catch {
    return [];
  }
}

export async function parseGoModDeps(moduleDir: string): Promise<string[]> {
  const goModPath = path.join(moduleDir, "go.mod");
  try {
    const raw = await readFile(goModPath, "utf-8");
    const deps: string[] = [];
    const requireRegex = /require\s+(\S+)\s+/g;
    let match: RegExpExecArray | null;
    while ((match = requireRegex.exec(raw)) !== null) {
      deps.push(match[1]);
    }
    const blockRegex = /require\s*\(\s*([\s\S]*?)\)/g;
    while ((match = blockRegex.exec(raw)) !== null) {
      const lines = match[1].split("\n");
      for (const line of lines) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("//")) {
          const parts = trimmed.split(/\s+/);
          if (parts[0]) deps.push(parts[0]);
        }
      }
    }
    return deps;
  } catch {
    return [];
  }
}

export async function parseCargoDeps(moduleDir: string): Promise<string[]> {
  const cargoPath = path.join(moduleDir, "Cargo.toml");
  try {
    const raw = await readFile(cargoPath, "utf-8");
    const deps: string[] = [];
    const pathDepRegex = /(\w[\w-]*)\s*=\s*\{[^}]*path\s*=\s*"([^"]+)"/g;
    let match: RegExpExecArray | null;
    while ((match = pathDepRegex.exec(raw)) !== null) {
      deps.push(match[1]);
    }
    return deps;
  } catch {
    return [];
  }
}

export async function parseCsprojReferences(moduleDir: string): Promise<string[]> {
  const deps: string[] = [];
  const { readdir: rd } = await import("node:fs/promises");
  try {
    const entries = await rd(moduleDir);
    for (const entry of entries) {
      if (!entry.endsWith(".csproj") && !entry.endsWith(".vcxproj") && !entry.endsWith(".fsproj"))
        continue;
      const projPath = path.join(moduleDir, entry);
      try {
        const raw = await readFile(projPath, "utf-8");
        const refRegex = /<ProjectReference\s+Include="([^"]+)"/g;
        let match: RegExpExecArray | null;
        while ((match = refRegex.exec(raw)) !== null) {
          // Extract project name from the reference path
          const refPath = match[1].replace(/\\/g, "/");
          const refName = path.basename(refPath, path.extname(refPath));
          deps.push(refName);
        }
      } catch {
        // skip unreadable project files
      }
    }
  } catch {
    // skip if dir can't be read
  }
  return deps;
}

/**
 * Print a summary of the dependency graph for logging.
 */
export function formatDependencyGraphSummary(graph: ModuleDependencyGraph): string {
  const lines: string[] = [];
  const sorted = [...graph.nodes.values()].sort((a, b) => a.dependencyRank - b.dependencyRank);
  for (const node of sorted.slice(0, 10)) {
    const dependedBy = graph.dependedOnBy.get(node.moduleId);
    const depNames = dependedBy ? [...dependedBy].slice(0, 5).join(", ") : "";
    const suffix = (dependedBy?.size ?? 0) > 5 ? ` +${(dependedBy?.size ?? 0) - 5} more` : "";
    lines.push(
      `  #${node.dependencyRank + 1} ${node.moduleId} (in-degree: ${node.inDegree}) ← ${depNames}${suffix}`,
    );
  }
  return lines.join("\n");
}

export function deriveInteractionEdgesFromDependencyGraph(
  graph: ModuleDependencyGraph,
): ModuleInteractionEdge[] {
  const edges: ModuleInteractionEdge[] = [];
  for (const [source, targets] of graph.dependsOn.entries()) {
    for (const target of targets) {
      edges.push({
        source,
        target,
        interactionType: "import",
        evidence: ["workspace dependency edge"],
      });
    }
  }
  return edges;
}
