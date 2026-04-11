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
import type { DiscoveredModule } from "../discovery/types.js";
import type { ModuleDependencyGraph, ModuleDependencyNode } from "./types.js";

/**
 * Build a dependency graph for the given modules within a monorepo.
 *
 * Reads each module's manifest files (package.json, go.mod, Cargo.toml)
 * and resolves references to sibling modules. Returns an adjacency list
 * with per-module in-degree ranking.
 */
export async function buildDependencyGraph(
  monorepoRoot: string,
  modules: DiscoveredModule[],
): Promise<ModuleDependencyGraph> {
  const modulesByName = new Map<string, DiscoveredModule>();
  const modulesByPackageName = new Map<string, string>();

  for (const m of modules) {
    modulesByName.set(m.name, m);
  }

  // Phase 1: Resolve package names from manifests (npm packages often have
  // different names from their directory names, e.g., "@n8n/core" vs "core")
  for (const m of modules) {
    const absPath = path.resolve(monorepoRoot, m.path);
    const pkgName = await readPackageName(absPath);
    if (pkgName) {
      modulesByPackageName.set(pkgName, m.name);
    }
    // Also index by directory-based module name as fallback
    modulesByPackageName.set(m.name, m.name);
  }

  // Phase 2: Parse each module's dependencies and match against siblings
  const dependsOn = new Map<string, Set<string>>();
  const dependedOnBy = new Map<string, Set<string>>();

  for (const m of modules) {
    dependsOn.set(m.name, new Set());
    dependedOnBy.set(m.name, new Set());
  }

  for (const m of modules) {
    const absPath = path.resolve(monorepoRoot, m.path);
    const deps = await resolveModuleDeps(absPath, m.language);

    for (const dep of deps) {
      const siblingName = modulesByPackageName.get(dep);
      if (siblingName && siblingName !== m.name) {
        dependsOn.get(m.name)!.add(siblingName);
        dependedOnBy.get(siblingName)!.add(m.name);
      }
    }
  }

  // Phase 3: Compute rankings
  const nodes = new Map<string, ModuleDependencyNode>();
  const rankedModules = modules
    .map((m) => ({
      moduleId: m.name,
      modulePath: m.path,
      inDegree: dependedOnBy.get(m.name)?.size ?? 0,
      outDegree: dependsOn.get(m.name)?.size ?? 0,
    }))
    .sort((a, b) => b.inDegree - a.inDegree);

  for (let i = 0; i < rankedModules.length; i++) {
    const rm = rankedModules[i];
    nodes.set(rm.moduleId, { ...rm, dependencyRank: i });
  }

  return { dependsOn, dependedOnBy, nodes };
}

// ── Manifest Parsers ───────────────────────────────────────────────────

async function readPackageName(moduleDir: string): Promise<string | null> {
  const pkgPath = path.join(moduleDir, "package.json");
  try {
    const raw = await readFile(pkgPath, "utf-8");
    const pkg = JSON.parse(raw);
    return typeof pkg.name === "string" ? pkg.name : null;
  } catch {
    return null;
  }
}

async function resolveModuleDeps(
  moduleDir: string,
  language?: string,
): Promise<string[]> {
  const deps: string[] = [];

  // npm/yarn/pnpm package.json dependencies
  const pkgDeps = await parsePackageJsonDeps(moduleDir);
  deps.push(...pkgDeps);

  // go.mod require directives
  if (language === "go" || language === "Go") {
    const goDeps = await parseGoModDeps(moduleDir);
    deps.push(...goDeps);
  }

  // Cargo.toml path dependencies
  if (language === "rust" || language === "Rust") {
    const cargoDeps = await parseCargoDeps(moduleDir);
    deps.push(...cargoDeps);
  }

  return deps;
}

async function parsePackageJsonDeps(moduleDir: string): Promise<string[]> {
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

async function parseGoModDeps(moduleDir: string): Promise<string[]> {
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

async function parseCargoDeps(moduleDir: string): Promise<string[]> {
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
    lines.push(`  #${node.dependencyRank + 1} ${node.moduleId} (in-degree: ${node.inDegree}) ← ${depNames}${suffix}`);
  }
  return lines.join("\n");
}
