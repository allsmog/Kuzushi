/**
 * Workspace dependency analysis and deterministic clustering.
 *
 * Two capabilities:
 *   1. buildWorkspaceDependencyMap — analyze internal deps between workspace members
 *   2. clusterWorkspaceMembers — group tightly-coupled packages into scan modules
 */

import path from "node:path";
import { getLogger } from "../logger.js";
import {
  parseCargoDeps,
  parseGoModDeps,
  parsePackageJsonDeps,
  readPackageName,
} from "../monorepo/dependency-graph.js";
import type { RawDiscoveryNode } from "./adapters/types.js";
import { compareModulePaths, normalizeModuleName } from "./helpers.js";
import type { DiscoveredModule, DiscoveredProduct } from "./types.js";

const log = getLogger("discovery-clustering");

// ── Types ────────────────────────────────────────────────────────────

export interface WorkspaceDependencyMap {
  /** Module path → set of sibling module paths it depends on. */
  internalDeps: Map<string, Set<string>>;
  /** Package name (e.g., "@n8n/core") → module path. */
  packageNameToPath: Map<string, string>;
  /** Formatted summary for the LLM carving prompt. */
  promptSummary: string;
}

// ── Patterns for test/tooling packages to exclude from scan modules ──

const TOOLING_PATTERNS = [
  /\beslint[-/]/i,
  /\bstylelint[-/]/i,
  /\btypescript[-/]config/i,
  /\bvitest[-/]config/i,
  /\bprettier[-/]/i,
  /\bbenchmark/i,
  /\bstorybook/i,
  /\btesting\//i,
  /\be2e\b/i,
  /\btest-utils?\b/i,
  /\bcreate-node\b/i,
  /\bcode-health\b/i,
  /\bjanitor\b/i,
];

function isToolingPackage(nodePath: string, name: string): boolean {
  const combined = `${nodePath} ${name}`;
  return TOOLING_PATTERNS.some((p) => p.test(combined));
}

// ── Build workspace dependency map ───────────────────────────────────

export async function buildWorkspaceDependencyMap(
  repoRoot: string,
  rawNodes: RawDiscoveryNode[],
): Promise<WorkspaceDependencyMap> {
  const leaves = rawNodes.filter((n) => !n.isContainer);
  const containers = rawNodes.filter((n) => n.isContainer);

  // Build lookup: which container owns which leaf (by childPaths)
  const leafToContainer = new Map<string, RawDiscoveryNode>();
  for (const container of containers) {
    for (const childPath of container.childPaths) {
      // Innermost container wins (same logic as graph.ts)
      const existing = leafToContainer.get(childPath);
      if (!existing || container.path.length > existing.path.length) {
        leafToContainer.set(childPath, container);
      }
    }
  }

  // Collect workspace-member leaves (those claimed by a container)
  const workspaceLeaves = leaves.filter((n) => leafToContainer.has(n.path));

  // Read package names for all workspace leaves
  const packageNameToPath = new Map<string, string>();
  for (const leaf of workspaceLeaves) {
    const absPath = path.resolve(repoRoot, leaf.path);
    const pkgName = await readPackageName(absPath);
    if (pkgName) {
      packageNameToPath.set(pkgName, leaf.path);
    }
    // Also register the leaf name (adapter-determined) as a fallback
    if (leaf.name && !packageNameToPath.has(leaf.name)) {
      packageNameToPath.set(leaf.name, leaf.path);
    }
  }

  // Read dependencies for each workspace leaf, resolve to sibling paths
  const internalDeps = new Map<string, Set<string>>();
  for (const leaf of workspaceLeaves) {
    const absPath = path.resolve(repoRoot, leaf.path);
    const deps = await resolveLeafDeps(absPath, leaf);
    const siblingDeps = new Set<string>();

    for (const dep of deps) {
      const siblingPath = packageNameToPath.get(dep);
      if (siblingPath && siblingPath !== leaf.path) {
        siblingDeps.add(siblingPath);
      }
    }

    internalDeps.set(leaf.path, siblingDeps);
  }

  const promptSummary = buildPromptSummary(internalDeps, packageNameToPath);
  log.info(`Workspace deps: ${workspaceLeaves.length} leaves, ${countEdges(internalDeps)} edges`);

  return { internalDeps, packageNameToPath, promptSummary };
}

async function resolveLeafDeps(absPath: string, leaf: RawDiscoveryNode): Promise<string[]> {
  const deps: string[] = [];
  const bs = leaf.buildSystem?.toLowerCase() ?? "";
  const lang = leaf.language?.toLowerCase() ?? "";

  if (bs.includes("package.json") || lang === "javascript" || lang === "typescript") {
    deps.push(...(await parsePackageJsonDeps(absPath)));
  }
  if (bs.includes("go.mod") || lang === "go") {
    deps.push(...(await parseGoModDeps(absPath)));
  }
  if (bs.includes("cargo") || lang === "rust") {
    deps.push(...(await parseCargoDeps(absPath)));
  }

  return deps;
}

function countEdges(deps: Map<string, Set<string>>): number {
  let count = 0;
  for (const s of deps.values()) count += s.size;
  return count;
}

function buildPromptSummary(
  internalDeps: Map<string, Set<string>>,
  nameMap: Map<string, string>,
): string {
  // Invert nameMap: path → shortest package name
  const pathToName = new Map<string, string>();
  for (const [name, p] of nameMap) {
    const existing = pathToName.get(p);
    if (!existing || name.length < existing.length) {
      pathToName.set(p, name);
    }
  }

  const lines: string[] = [];
  const sorted = [...internalDeps.entries()]
    .filter(([, deps]) => deps.size > 0)
    .sort((a, b) => b[1].size - a[1].size);

  for (const [leafPath, deps] of sorted.slice(0, 20)) {
    const name = pathToName.get(leafPath) ?? leafPath;
    const depNames = [...deps]
      .slice(0, 8)
      .map((d) => pathToName.get(d) ?? d)
      .join(", ");
    const suffix = deps.size > 8 ? ` +${deps.size - 8} more` : "";
    lines.push(`${name} → ${depNames}${suffix} (${deps.size} internal deps)`);
  }

  return lines.join("\n");
}

// ── Deterministic clustering ─────────────────────────────────────────

export function clusterWorkspaceMembers(
  depMap: WorkspaceDependencyMap,
  rawNodes: RawDiscoveryNode[],
  products: DiscoveredProduct[],
): DiscoveredModule[] {
  const { internalDeps } = depMap;
  if (internalDeps.size === 0) return [];

  const containers = rawNodes.filter((n) => n.isContainer);
  const leaves = rawNodes.filter((n) => !n.isContainer);

  // Build container lookup
  const leafToContainer = new Map<string, RawDiscoveryNode>();
  for (const container of containers) {
    for (const childPath of container.childPaths) {
      const existing = leafToContainer.get(childPath);
      if (!existing || container.path.length > existing.path.length) {
        leafToContainer.set(childPath, container);
      }
    }
  }

  // Group workspace leaves by their owning container
  const containerGroups = new Map<string, string[]>();
  for (const [leafPath] of internalDeps) {
    const container = leafToContainer.get(leafPath);
    const containerPath = container?.path ?? "__standalone__";
    const group = containerGroups.get(containerPath) ?? [];
    group.push(leafPath);
    containerGroups.set(containerPath, group);
  }

  const modules: DiscoveredModule[] = [];

  // Process each container's members
  for (const [containerPath, memberPaths] of containerGroups) {
    if (containerPath === "__standalone__") continue;

    // Build undirected adjacency restricted to this container's members
    const memberSet = new Set(memberPaths);
    const adjacency = new Map<string, Set<string>>();
    for (const m of memberPaths) {
      adjacency.set(m, new Set());
    }
    for (const m of memberPaths) {
      const deps = internalDeps.get(m);
      if (!deps) continue;
      for (const dep of deps) {
        if (memberSet.has(dep)) {
          adjacency.get(m)!.add(dep);
          adjacency.get(dep)!.add(m);
        }
      }
    }

    // Find connected components via BFS
    const visited = new Set<string>();
    const components: string[][] = [];
    for (const m of memberPaths) {
      if (visited.has(m)) continue;
      const component: string[] = [];
      const queue = [m];
      while (queue.length > 0) {
        const current = queue.pop()!;
        if (visited.has(current)) continue;
        visited.add(current);
        component.push(current);
        for (const neighbor of adjacency.get(current) ?? []) {
          if (!visited.has(neighbor)) {
            queue.push(neighbor);
          }
        }
      }
      components.push(component);
    }

    // Convert each component into a DiscoveredModule
    const container = containers.find((c) => c.path === containerPath);
    const product = products.find((p) => p.path === containerPath);

    for (const component of components) {
      // Separate scannable packages from tooling
      const scannable = component.filter((p) => {
        const leaf = leaves.find((l) => l.path === p);
        return !isToolingPackage(p, leaf?.name ?? "");
      });

      if (scannable.length === 0) continue;

      // Hub = member with highest in-degree within the component
      const hub = pickHub(scannable, internalDeps);
      const hubLeaf = leaves.find((l) => l.path === hub);

      const includePaths = scannable.length > 1 ? scannable.sort(compareModulePaths) : undefined;

      modules.push({
        name: deriveClusterName(hub, hubLeaf, container, product),
        path: hub,
        includePaths,
        description: hubLeaf?.description ?? "",
        language: hubLeaf?.language ?? "unknown",
        buildSystem: hubLeaf?.buildSystem || undefined,
        moduleKind: "workspace-member",
        productPath: containerPath,
        discoveryEvidence: ["deterministic-clustering"],
      });
    }
  }

  // Add standalone modules (not in any workspace) from the original raw nodes
  const clusteredPaths = new Set<string>();
  for (const m of modules) {
    clusteredPaths.add(m.path);
    for (const p of m.includePaths ?? []) {
      clusteredPaths.add(p);
    }
  }

  for (const leaf of leaves) {
    if (clusteredPaths.has(leaf.path)) continue;
    if (leafToContainer.has(leaf.path)) continue; // workspace member handled above
    if (isToolingPackage(leaf.path, leaf.name)) continue;

    modules.push({
      name: normalizeModuleName(leaf.name),
      path: leaf.path,
      description: leaf.description,
      language: leaf.language,
      buildSystem: leaf.buildSystem || undefined,
      moduleKind: "standalone",
      discoveryEvidence: leaf.evidence,
    });
  }

  modules.sort((a, b) => compareModulePaths(a.path, b.path));
  return modules;
}

function pickHub(members: string[], internalDeps: Map<string, Set<string>>): string {
  let bestPath = members[0];
  let bestInDegree = 0;

  for (const m of members) {
    let inDegree = 0;
    for (const [, deps] of internalDeps) {
      if (deps.has(m)) inDegree++;
    }
    if (inDegree > bestInDegree) {
      bestInDegree = inDegree;
      bestPath = m;
    }
  }

  return bestPath;
}

function deriveClusterName(
  hubPath: string,
  hubLeaf: RawDiscoveryNode | undefined,
  container: RawDiscoveryNode | undefined,
  product: DiscoveredProduct | undefined,
): string {
  // Prefer container/product name if unique enough
  if (container?.name && container.name !== "." && container.name !== "root") {
    return normalizeModuleName(container.name);
  }
  if (product?.path && product.path !== ".") {
    return normalizeModuleName(path.basename(product.path));
  }
  // Fall back to hub leaf name
  return normalizeModuleName(hubLeaf?.name ?? path.basename(hubPath));
}
