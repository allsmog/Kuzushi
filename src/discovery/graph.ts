/**
 * Unified discovery graph algorithm.
 *
 * Takes raw nodes from all adapters and resolves them into
 * non-overlapping leaf modules + product groupings.
 *
 * Four phases:
 *   1. Collect  — merge leaf duplicates, keep containers separate per kind
 *   2. Resolve  — assign children to containers (most-specific adapter wins)
 *   3. Collapse — containers → products, leaves → modules
 *   4. Derive   — build product children lists, truncate to maxModules
 */

import type { RawDiscoveryNode } from "./adapters/types.js";
import { compareModulePaths, rejectOverlappingModules } from "./helpers.js";
import type { DiscoveredModule, DiscoveredProduct, ProductKind } from "./types.js";

// Language specificity ranking — more specific wins during merge.
const LANGUAGE_SPECIFICITY: Record<string, number> = {
  Rust: 10,
  Go: 10,
  "C++": 9,
  "C#": 9,
  "C/C++": 8,
  Java: 8,
  Python: 7,
  TypeScript: 6,
  JavaScript: 5,
  unknown: 0,
};

/** Stable key for a container: path + kind. */
function containerKey(path: string, kind: ProductKind): string {
  return `${path}\0${kind}`;
}

export function resolveDiscoveryGraph(
  rawNodes: RawDiscoveryNode[],
  maxModules: number,
): { modules: DiscoveredModule[]; products: DiscoveredProduct[] } {
  // Phase 1: Collect
  // Leaves are merged by path (multi-adapter hits at the same leaf get unioned).
  // Containers are kept separate per (path, containerKind) so each build system
  // retains its own child declarations and moduleKind mapping.
  const leafByPath = new Map<string, RawDiscoveryNode>();
  const containersByKey = new Map<string, RawDiscoveryNode>();

  for (const node of rawNodes) {
    if (node.isContainer && node.containerKind) {
      const key = containerKey(node.path, node.containerKind);
      const existing = containersByKey.get(key);
      if (existing) {
        // Same path + same kind — union children and evidence
        containersByKey.set(key, {
          ...existing,
          childPaths: [...new Set([...existing.childPaths, ...node.childPaths])],
          evidence: [...new Set([...existing.evidence, ...node.evidence])],
        });
      } else {
        containersByKey.set(key, { ...node });
      }
    } else {
      // Leaf node (or container with no kind — treat as leaf)
      const existing = leafByPath.get(node.path);
      if (existing) {
        leafByPath.set(node.path, mergeLeaves(existing, node));
      } else {
        leafByPath.set(node.path, { ...node });
      }
    }
  }

  // Phase 2: Resolve ownership
  // For each child path, find which container declared it.
  // If multiple containers at different paths both claim the same child,
  // the innermost (longest path) wins. If multiple containers at the SAME
  // path claim the same child (e.g., root node + go-workspace both at "."),
  // pick the container whose kind best matches the child's build evidence.
  const childToContainerKey = new Map<string, string>();

  for (const [cKey, container] of containersByKey) {
    for (const childPath of container.childPaths) {
      const existingKey = childToContainerKey.get(childPath);
      if (!existingKey) {
        childToContainerKey.set(childPath, cKey);
        continue;
      }

      const existingContainer = containersByKey.get(existingKey)!;
      const winner = pickBetterContainer(existingContainer, container, leafByPath.get(childPath));
      if (winner === container) {
        childToContainerKey.set(childPath, cKey);
      }
    }
  }

  // Prune children that don't exist as leaves
  for (const [childPath, cKey] of childToContainerKey) {
    if (!leafByPath.has(childPath)) {
      childToContainerKey.delete(childPath);
      const container = containersByKey.get(cKey);
      if (container) {
        container.childPaths = container.childPaths.filter((p) => p !== childPath);
      }
    }
  }

  // Demote containers that lost all their children
  for (const [cKey, container] of containersByKey) {
    const actualChildren = container.childPaths.filter(
      (cp) => childToContainerKey.get(cp) === cKey && leafByPath.has(cp),
    );
    if (actualChildren.length === 0) {
      containersByKey.delete(cKey);
      // Demote to leaf — but only if no other container at this path still exists
      const otherContainerAtPath = [...containersByKey.values()].some(
        (c) => c.path === container.path,
      );
      if (!otherContainerAtPath) {
        const existing = leafByPath.get(container.path);
        if (existing) {
          leafByPath.set(
            container.path,
            mergeLeaves(existing, { ...container, isContainer: false, childPaths: [] }),
          );
        } else {
          leafByPath.set(container.path, { ...container, isContainer: false, childPaths: [] });
        }
      }
    } else {
      container.childPaths = actualChildren;
    }
  }

  // Remove container paths from leaves — a path is a container if ANY container
  // at that path still exists.
  const containerPaths = new Set([...containersByKey.values()].map((c) => c.path));
  for (const cp of containerPaths) {
    leafByPath.delete(cp);
  }

  // Resolve overlapping leaves before collapsing to modules.
  // When a broad workspace glob (e.g., pnpm "**") catches a directory that
  // also contains deeper leaves from another adapter (e.g., Bazel BUILD
  // packages), drop the shallower leaf. The deeper, more-specific leaf wins.
  resolveOverlappingLeaves(leafByPath, childToContainerKey, containersByKey);

  // Phase 3: Collapse — build final modules and products
  const modules: DiscoveredModule[] = [];
  const sortedLeafPaths = [...leafByPath.keys()].sort(compareModulePaths);

  for (const leafPath of sortedLeafPaths) {
    const node = leafByPath.get(leafPath)!;
    const ownerKey = childToContainerKey.get(leafPath);
    const ownerContainer = ownerKey ? containersByKey.get(ownerKey) : undefined;

    modules.push({
      name: node.name,
      path: node.path,
      description: node.description,
      language: node.language,
      buildSystem: node.buildSystem || undefined,
      moduleKind: resolveModuleKind(ownerContainer),
      productPath: ownerContainer?.path,
      discoveryEvidence: node.evidence,
    });
  }

  // Note: no rejectOverlappingModules() here — resolveOverlappingLeaves
  // already handles overlaps, and intentional nesting (e.g., go.work declaring
  // both "galaxy" and "galaxy/cmd/galaxy-cli") is valid.

  // Phase 4: Derive products
  // Multiple containers at the same path produce separate products.
  const products: DiscoveredProduct[] = [];
  const sortedContainerKeys = [...containersByKey.keys()].sort();

  for (const cKey of sortedContainerKeys) {
    const container = containersByKey.get(cKey)!;
    products.push({
      path: container.path,
      kind: container.containerKind!,
      children: container.childPaths.sort(compareModulePaths),
      discoveryEvidence: container.evidence,
    });
  }

  // Truncate to maxModules
  const truncated = modules.slice(0, maxModules);

  return { modules: truncated, products };
}

/** Evidence strings that indicate a real, independently-buildable project. */
const REAL_PROJECT_EVIDENCE = [
  "go.mod",
  "Cargo.toml",
  "BUILD.bazel",
  "BUILD",
  ".csproj",
  ".vcxproj",
  ".fsproj",
  ".sln",
  "SConstruct",
  "pnpm-workspace.yaml",
];

function hasRealBuildEvidence(node: RawDiscoveryNode): boolean {
  return node.evidence.some((e) => {
    const lower = e.toLowerCase();
    return REAL_PROJECT_EVIDENCE.some((marker) => lower.includes(marker.toLowerCase()));
  });
}

/**
 * Resolve overlapping leaf paths. When leaf A is a prefix of leaf B
 * (A/child === B), one must be dropped — unless both are legitimate
 * independent modules.
 *
 * Rules:
 *   1. Both declared by the same specific container → keep both.
 *   2. Both have real build metadata (go.mod, BUILD, Cargo.toml, etc.)
 *      → keep both. They're independently buildable nested modules.
 *   3. Deeper leaf owned by specific container, shallower has weak evidence
 *      → drop shallower (false positive from a broad glob).
 *   4. Shallower owned by specific container, deeper has weak evidence
 *      → drop deeper.
 *   5. Both weak evidence → drop shallower (prefer more focused scan).
 */
function resolveOverlappingLeaves(
  leafByPath: Map<string, RawDiscoveryNode>,
  childToContainerKey: Map<string, string>,
  containersByKey: Map<string, RawDiscoveryNode>,
): void {
  const sortedPaths = [...leafByPath.keys()].sort(compareModulePaths);
  const toDrop = new Set<string>();

  for (let i = 0; i < sortedPaths.length; i++) {
    if (toDrop.has(sortedPaths[i])) continue;
    for (let j = i + 1; j < sortedPaths.length; j++) {
      if (toDrop.has(sortedPaths[j])) continue;
      const shallow = sortedPaths[i];
      const deep = sortedPaths[j];

      // Only care about nesting
      if (deep !== shallow && deep.startsWith(`${shallow}/`)) {
        const shallowKey = childToContainerKey.get(shallow);
        const deepKey = childToContainerKey.get(deep);
        const shallowSpecific = isSpecificContainer(shallowKey, containersByKey);
        const deepSpecific = isSpecificContainer(deepKey, containersByKey);

        const shallowNode = leafByPath.get(shallow)!;
        const deepNode = leafByPath.get(deep)!;

        // Rule 1: both declared by the same specific container → keep both
        if (shallowSpecific && deepSpecific && shallowKey === deepKey) {
          continue;
        }

        // Rule 2: both have real build metadata → keep both
        // (e.g., services/api has go.mod AND services/api/logger has go.mod)
        if (hasRealBuildEvidence(shallowNode) && hasRealBuildEvidence(deepNode)) {
          continue;
        }

        if (deepSpecific && !shallowSpecific) {
          // Rule 3: deeper from specific adapter, shallow from broad glob → drop shallow
          toDrop.add(shallow);
          break;
        } else if (shallowSpecific && !deepSpecific) {
          // Rule 4: shallow is specific, deep is the false positive → drop deep
          toDrop.add(deep);
        } else {
          // Rule 5: both weak evidence → drop shallower
          toDrop.add(shallow);
          break;
        }
      }
    }
  }

  for (const p of toDrop) {
    leafByPath.delete(p);
    childToContainerKey.delete(p);
  }
}

function isSpecificContainer(
  cKey: string | undefined,
  containersByKey: Map<string, RawDiscoveryNode>,
): boolean {
  if (!cKey) return false;
  const container = containersByKey.get(cKey);
  if (!container) return false;
  // "workspace-root" is the generic catch-all from Node; everything else is specific
  return container.containerKind !== "workspace-root";
}

function mergeLeaves(existing: RawDiscoveryNode, incoming: RawDiscoveryNode): RawDiscoveryNode {
  const existingSpecificity = LANGUAGE_SPECIFICITY[existing.language] ?? 0;
  const incomingSpecificity = LANGUAGE_SPECIFICITY[incoming.language] ?? 0;

  return {
    path: existing.path,
    name: incomingSpecificity > existingSpecificity ? incoming.name : existing.name,
    language: incomingSpecificity > existingSpecificity ? incoming.language : existing.language,
    buildSystem:
      incomingSpecificity > existingSpecificity ? incoming.buildSystem : existing.buildSystem,
    description: existing.description || incoming.description,
    evidence: [...new Set([...existing.evidence, ...incoming.evidence])],
    isContainer: false,
    childPaths: [],
  };
}

/**
 * When two containers both claim the same child, pick the better owner.
 *
 * Priority:
 *   1. Innermost container (longer path) always wins — scoping beats anything.
 *   2. At the same path, match the child's build evidence to the container kind.
 *      go.mod evidence → go-workspace wins over workspace-root.
 *      BUILD.bazel evidence → bazel-workspace wins.
 *      package.json evidence → workspace-root wins.
 *   3. Tie-break: more specific containerKind wins (go/bazel/cargo > workspace-root).
 */
function pickBetterContainer(
  a: RawDiscoveryNode,
  b: RawDiscoveryNode,
  child: RawDiscoveryNode | undefined,
): RawDiscoveryNode {
  // Innermost (longer path) wins
  if (a.path.length !== b.path.length) {
    return a.path.length > b.path.length ? a : b;
  }

  // Same path — match child's evidence to container kind
  if (child) {
    const aScore = evidenceMatchScore(a.containerKind, child.evidence);
    const bScore = evidenceMatchScore(b.containerKind, child.evidence);
    if (aScore !== bScore) {
      return aScore > bScore ? a : b;
    }
  }

  // Tie-break: more specific kind wins
  const aSpecificity = CONTAINER_SPECIFICITY[a.containerKind ?? ""] ?? 0;
  const bSpecificity = CONTAINER_SPECIFICITY[b.containerKind ?? ""] ?? 0;
  return bSpecificity > aSpecificity ? b : a;
}

const CONTAINER_SPECIFICITY: Record<string, number> = {
  "workspace-root": 1,
  "go-workspace": 5,
  "cargo-workspace": 5,
  "bazel-workspace": 5,
  solution: 5,
};

/** How well does a container kind match a child's discovery evidence? */
function evidenceMatchScore(kind: string | undefined, evidence: string[]): number {
  const joined = evidence.join(" ").toLowerCase();
  switch (kind) {
    case "go-workspace":
      return joined.includes("go.mod") || joined.includes("go.work") ? 10 : 0;
    case "cargo-workspace":
      return joined.includes("cargo.toml") ? 10 : 0;
    case "bazel-workspace":
      return joined.includes("build") || joined.includes("bazel") ? 10 : 0;
    case "solution":
      return joined.includes(".csproj") || joined.includes(".vcxproj") || joined.includes(".sln")
        ? 10
        : 0;
    case "workspace-root":
      return joined.includes("package.json") ? 5 : 0;
    default:
      return 0;
  }
}

function resolveModuleKind(
  ownerContainer: RawDiscoveryNode | undefined,
): DiscoveredModule["moduleKind"] {
  if (!ownerContainer) return "standalone";

  switch (ownerContainer.containerKind) {
    case "workspace-root":
      return "workspace-member";
    case "go-workspace":
      return "go-workspace-member";
    case "cargo-workspace":
      return "workspace-member";
    case "solution":
      return "solution-project";
    case "bazel-workspace":
      return "bazel-package";
    default:
      return "standalone";
  }
}
