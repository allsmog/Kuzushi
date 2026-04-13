/**
 * Repo-wide structure discovery.
 *
 * Two-pass pipeline:
 *   1. Metadata pass — 6 adapters scan for build system manifests
 *   2. LLM pass — optional refinement for bizarre/uncovered layouts
 */

import { existsSync } from "node:fs";
import { readdir } from "node:fs/promises";
import path from "node:path";
import { getLogger } from "../logger.js";
import type { DiscoveryOptions, DiscoveryResult } from "./types.js";
import type { RawDiscoveryNode } from "./adapters/types.js";
import { NodeAdapter } from "./adapters/node-adapter.js";
import { GoAdapter } from "./adapters/go-adapter.js";
import { RustAdapter } from "./adapters/rust-adapter.js";
import { MsvsAdapter } from "./adapters/msvs-adapter.js";
import { BazelAdapter } from "./adapters/bazel-adapter.js";
import { NativeAdapter } from "./adapters/native-adapter.js";
import { resolveDiscoveryGraph } from "./graph.js";
import { carveModulesWithLlm } from "./llm-refinement.js";
import { buildWorkspaceDependencyMap, clusterWorkspaceMembers } from "./workspace-clustering.js";
import { readJson, readText } from "./helpers.js";

const log = getLogger("discovery");

const DEFAULT_MAX_MODULES = 30;
const DEFAULT_MAX_DEPTH = 8;

const ADAPTERS = [
  new NodeAdapter(),
  new GoAdapter(),
  new RustAdapter(),
  new MsvsAdapter(),
  new BazelAdapter(),
  new NativeAdapter(),
];

export async function discoverRepoStructure(
  repoRoot: string,
  options: DiscoveryOptions = {},
): Promise<DiscoveryResult> {
  const maxModules = options.maxModules ?? DEFAULT_MAX_MODULES;
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;

  // Pass 1: metadata adapters
  const allNodes: RawDiscoveryNode[] = [];
  for (const adapter of ADAPTERS) {
    const nodes = await adapter.discover(repoRoot, maxDepth);
    allNodes.push(...nodes);
    if (nodes.length > 0) {
      log.info(`${adapter.id}: ${nodes.length} node(s)`);
    }
  }

  const metadataResult = resolveDiscoveryGraph(allNodes, maxModules);
  log.info(
    `Metadata pass: ${metadataResult.modules.length} module(s), ${metadataResult.products.length} product(s)`,
  );

  // Build workspace internal dependency map (used by both clustering and LLM carving)
  const depMap = await buildWorkspaceDependencyMap(repoRoot, allNodes);

  // Pass 2: LLM carving (only when runtime is provided)
  if (options.runtime) {
    const model = options.model ?? "claude-sonnet-4-20250514";
    const carved = await carveModulesWithLlm(
      repoRoot,
      allNodes,
      metadataResult.products,
      options.runtime,
      model,
      depMap,
    );

    // If LLM carving produced modules, use them. Otherwise fall back to metadata.
    if (carved.modules.length > 0) {
      return {
        modules: carved.modules,
        products: carved.products,
        costUsd: carved.costUsd,
        reasoning: `LLM-carved (${carved.modules.length} modules, ${carved.products.length} products)`,
      };
    }

    log.warn("LLM carving returned no modules, falling back to metadata pass");
  }

  // No runtime or LLM fallback: apply deterministic clustering
  const clustered = clusterWorkspaceMembers(depMap, allNodes, metadataResult.products);
  if (clustered.length > 0) {
    return {
      modules: clustered.slice(0, maxModules),
      products: metadataResult.products,
      costUsd: 0,
      reasoning: `Deterministic clustering (${clustered.length} modules)`,
    };
  }

  return {
    modules: metadataResult.modules,
    products: metadataResult.products,
    costUsd: 0,
    reasoning: `Metadata discovery (${metadataResult.modules.length} modules, ${metadataResult.products.length} products)`,
  };
}

/**
 * Quick check: does this path look like a monorepo?
 * Pure filesystem marker check — no full adapter run, no LLM.
 */
export async function looksLikeMonorepo(rootPath: string): Promise<boolean> {
  // pnpm-workspace.yaml
  if (existsSync(path.join(rootPath, "pnpm-workspace.yaml"))) return true;

  // package.json workspaces
  const pkg = await readJson(path.join(rootPath, "package.json"));
  if (pkg?.["workspaces"]) return true;

  // go.work
  if (existsSync(path.join(rootPath, "go.work"))) return true;

  // Cargo.toml [workspace]
  const cargo = await readText(path.join(rootPath, "Cargo.toml"));
  if (cargo.includes("[workspace]")) return true;

  // .sln files at root
  try {
    const rootEntries = await readdir(rootPath);
    if (rootEntries.some((e) => e.endsWith(".sln"))) return true;
  } catch {
    // ignore
  }

  // Bazel workspace markers
  for (const f of ["WORKSPACE", "WORKSPACE.bazel", "MODULE.bazel"]) {
    if (existsSync(path.join(rootPath, f))) return true;
  }

  return false;
}
