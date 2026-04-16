/**
 * LLM module carving.
 *
 * One structured LLM call receives the directory tree and adapter signals,
 * then outputs the final list of security scan modules. The LLM thinks
 * like a security architect: each module is an independently deployable
 * unit with its own attack surface.
 */

import { existsSync } from "node:fs";
import path from "node:path";
import { runStructuredAgentQuery } from "../agent-runtime/execution.js";
import type { AgentRuntime } from "../agent-runtime/types.js";
import { getLogger } from "../logger.js";
import { walkRepo } from "../repo-walk.js";
import { isRecord } from "../utils.js";
import type { RawDiscoveryNode } from "./adapters/types.js";
import { compareModulePaths, normalizeModuleName, normalizePromptPath } from "./helpers.js";
import type { DiscoveredModule, DiscoveredProduct } from "./types.js";
import type { WorkspaceDependencyMap } from "./workspace-clustering.js";

const log = getLogger("discovery-llm");

// ── Schema ────────────────────────────────────────────────────────────

const MODULE_CARVING_SCHEMA = {
  type: "object",
  additionalProperties: false,
  required: ["modules"],
  properties: {
    modules: {
      type: "array",
      items: {
        type: "object",
        additionalProperties: false,
        required: ["path", "name", "language", "rationale"],
        properties: {
          path: { type: "string" },
          name: { type: "string" },
          language: { type: "string" },
          rationale: { type: "string" },
          includePaths: { type: "array", items: { type: "string" } },
        },
      },
    },
  },
} as const;

const SYSTEM_PROMPT = [
  "You are a security architect carving a monorepo into scan modules.",
  "",
  "You receive a directory tree and a summary of what build-system adapters",
  "found. Your job is to output the FINAL list of modules that a security",
  "scanner should scan independently.",
  "",
  "What is a scan module:",
  "- An independently deployable unit with its own attack surface.",
  "- A workspace (pnpm, go.work, Cargo) with many packages is ONE module,",
  "  not one-per-package. They share a build, a deployment, and an attack surface.",
  "- A Go monolith with nested sub-tool go.mod files is ONE primary module.",
  "  Sub-tools are separate modules only if they are independently deployed.",
  "- A Visual Studio solution (.sln) with multiple projects is ONE module.",
  "- A Bazel subtree that was collapsed from many BUILD files is ONE module.",
  "",
  "What to exclude:",
  "- Test frameworks, test automation, e2e test suites",
  "- Build tools, CI actions, linters, code generators",
  "- Simulators, mock servers, dev-only tooling",
  "- Documentation, specs, schemas (unless they generate code)",
  "- Third-party vendored code",
  "",
  "What to include:",
  "- Backend services (Go, Java, Python, Rust, C++)",
  "- Frontend applications (React, Angular, Vue)",
  "- Native/on-prem agents (C++, C#, Windows services)",
  "- Kubernetes operators and controllers",
  "- Standalone applications with their own deployment",
  "- Orphan subtrees with real application code but no build metadata",
  "",
  "Scan scope grouping (includePaths):",
  "- Set 'path' to the primary package (server entry point, main app root).",
  "- Set 'includePaths' to ALL sibling packages the scanner must see to trace",
  "  data flow through this module (shared libs, internal APIs, data layer).",
  "- A shared utility MAY appear in multiple modules' includePaths.",
  "- Omit 'includePaths' for standalone modules with no workspace siblings.",
  "",
  "Guidelines:",
  "- Target 10-20 modules for a giant repo.",
  "- Only use paths that exist in the directory tree.",
  "- Every module MUST have a rationale explaining why it is an independent scan unit.",
  "- The path should be the root of the scan unit, not a file inside it.",
].join("\n");

// ── Public API ────────────────────────────────────────────────────────

export async function carveModulesWithLlm(
  repoRoot: string,
  rawNodes: RawDiscoveryNode[],
  metadataProducts: DiscoveredProduct[],
  runtime: AgentRuntime,
  model: string,
  depMap?: WorkspaceDependencyMap,
): Promise<{ modules: DiscoveredModule[]; products: DiscoveredProduct[]; costUsd: number }> {
  const prompt = await buildCarvingPrompt(repoRoot, rawNodes, depMap);

  const result = await runStructuredAgentQuery({
    prompt,
    cwd: repoRoot,
    model,
    allowedTools: [],
    runtimeOptions: {
      runtime,
      maxOutputTokens: 4096,
      thinkingDisabled: true,
    },
    schema: MODULE_CARVING_SCHEMA as unknown as Record<string, unknown>,
    strict: true,
    systemPromptPrefix: SYSTEM_PROMPT,
    retryInvalidStructuredOutput: 1,
  });

  if (result.executionError) {
    log.error(`LLM carving failed: ${result.executionError}`);
    return { modules: [], products: metadataProducts, costUsd: result.costUsd };
  }

  const carved = parseCarvingOutput(result.structuredOutput, repoRoot, rawNodes);
  log.info(`LLM carving: ${carved.length} module(s) ($${result.costUsd.toFixed(4)})`);

  return {
    modules: carved,
    products: metadataProducts,
    costUsd: result.costUsd,
  };
}

// ── Prompt building ───────────────────────────────────────────────────

async function buildCarvingPrompt(
  repoRoot: string,
  rawNodes: RawDiscoveryNode[],
  depMap?: WorkspaceDependencyMap,
): Promise<string> {
  const sections: string[] = [];

  // 1. Directory tree
  const entries = await walkRepo(repoRoot, { maxDepth: 4, maxEntries: 4000 });
  const tree = entries
    .map((e) => `${"  ".repeat(e.depth)}${e.kind === "dir" ? e.relPath + "/" : e.relPath}`)
    .join("\n");
  sections.push("## Directory Tree\n```\n" + tree + "\n```");

  // 2. Adapter signals — summarized by adapter, not as raw node list
  const signals = buildAdapterSignalSummary(rawNodes);
  sections.push("## Adapter Signals\n" + signals);

  // 3. Internal workspace dependencies
  if (depMap?.promptSummary) {
    sections.push("## Internal Workspace Dependencies\n" + depMap.promptSummary);
  }

  // 4. Orphan subtrees
  const claimedPaths = new Set<string>();
  for (const node of rawNodes) {
    claimedPaths.add(node.path);
    for (const child of node.childPaths) {
      claimedPaths.add(child);
    }
  }

  const orphans = entries
    .filter((e) => e.kind === "dir" && e.depth >= 1 && e.depth <= 2)
    .map((e) => normalizePromptPath(e.relPath))
    .filter((p) => {
      if (claimedPaths.has(p)) return false;
      for (const claimed of claimedPaths) {
        if (p.startsWith(claimed + "/") || claimed.startsWith(p + "/")) return false;
      }
      return true;
    });

  if (orphans.length > 0) {
    sections.push(
      "## Orphan Subtrees (not claimed by any build system)\n" +
        orphans.map((p) => `- ${p}/`).join("\n"),
    );
  }

  sections.push(
    "Output the final list of security scan modules. Each module should be a unit you would hand to a security scanner independently.",
  );

  return sections.join("\n\n");
}

function buildAdapterSignalSummary(rawNodes: RawDiscoveryNode[]): string {
  const lines: string[] = [];

  // Group nodes by the adapter that produced them (inferred from evidence/buildSystem)
  const containers = rawNodes.filter((n) => n.isContainer);
  const leaves = rawNodes.filter((n) => !n.isContainer);

  // Node workspaces
  const nodeContainers = containers.filter((c) => c.containerKind === "workspace-root");
  if (nodeContainers.length > 0) {
    for (const ws of nodeContainers) {
      lines.push(
        `**Node workspace** at \`${ws.path}\`: ${ws.childPaths.length} package(s) [${ws.evidence.join(", ")}]`,
      );
      if (ws.childPaths.length <= 10) {
        for (const child of ws.childPaths) {
          lines.push(`  - ${child}`);
        }
      } else {
        for (const child of ws.childPaths.slice(0, 5)) {
          lines.push(`  - ${child}`);
        }
        lines.push(`  - ... and ${ws.childPaths.length - 5} more`);
      }
    }
  }

  // Standalone Node apps
  const nodeStandalone = leaves.filter(
    (n) =>
      n.buildSystem === "package.json" && !containers.some((c) => c.childPaths.includes(n.path)),
  );
  if (nodeStandalone.length > 0) {
    lines.push(
      `**Standalone Node apps**: ${nodeStandalone.map((n) => `\`${n.path}\``).join(", ")}`,
    );
  }

  // Go workspaces
  const goContainers = containers.filter((c) => c.containerKind === "go-workspace");
  if (goContainers.length > 0) {
    for (const ws of goContainers) {
      lines.push(
        `**Go workspace** at \`${ws.path}\`: ${ws.childPaths.length} module(s) [${ws.evidence.join(", ")}]`,
      );
      for (const child of ws.childPaths) {
        lines.push(`  - ${child}`);
      }
    }
  }

  // Standalone Go modules
  const goStandalone = leaves.filter(
    (n) => n.buildSystem === "go.mod" && !containers.some((c) => c.childPaths.includes(n.path)),
  );
  if (goStandalone.length > 0) {
    lines.push(`**Standalone Go modules** (${goStandalone.length}):`);
    for (const m of goStandalone) {
      lines.push(`  - \`${m.path}\` (${m.name})`);
    }
  }

  // Rust workspaces
  const rustContainers = containers.filter((c) => c.containerKind === "cargo-workspace");
  if (rustContainers.length > 0) {
    for (const ws of rustContainers) {
      lines.push(`**Cargo workspace** at \`${ws.path}\`: ${ws.childPaths.length} crate(s)`);
    }
  }

  // MSVS solutions
  const slnContainers = containers.filter((c) => c.containerKind === "solution");
  if (slnContainers.length > 0) {
    for (const sln of slnContainers) {
      const projectLangs = leaves
        .filter((n) => sln.childPaths.includes(n.path))
        .map((n) => n.language);
      const langSummary = [...new Set(projectLangs)].join("/");
      lines.push(
        `**Visual Studio solution** at \`${sln.path}\`: ${sln.childPaths.length} project(s) (${langSummary}) [${sln.evidence.join(", ")}]`,
      );
      for (const child of sln.childPaths) {
        lines.push(`  - ${child}`);
      }
    }
  }

  // Bazel workspace
  const bazelContainers = containers.filter((c) => c.containerKind === "bazel-workspace");
  if (bazelContainers.length > 0) {
    for (const ws of bazelContainers) {
      const bazelLeaves = leaves.filter((n) => ws.childPaths.includes(n.path));
      lines.push(
        `**Bazel workspace** at \`${ws.path}\`: ${ws.childPaths.length} package(s) [${ws.evidence.join(", ")}]`,
      );
      for (const pkg of bazelLeaves) {
        lines.push(`  - \`${pkg.path}\` (${pkg.language})`);
      }
    }
  }

  // Native (SConstruct)
  const nativeLeaves = leaves.filter((n) => n.buildSystem === "SConstruct");
  if (nativeLeaves.length > 0) {
    lines.push(`**Native (SConstruct)**: ${nativeLeaves.map((n) => `\`${n.path}\``).join(", ")}`);
  }

  return lines.join("\n");
}

// ── Output parsing ────────────────────────────────────────────────────

function parseCarvingOutput(
  raw: unknown,
  repoRoot: string,
  rawNodes: RawDiscoveryNode[],
): DiscoveredModule[] {
  if (!isRecord(raw)) return [];
  const modules = (raw as Record<string, unknown>)["modules"];
  if (!Array.isArray(modules)) return [];

  // Build a lookup from path → adapter node for inheriting metadata
  const nodeByPath = new Map<string, RawDiscoveryNode>();
  for (const node of rawNodes) {
    if (!node.isContainer) {
      nodeByPath.set(node.path, node);
    }
  }

  const result: DiscoveredModule[] = [];

  for (const item of modules) {
    if (!isRecord(item)) continue;
    const entry = item as Record<string, unknown>;

    const rawPath = typeof entry["path"] === "string" ? entry["path"] : null;
    const name = typeof entry["name"] === "string" ? entry["name"] : null;
    const language = typeof entry["language"] === "string" ? entry["language"] : "unknown";

    if (!rawPath || !name) continue;

    const modulePath = normalizePromptPath(rawPath);
    const absPath = path.resolve(repoRoot, modulePath);
    if (!existsSync(absPath)) {
      log.warn(`LLM carved path does not exist: ${modulePath}`);
      continue;
    }

    // Inherit metadata from adapter node if one exists at this path
    const adapterNode = nodeByPath.get(modulePath);

    // Validate includePaths
    let includePaths: string[] | undefined;
    const rawIncludePaths = (entry as Record<string, unknown>)["includePaths"];
    if (Array.isArray(rawIncludePaths)) {
      const validated: string[] = [];
      for (const rawP of rawIncludePaths) {
        if (typeof rawP !== "string") continue;
        const normalized = normalizePromptPath(rawP);
        const absP = path.resolve(repoRoot, normalized);
        if (!existsSync(absP)) {
          log.warn(`LLM includePath does not exist: ${normalized}`);
          continue;
        }
        if (normalized !== modulePath) {
          validated.push(normalized);
        }
      }
      if (validated.length > 0) {
        // Include the primary path and sort
        includePaths = [modulePath, ...validated].sort(compareModulePaths);
      }
    }

    result.push({
      name: normalizeModuleName(name),
      path: modulePath,
      includePaths,
      description: adapterNode?.description ?? "",
      language: adapterNode?.language ?? language,
      buildSystem: adapterNode?.buildSystem || undefined,
      moduleKind: "standalone",
      discoveryEvidence: ["llm-carving"],
    });
  }

  result.sort((a, b) => compareModulePaths(a.path, b.path));
  return result;
}
