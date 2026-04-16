import path from "node:path";
import {
  type ContextGathererOutput,
  gatherContextForRoot,
} from "../agents/tasks/context-gatherer.js";
import type { DiscoveredModule } from "../discovery/types.js";
import type { FileIndex, SecurityPatternMatch } from "../types.js";
import type { ModuleSharedContext, MonorepoContextIndex, StaticIntelligence } from "./types.js";

const DEFAULT_CONTEXT_CONCURRENCY = 4;

export async function buildMonorepoContextIndex(
  monorepoRoot: string,
  modules: DiscoveredModule[],
  staticIntel: StaticIntelligence,
): Promise<MonorepoContextIndex> {
  const result = new Map<string, ModuleSharedContext>();
  let cursor = 0;

  const worker = async (): Promise<void> => {
    while (cursor < modules.length) {
      const index = cursor++;
      const module = modules[index];
      const gathered = await gatherAcrossIncludePaths(monorepoRoot, module);
      result.set(module.path, {
        modulePath: module.path,
        repoContext: gathered.repoContext,
        fileIndex: gathered.fileIndex,
        attackSurface: staticIntel.attackSurfaces.get(module.path) ?? {
          isExternalFacing: false,
          entryPointTypes: [],
          entryPointCount: 0,
          detectedFrameworks: [],
        },
        dependencyNode: staticIntel.dependencyGraph.nodes.get(module.path),
        dependsOn: [...(staticIntel.dependencyGraph.dependsOn.get(module.path) ?? [])].sort(),
        dependedOnBy: [...(staticIntel.dependencyGraph.dependedOnBy.get(module.path) ?? [])].sort(),
      });
    }
  };

  await Promise.all(
    Array.from({ length: Math.min(DEFAULT_CONTEXT_CONCURRENCY, Math.max(1, modules.length)) }, () =>
      worker(),
    ),
  );

  return { modules: result };
}

async function gatherAcrossIncludePaths(
  monorepoRoot: string,
  module: DiscoveredModule,
): Promise<ContextGathererOutput> {
  const paths = module.includePaths ?? [module.path];
  if (paths.length <= 1) {
    return gatherContextForRoot(path.resolve(monorepoRoot, module.path));
  }

  const results = await Promise.all(
    paths.map((p) => gatherContextForRoot(path.resolve(monorepoRoot, p))),
  );

  return mergeGatheredContexts(results);
}

function mergeGatheredContexts(results: ContextGathererOutput[]): ContextGathererOutput {
  const emptyFileIndex: FileIndex = {
    tree: [],
    totalFiles: 0,
    truncated: false,
    patternMatches: {},
  };
  if (results.length === 0) {
    return {
      repoContext: {
        languages: [],
        frameworks: [],
        authPatterns: [],
        sanitizationLibs: [],
        ormOrDb: [],
        entryPoints: [],
      },
      fileIndex: emptyFileIndex,
    };
  }
  if (results.length === 1) return results[0];

  const languages = new Set<string>();
  const frameworks = new Set<string>();
  const authPatterns = new Set<string>();
  const sanitizationLibs = new Set<string>();
  const ormOrDb = new Set<string>();
  const entryPoints = new Set<string>();
  const mergedTree: Array<{ path: string }> = [];
  let totalFiles = 0;
  let truncated = false;
  const mergedPatterns: Record<string, SecurityPatternMatch[]> = {};

  for (const r of results) {
    for (const v of r.repoContext.languages) languages.add(v);
    for (const v of r.repoContext.frameworks) frameworks.add(v);
    for (const v of r.repoContext.authPatterns) authPatterns.add(v);
    for (const v of r.repoContext.sanitizationLibs) sanitizationLibs.add(v);
    for (const v of r.repoContext.ormOrDb) ormOrDb.add(v);
    for (const v of r.repoContext.entryPoints) entryPoints.add(v);
    mergedTree.push(...r.fileIndex.tree);
    totalFiles += r.fileIndex.totalFiles;
    if (r.fileIndex.truncated) truncated = true;
    for (const [key, matches] of Object.entries(r.fileIndex.patternMatches)) {
      const existing = mergedPatterns[key] ?? [];
      existing.push(...matches);
      mergedPatterns[key] = existing;
    }
  }

  return {
    repoContext: {
      languages: [...languages],
      frameworks: [...frameworks],
      authPatterns: [...authPatterns],
      sanitizationLibs: [...sanitizationLibs],
      ormOrDb: [...ormOrDb],
      entryPoints: [...entryPoints],
    },
    fileIndex: {
      tree: mergedTree,
      totalFiles,
      truncated,
      patternMatches: mergedPatterns,
    },
  };
}
