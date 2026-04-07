import path from "node:path";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { discoverModules, inspectModuleRoot, normalizeModuleName, resolveModuleDirectory } from "../../discovery/module-discovery.js";
import type { DiscoveredModule, DiscoveryResult } from "../../discovery/types.js";
import { printMonorepoSummary, type MonorepoModuleResult } from "../../report-monorepo.js";
import { defaultDbPath, getVerdictCounts, initDb } from "../../store.js";
import { CliUsageError } from "../errors.js";
import type { ScanCommandOptions } from "../scan-config.js";
import { isShutdownCapableRuntime, resolveRepo } from "../shared.js";
import {
  applyPipelineCacheOptions,
  createPipelineRuntime,
  prepareScanExecution,
  runPipeline,
} from "./scan.js";

export async function runMonorepoScan(
  repoPath: string,
  opts: ScanCommandOptions,
): Promise<void> {
  if (opts.resume !== undefined) {
    throw new CliUsageError("--resume is not supported with monorepo module scanning.");
  }

  const { root: monorepoRoot, name: monorepoName } = resolveRepo(repoPath);
  const { config, scanOpts } = prepareScanExecution(monorepoRoot, opts);
  let runtime: AgentRuntime | undefined;

  try {
    let modules: DiscoveredModule[];
    if (opts.modules) {
      modules = await parseManualModules(monorepoRoot, opts.modules);
    } else if (config.monorepo?.modules && config.monorepo.modules.length > 0) {
      modules = await normalizeConfiguredModules(monorepoRoot, config.monorepo.modules);
    } else {
      applyPipelineCacheOptions(opts);
      runtime = createPipelineRuntime(config, scanOpts);
      const discoveryResult = await discoverModules(monorepoRoot, runtime, {
        model: config.monorepo?.discoveryModel ?? config.model,
        maxModules: config.monorepo?.maxModules ?? 30,
      });
      modules = discoveryResult.modules;
      printDiscoveryResult(discoveryResult);
    }

    const filteredModules = applyModuleFilters(
      modules,
      opts.moduleFilter,
      config.monorepo?.excludeModules ?? [],
    );

    if (opts.listModules) {
      printModules(filteredModules);
      return;
    }

    if (filteredModules.length === 0) {
      console.log("No modules matched the current filter.");
      return;
    }

    if (!runtime) {
      applyPipelineCacheOptions(opts);
      runtime = createPipelineRuntime(config, scanOpts);
    }

    const dbPath = opts.db ?? defaultDbPath(monorepoRoot);
    const results: MonorepoModuleResult[] = [];

    for (const [index, module] of filteredModules.entries()) {
      const moduleRoot = resolveModuleDirectory(monorepoRoot, module.path);
      const repoName = `${monorepoName}/${module.name}`;
      printModuleHeader(module, index + 1, filteredModules.length);

      const pipelineResult = await runPipeline({
        repoRoot: monorepoRoot,
        scanPath: moduleRoot,
        repoName,
        runRepoId: repoName,
        config,
        scanOpts,
        opts,
        dbPath,
        reportMode: "suppress",
        runtime,
        manageCache: false,
      });

      results.push({
        module,
        repoName,
        status: pipelineResult.status,
        stats: pipelineResult.stats,
        verdictCounts: { tp: 0, fp: 0, needs_review: 0, by_design: 0 },
      });
    }

    const db = initDb(dbPath);
    try {
      const summarized = results.map((result) => ({
        ...result,
        verdictCounts: getVerdictCounts(db, result.repoName),
      }));
      printMonorepoSummary(db, summarized);
    } finally {
      db.close();
    }
  } finally {
    if (runtime && isShutdownCapableRuntime(runtime)) {
      await runtime.shutdown();
    }
  }
}

export async function parseManualModules(
  monorepoRoot: string,
  rawSpec: string,
): Promise<DiscoveredModule[]> {
  const modules: DiscoveredModule[] = [];
  for (const rawEntry of rawSpec.split(",")) {
    const entry = rawEntry.trim();
    if (!entry) {
      continue;
    }

    const separator = entry.indexOf(":");
    if (separator <= 0 || separator === entry.length - 1) {
      throw new Error(`invalid module spec "${entry}" (expected name:path)`);
    }

    const rawName = entry.slice(0, separator).trim();
    const rawPath = entry.slice(separator + 1).trim();
    const modulePath = normalizeRelativeModulePath(monorepoRoot, rawPath);
    const metadata = await inspectModuleRoot(monorepoRoot, modulePath);
    modules.push({
      name: normalizeModuleName(rawName),
      path: modulePath,
      description: metadata.description,
      language: metadata.language,
      buildSystem: metadata.buildSystem,
    });
  }

  return dedupeModules(modules);
}

export async function normalizeConfiguredModules(
  monorepoRoot: string,
  modules: DiscoveredModule[],
): Promise<DiscoveredModule[]> {
  const normalized: DiscoveredModule[] = [];
  for (const module of modules) {
    const modulePath = normalizeRelativeModulePath(monorepoRoot, module.path);
    const metadata = await inspectModuleRoot(monorepoRoot, modulePath);
    normalized.push({
      name: normalizeModuleName(module.name),
      path: modulePath,
      description: module.description?.trim() || metadata.description,
      language: module.language?.trim() || metadata.language,
      buildSystem: module.buildSystem?.trim() || metadata.buildSystem,
      isParent: module.isParent === true ? true : undefined,
      parentModule: module.parentModule?.trim()
        ? normalizeModuleName(module.parentModule)
        : undefined,
    });
  }

  return dedupeModules(normalized);
}

export function applyModuleFilters(
  modules: DiscoveredModule[],
  filterPattern?: string,
  excludePatterns: string[] = [],
): DiscoveredModule[] {
  return modules.filter((module) => {
    if (filterPattern && !matchPattern(module.name, filterPattern)) {
      return false;
    }

    if (excludePatterns.some((pattern) => matchPattern(module.name, pattern))) {
      return false;
    }

    return true;
  });
}

export function matchPattern(value: string, pattern: string): boolean {
  const trimmed = pattern.trim();
  if (!trimmed) {
    return true;
  }

  const escaped = trimmed.replace(/[|\\{}()[\]^$+?.]/g, "\\$&").replace(/\*/g, ".*").replace(/\\\?/g, ".");
  return new RegExp(`^${escaped}$`, "i").test(value);
}

function normalizeRelativeModulePath(monorepoRoot: string, modulePath: string): string {
  const resolved = resolveModuleDirectory(monorepoRoot, modulePath);
  return path.relative(monorepoRoot, resolved).replace(/\\/g, "/") || ".";
}

function dedupeModules(modules: DiscoveredModule[]): DiscoveredModule[] {
  const seen = new Map<string, DiscoveredModule>();
  for (const module of modules) {
    const key = `${module.name}::${module.path}`;
    if (!seen.has(key)) {
      seen.set(key, module);
    }
  }

  return [...seen.values()];
}

function printDiscoveryResult(result: DiscoveryResult): void {
  console.log("");
  console.log(`Discovered ${result.modules.length} module(s) ($${result.costUsd.toFixed(4)}).`);
}

function printModules(modules: DiscoveredModule[]): void {
  if (modules.length === 0) {
    console.log("No modules discovered.");
    return;
  }

  console.log("Discovered modules:");
  for (const module of modules) {
    const indent = module.parentModule ? "  " : "";
    const label = module.parentModule ? "-" : "*";
    const details = [module.language, module.path].filter(Boolean).join(" | ");
    console.log(`${indent}${label} ${module.name}: ${details}`);
    if (module.description) {
      console.log(`${indent}  ${module.description}`);
    }
  }
}

function printModuleHeader(module: DiscoveredModule, index: number, total: number): void {
  console.log("");
  console.log(`== Module ${index}/${total}: ${module.name} (${module.path}) ==`);
}
