import path from "node:path";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import { discoverModules, inspectModuleRoot, normalizeModuleName, resolveModuleDirectory } from "../../discovery/module-discovery.js";
import type { DiscoveredModule, DiscoveryResult, ModulePriority } from "../../discovery/types.js";
import { buildDependencyGraph, formatDependencyGraphSummary } from "../../monorepo/dependency-graph.js";
import { detectAttackSurfaces, formatAttackSurfaceSummary } from "../../monorepo/attack-surface.js";
import { buildArchitecturalThreatModel } from "../../monorepo/architectural-analysis.js";
import {
  createBudget,
  sortModulesByPriority,
  planModuleScans,
  adaptRemainingPlan,
  canContinueScanning,
  recordModuleCost,
  formatScanPlan,
} from "../../monorepo/budget-controller.js";
import type { StaticIntelligence, MonorepoSharedContext } from "../../monorepo/types.js";
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

    const priorityThreshold = normalizePriorityThreshold(opts.modulePriority);
    const priorityFilteredModules = applyPriorityFilter(filteredModules, priorityThreshold);

    if (opts.listModules || opts.dryRun) {
      printModules(priorityFilteredModules, priorityThreshold, filteredModules.length);
      return;
    }

    if (priorityFilteredModules.length === 0) {
      console.log("No modules matched the current filter.");
      if (priorityThreshold !== "all" && filteredModules.length > 0) {
        console.log(`(${filteredModules.length} module(s) exist but none met the --module-priority "${priorityThreshold}" threshold. Use --module-priority all to scan everything.)`);
      }
      return;
    }

    if (!runtime) {
      applyPipelineCacheOptions(opts);
      runtime = createPipelineRuntime(config, scanOpts);
    }

    const dbPath = opts.db ?? defaultDbPath(monorepoRoot);
    const results: MonorepoModuleResult[] = [];
    const budget = createBudget(config);

    // ── Phase 0: Static Intelligence ($0) ──────────────────────────
    console.log("\n[Phase 0] Building static intelligence...");
    const depGraph = await buildDependencyGraph(monorepoRoot, priorityFilteredModules);
    const attackSurfaces = await detectAttackSurfaces(monorepoRoot, priorityFilteredModules);
    const staticIntel: StaticIntelligence = {
      dependencyGraph: depGraph,
      attackSurfaces,
      interactionEdges: [], // TODO: Phase 0 interaction detection
    };

    console.log("\nDependency graph:");
    console.log(formatDependencyGraphSummary(depGraph));
    console.log("\nAttack surfaces:");
    console.log(formatAttackSurfaceSummary(attackSurfaces));

    // ── Phase 1: Architectural Threat Model (~$1) ──────────────────
    const enableArchThreatModel = config.monorepo?.architecturalThreatModel !== false;
    let archResult = enableArchThreatModel
      ? await (async () => {
          console.log("\n[Phase 1] Running architectural threat model...");
          const result = await buildArchitecturalThreatModel(
            priorityFilteredModules,
            staticIntel,
            {
              model: config.monorepo?.discoveryModel ?? config.model,
              runtime,
              monorepoRoot,
            },
          );
          budget.phase1CostUsd = result.costUsd;
          budget.spentUsd += result.costUsd;
          console.log(`Architectural analysis: ${result.threatModel.threats.length} threats, ${result.threatModel.crossModuleHypotheses.length} cross-module hypotheses ($${result.costUsd.toFixed(4)})`);
          return result;
        })()
      : null;

    // Sort modules by composite security priority
    const sortedModules = sortModulesByPriority(priorityFilteredModules, depGraph, attackSurfaces);

    // Build scan plan: assign depth per module based on risk + budget
    const riskAssessments = archResult?.threatModel.moduleRiskAssessments ?? [];
    const hypotheses = archResult?.threatModel.crossModuleHypotheses ?? [];
    let scanPlans = planModuleScans(sortedModules, riskAssessments, hypotheses, budget);

    console.log("\n" + formatScanPlan(scanPlans, budget));

    // ── Phase 2: Per-Module Scans (budget-aware) ───────────────────
    const maxModulesToScan = opts.maxModules ?? scanPlans.length;
    const scannableCount = Math.min(maxModulesToScan, scanPlans.length);
    if (scannableCount < scanPlans.length) {
      console.log(`\n[Phase 2] Scanning top ${scannableCount} of ${scanPlans.length} modules (--max-modules ${maxModulesToScan})...`);
    } else {
      console.log("\n[Phase 2] Scanning modules...");
    }

    for (let i = 0; i < scanPlans.length; i++) {
      if (i >= scannableCount) {
        console.log(`\n  Skipped ${scanPlans.length - scannableCount} remaining modules (--max-modules ${maxModulesToScan})`);
        break;
      }
      const plan = scanPlans[i];

      if (plan.scanDepth === "skip") {
        console.log(`\n== Module ${i + 1}/${scanPlans.length}: ${plan.module.name} [SKIP] ==`);
        results.push({
          module: plan.module,
          repoName: `${monorepoName}/${plan.module.name}`,
          status: "complete",
          stats: undefined,
          verdictCounts: { tp: 0, fp: 0, needs_review: 0, by_design: 0 },
        });
        continue;
      }

      if (!canContinueScanning(budget)) {
        const remaining = scanPlans.length - i;
        console.log(`\nBudget exhausted ($${budget.spentUsd.toFixed(2)}/$${Number.isFinite(budget.totalBudgetUsd) ? budget.totalBudgetUsd.toFixed(2) : "∞"}). Skipping remaining ${remaining} modules.`);
        break;
      }

      const moduleRoot = resolveModuleDirectory(monorepoRoot, plan.module.path);
      const repoName = `${monorepoName}/${plan.module.name}`;
      const budgetStr = Number.isFinite(budget.totalBudgetUsd)
        ? `$${budget.spentUsd.toFixed(2)} / $${budget.totalBudgetUsd.toFixed(2)}`
        : `$${budget.spentUsd.toFixed(2)}`;
      console.log(`\n== Module ${i + 1}/${scanPlans.length}: ${plan.module.name} [${plan.scanDepth.toUpperCase()}] (${budgetStr}) ==`);

      // Build per-module config with depth overrides
      const moduleConfig = { ...config, ...plan.configOverrides };

      // Build monorepo shared context for this module
      const moduleRiskAssessment = riskAssessments.find((r) => r.moduleName === plan.module.name);
      const monorepoContext: MonorepoSharedContext | undefined = archResult && moduleRiskAssessment
        ? {
            architecturalThreatModel: archResult.threatModel,
            moduleRiskAssessment,
            crossModuleHypotheses: plan.scanDirectives,
            dependencyGraph: depGraph,
            attackSurface: attackSurfaces.get(plan.module.name) ?? { isExternalFacing: false, entryPointTypes: [], entryPointCount: 0, detectedFrameworks: [] },
          }
        : undefined;

      const pipelineResult = await runPipeline({
        repoRoot: monorepoRoot,
        scanPath: moduleRoot,
        repoName,
        runRepoId: repoName,
        config: moduleConfig,
        scanOpts,
        opts,
        dbPath,
        reportMode: "suppress",
        runtime,
        manageCache: false,
        monorepoContext,
      });

      const moduleCost = pipelineResult.stats?.totalCostUsd ?? 0;
      recordModuleCost(budget, moduleCost);

      if (moduleCost > 0) {
        console.log(`  Cost: $${moduleCost.toFixed(2)} (cumulative: $${budget.spentUsd.toFixed(2)})`);
      }

      results.push({
        module: plan.module,
        repoName,
        status: pipelineResult.status,
        stats: pipelineResult.stats,
        verdictCounts: { tp: 0, fp: 0, needs_review: 0, by_design: 0 },
      });

      // Adapt remaining plans if actual cost exceeded estimates
      if (i < scanPlans.length - 1) {
        scanPlans = [
          ...scanPlans.slice(0, i + 1),
          ...adaptRemainingPlan(scanPlans.slice(i + 1), budget),
        ];
      }
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

function printModules(modules: DiscoveredModule[], threshold?: string, totalBeforeFilter?: number): void {
  if (modules.length === 0) {
    console.log("No modules discovered.");
    return;
  }

  const header = totalBeforeFilter != null && totalBeforeFilter !== modules.length
    ? `Discovered modules (${modules.length}/${totalBeforeFilter} at priority "${threshold}"):`
    : `Discovered modules (${modules.length}):`;
  console.log(header);
  for (const module of modules) {
    const indent = module.parentModule ? "  " : "";
    const label = module.parentModule ? "-" : "*";
    const priorityTag = module.priority ? ` [${module.priority}]` : "";
    const details = [module.language, module.path].filter(Boolean).join(" | ");
    console.log(`${indent}${label} ${module.name}${priorityTag}: ${details}`);
    if (module.securitySignals?.length) {
      console.log(`${indent}  signals: ${module.securitySignals.join(", ")}`);
    } else if (module.description) {
      console.log(`${indent}  ${module.description}`);
    }
  }
}

const PRIORITY_ORDER: Record<ModulePriority, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function normalizePriorityThreshold(raw: string | undefined): ModulePriority | "all" {
  if (!raw || raw === "all") return "all";
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low") return raw;
  return "high"; // default
}

export function applyPriorityFilter(
  modules: DiscoveredModule[],
  threshold: ModulePriority | "all",
): DiscoveredModule[] {
  if (threshold === "all") return modules;
  const cutoff = PRIORITY_ORDER[threshold];
  return modules.filter((m) => {
    if (!m.priority) return true; // no priority assigned → always include
    return PRIORITY_ORDER[m.priority] <= cutoff;
  });
}

function printPriorityBreakdown(
  allModules: DiscoveredModule[],
  filteredModules: DiscoveredModule[],
  threshold: ModulePriority | "all",
): void {
  if (threshold === "all" || allModules.length === filteredModules.length) return;

  const counts: Record<ModulePriority, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const m of filteredModules) {
    if (m.priority) counts[m.priority]++;
  }
  const skipped = allModules.length - filteredModules.length;
  const scanning = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([p, n]) => `${p}: ${n}`)
    .join(", ");

  console.log(`\nScanning ${filteredModules.length}/${allModules.length} modules (${scanning}) — skipped ${skipped} below priority "${threshold}".`);
  console.log(`Use --module-priority all to scan everything.\n`);
}

function printModuleHeader(module: DiscoveredModule, index: number, total: number): void {
  console.log("");
  console.log(`== Module ${index}/${total}: ${module.name} (${module.path}) ==`);
}
