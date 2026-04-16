import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import type { BoundaryManifest } from "../../agents/tasks/taint-analysis/cross-service/types.js";
import {
  buildManualModule,
  normalizeModuleName,
  rejectOverlappingModules,
  resolveModuleDirectory,
} from "../../discovery/helpers.js";
import { discoverRepoStructure } from "../../discovery/repo-discovery.js";
import type {
  DiscoveredModule,
  DiscoveredProduct,
  DiscoveryResult,
  ModulePriority,
} from "../../discovery/types.js";
import { getGlobalLogLevel } from "../../logger.js";
import {
  __architecturalAnalysisInternals,
  buildArchitecturalThreatModel,
} from "../../monorepo/architectural-analysis.js";
import { detectAttackSurfaces, formatAttackSurfaceSummary } from "../../monorepo/attack-surface.js";
import { buildBoundaryManifest } from "../../monorepo/boundary-manifest.js";
import {
  createBudget,
  formatScanPlan,
  planModuleScans,
  pruneModulePlans,
  recordModuleCost,
  sortModulesByPriority,
} from "../../monorepo/budget-controller.js";
import { buildMonorepoContextIndex } from "../../monorepo/context-index.js";
import { traceAcrossModules } from "../../monorepo/cross-module-tracing.js";
import {
  buildDependencyGraph,
  deriveInteractionEdgesFromDependencyGraph,
  formatDependencyGraphSummary,
} from "../../monorepo/dependency-graph.js";
import type {
  ModuleScanPlan,
  MonorepoContextIndex,
  MonorepoSharedContext,
  MonorepoThreatModel,
  StaticIntelligence,
} from "../../monorepo/types.js";
import {
  type MonorepoAggregateSummary,
  type MonorepoModuleResult,
  printMonorepoSummary,
} from "../../report-monorepo.js";
import type { Finding } from "../../scanners/types.js";
import {
  defaultDbPath,
  getActionableFindings,
  getLatestResumableRun,
  getResumableModuleRuns,
  getVerdictCounts,
  initDb,
  type StoredFindingRecord,
} from "../../store.js";
import type { MonorepoUIHandle } from "../../ui/monorepo-render.js";
import { configureTerminalOutput, resetTerminalOutput } from "../../ui/output.js";
import { CliUsageError } from "../errors.js";
import type { ScanCommandOptions } from "../scan-config.js";
import { isShutdownCapableRuntime, resolveRepo } from "../shared.js";
import {
  applyPipelineCacheOptions,
  createPipelineRuntime,
  prepareScanExecution,
  runPipeline,
} from "./scan.js";

const DEFAULT_MONOREPO_CONCURRENCY = 5;

interface ModuleExecutionResult extends MonorepoModuleResult {
  plan: ModuleScanPlan;
  runId?: string;
}

export async function runMonorepoScan(repoPath: string, opts: ScanCommandOptions): Promise<void> {
  const { root: monorepoRoot, name: monorepoName } = resolveRepo(repoPath);
  const { config, scanOpts } = prepareScanExecution(monorepoRoot, opts);
  let runtime: AgentRuntime | undefined;
  configureTerminalOutput({
    verbose: getGlobalLogLevel() === "debug",
    quiet: true,
  });

  try {
    // For --list-modules, resolve without runtime (no LLM).
    // For full scans, create runtime first so LLM refinement runs during discovery.
    if (opts.listModules) {
      const { modules } = await resolveMonorepoModules(monorepoRoot, config, opts);
      const filteredModules = applyModuleFilters(
        modules,
        opts.moduleFilter,
        config.monorepo?.excludeModules ?? [],
      );
      if (filteredModules.length === 0) {
        console.log("No modules matched the current filter.");
        return;
      }
      if (normalizePriorityThreshold(opts.modulePriority) !== "all") {
        console.log(
          "--module-priority is ignored by --list-modules because priority classification happens in Phase 1.",
        );
      }
      printModules(filteredModules);
      return;
    }

    applyPipelineCacheOptions(opts);
    runtime = createPipelineRuntime(config, scanOpts);

    const dbPath = opts.db ?? defaultDbPath(monorepoRoot);
    const budget = createBudget(config);

    // ── Resume fast-path: skip discovery/Phase 0/Phase 1 entirely ────
    // Reconstruct the module list from existing DB runs and jump to Phase 2.
    if (opts.resume !== undefined) {
      const db = initDb(dbPath);
      let moduleRuns;
      try {
        moduleRuns = getResumableModuleRuns(db, monorepoName);
      } finally {
        db.close();
      }

      if (moduleRuns.length === 0) {
        throw new CliUsageError(
          `no resumable module runs found for "${monorepoName}". Run without --resume to start fresh.`,
        );
      }

      // Reconstruct minimal module + plan objects from the DB records
      const resumePlans: ModuleScanPlan[] = moduleRuns.map((run) => {
        const modulePath = run.repo.slice(monorepoName.length + 1); // strip "monorepoName/"
        const module: DiscoveredModule = {
          name: normalizeModuleName(path.basename(modulePath)),
          path: modulePath,
          description: "",
          language: "unknown",
          moduleKind: "standalone",
          discoveryEvidence: ["resume"],
        };
        return {
          module,
          tasks: [],
          riskLevel: "medium" as ModulePriority,
          rationale: "Resumed from previous run",
          focusAreas: [],
          estimatedCostUsd: 0,
        };
      });

      const nonComplete = resumePlans.filter((p) => {
        const run = moduleRuns.find((r) => r.repo === `${monorepoName}/${p.module.path}`);
        return run?.status !== "complete";
      });

      console.log(
        `\nResuming ${resumePlans.length} module(s) from previous run (${nonComplete.length} need triage)...`,
      );

      // Build minimal static intel + context for the fan-in/reporting phases
      const filteredModules = resumePlans.map((p) => p.module);
      const dependencyGraph = await buildDependencyGraph(monorepoRoot, filteredModules);
      const staticIntel: StaticIntelligence = {
        dependencyGraph,
        attackSurfaces: new Map(),
        interactionEdges: deriveInteractionEdgesFromDependencyGraph(dependencyGraph),
      };
      const contextIndex = await buildMonorepoContextIndex(
        monorepoRoot,
        filteredModules,
        staticIntel,
      );
      const threatModel = buildDeterministicThreatModel(filteredModules, staticIntel, contextIndex);

      console.log(`\n[Phase 2] Resuming ${resumePlans.length} modules...`);
      const results = await runPlansInParallel({
        plans: resumePlans,
        monorepoRoot,
        monorepoName,
        config,
        scanOpts,
        opts,
        dbPath,
        runtime,
        threatModel,
        staticIntel,
        contextIndex,
        budget,
      });

      const db2 = initDb(dbPath);
      try {
        const summarized = results.map((result) => ({
          ...result,
          verdictCounts: getVerdictCounts(db2, result.repoName),
        }));
        const aggregate = await runFanIn({
          monorepoRoot,
          runtime,
          model: config.monorepo?.discoveryModel ?? config.model,
          results,
          threatModel,
          staticIntel,
          contextIndex,
          db: db2,
          enabled: config.monorepo?.crossModuleTracing !== false,
        });
        budget.phase3CostUsd = aggregate.phase3CostUsd;
        budget.spentUsd += aggregate.phase3CostUsd;
        printMonorepoSummary(db2, summarized, aggregate.summary);
      } finally {
        db2.close();
      }
      return;
    }

    // ── Normal (non-resume) path ─────────────────────────────────────
    const {
      modules,
      products,
      costUsd: discoveryCostUsd,
    } = await resolveMonorepoModules(monorepoRoot, config, opts, runtime);
    const filteredModules = applyModuleFilters(
      modules,
      opts.moduleFilter,
      config.monorepo?.excludeModules ?? [],
    );

    if (filteredModules.length === 0) {
      console.log("No modules matched the current filter.");
      return;
    }

    budget.phase0CostUsd += discoveryCostUsd;
    budget.spentUsd += discoveryCostUsd;

    console.log("\n[Phase 0] Building static intelligence...");
    const dependencyGraph = await buildDependencyGraph(monorepoRoot, filteredModules, products);
    const attackSurfaces = await detectAttackSurfaces(monorepoRoot, filteredModules);
    const staticIntel: StaticIntelligence = {
      dependencyGraph,
      attackSurfaces,
      interactionEdges: deriveInteractionEdgesFromDependencyGraph(dependencyGraph),
    };
    const contextIndex = await buildMonorepoContextIndex(
      monorepoRoot,
      filteredModules,
      staticIntel,
    );

    console.log("\nDependency graph:");
    console.log(formatDependencyGraphSummary(dependencyGraph));
    console.log("\nAttack surfaces:");
    console.log(formatAttackSurfaceSummary(attackSurfaces));

    const enableArchitecturalThreatModel = config.monorepo?.architecturalThreatModel !== false;
    let threatModel: MonorepoThreatModel;
    if (enableArchitecturalThreatModel) {
      console.log("\n[Phase 1] Running architectural threat model...");
      const archResult = await buildArchitecturalThreatModel(
        filteredModules,
        staticIntel,
        contextIndex,
        {
          model: config.monorepo?.discoveryModel ?? config.model,
          runtime,
          monorepoRoot,
        },
      );
      budget.phase1CostUsd = archResult.costUsd;
      budget.spentUsd += archResult.costUsd;
      threatModel = archResult.threatModel;
      console.log(
        `Architectural analysis: ${threatModel.threats.length} threats, ` +
          `${threatModel.crossModuleHypotheses.length} cross-module hypotheses ($${archResult.costUsd.toFixed(4)})`,
      );
    } else {
      threatModel = buildDeterministicThreatModel(filteredModules, staticIntel, contextIndex);
      console.log(
        "\n[Phase 1] Architectural threat model disabled, using deterministic task planning.",
      );
    }

    const sortedModules = sortModulesByPriority(
      filteredModules,
      dependencyGraph,
      attackSurfaces,
      threatModel.modulePlans,
    );
    const allPlans = planModuleScans(sortedModules, threatModel.modulePlans);
    const priorityThreshold = normalizePriorityThreshold(opts.modulePriority);
    const prioritizedPlans = applyPlanPriorityFilter(allPlans, priorityThreshold);

    if (priorityThreshold !== "all") {
      printPriorityBreakdown(allPlans, prioritizedPlans, priorityThreshold);
    }

    if (opts.dryRun) {
      printModulePlans(prioritizedPlans, budget);
      return;
    }

    const scanPlans = pruneModulePlans(prioritizedPlans, budget, opts.maxModules);
    console.log(`\n${formatScanPlan(scanPlans, budget)}`);

    if (scanPlans.length === 0) {
      console.log("No modules selected after budget and priority pruning.");
      return;
    }

    console.log(`\n[Phase 2] Scanning ${scanPlans.length} modules in parallel...`);

    // Create monorepo UI renderer for live module progress
    let monorepoUI: MonorepoUIHandle | undefined;
    try {
      const { createMonorepoRenderer } = await import("../../ui/monorepo-render.js");
      monorepoUI = await createMonorepoRenderer(
        scanPlans.map((p) => ({ name: p.module.name, path: p.module.path, tasks: p.tasks })),
        "Scanning",
      );
    } catch {
      // UI not available — fallback to console.log (handled in runPlansInParallel)
    }

    const results = await runPlansInParallel({
      plans: scanPlans,
      monorepoRoot,
      monorepoName,
      config,
      scanOpts,
      opts,
      dbPath,
      runtime,
      threatModel,
      staticIntel,
      contextIndex,
      budget,
      monorepoUI,
    });

    monorepoUI?.cleanup();

    const db = initDb(dbPath);
    try {
      const summarized = results.map((result) => ({
        ...result,
        verdictCounts: getVerdictCounts(db, result.repoName),
      }));
      const aggregate = await runFanIn({
        monorepoRoot,
        runtime,
        model: config.monorepo?.discoveryModel ?? config.model,
        results,
        threatModel,
        staticIntel,
        contextIndex,
        db,
        enabled: config.monorepo?.crossModuleTracing !== false,
      });
      budget.phase3CostUsd = aggregate.phase3CostUsd;
      budget.spentUsd += aggregate.phase3CostUsd;
      printMonorepoSummary(db, summarized, aggregate.summary);
    } finally {
      db.close();
    }
  } finally {
    resetTerminalOutput();
    if (runtime && isShutdownCapableRuntime(runtime)) {
      await runtime.shutdown();
    }
  }
}

async function resolveMonorepoModules(
  monorepoRoot: string,
  config: ReturnType<typeof prepareScanExecution>["config"],
  opts: ScanCommandOptions,
  runtime?: AgentRuntime,
): Promise<{ modules: DiscoveredModule[]; products: DiscoveredProduct[]; costUsd: number }> {
  let modules: DiscoveredModule[];
  let products: DiscoveredProduct[] = [];
  let costUsd = 0;

  if (opts.modules) {
    modules = await parseManualModules(monorepoRoot, opts.modules);
  } else if (config.monorepo?.modules && config.monorepo.modules.length > 0) {
    modules = await normalizeConfiguredModules(monorepoRoot, config.monorepo.modules);
  } else {
    const discoveryResult = await discoverRepoStructure(monorepoRoot, {
      maxModules: config.monorepo?.maxModules ?? 30,
      runtime,
      model: config.monorepo?.discoveryModel ?? config.model,
    });
    printDiscoveryResult(discoveryResult);
    modules = discoveryResult.modules;
    products = discoveryResult.products;
    costUsd = discoveryResult.costUsd;
  }

  rejectOverlappingModules(modules);
  return { modules, products, costUsd };
}

function buildDeterministicThreatModel(
  modules: DiscoveredModule[],
  staticIntel: StaticIntelligence,
  contextIndex: MonorepoContextIndex,
): MonorepoThreatModel {
  return {
    dfd: { elements: [], trustBoundaries: [], dataFlows: [] },
    threats: [],
    modulePlans: modules.map((module) =>
      __architecturalAnalysisInternals.buildFallbackModulePlan(module, staticIntel, contextIndex),
    ),
    crossModuleHypotheses: [],
  };
}

async function runPlansInParallel(params: {
  plans: ModuleScanPlan[];
  monorepoRoot: string;
  monorepoName: string;
  config: ReturnType<typeof prepareScanExecution>["config"];
  scanOpts: ReturnType<typeof prepareScanExecution>["scanOpts"];
  opts: ScanCommandOptions;
  dbPath: string;
  runtime: AgentRuntime;
  threatModel: MonorepoThreatModel;
  staticIntel: StaticIntelligence;
  contextIndex: MonorepoContextIndex;
  budget: ReturnType<typeof createBudget>;
  monorepoUI?: MonorepoUIHandle;
}): Promise<ModuleExecutionResult[]> {
  const {
    plans,
    monorepoRoot,
    monorepoName,
    config,
    scanOpts,
    opts,
    dbPath,
    runtime,
    threatModel,
    staticIntel,
    contextIndex,
    budget,
    monorepoUI,
  } = params;

  const resuming = opts.resume !== undefined;
  const limiter = createConcurrencyLimiter(DEFAULT_MONOREPO_CONCURRENCY);
  const settled = await Promise.allSettled(
    plans.map((plan, index) =>
      limiter(async () => {
        const moduleRoot = resolveModuleDirectory(monorepoRoot, plan.module.path);
        const repoName = `${monorepoName}/${plan.module.path}`;
        const startedAt = Date.now();

        // When resuming, skip modules that already completed
        if (resuming) {
          const db = initDb(dbPath);
          try {
            const existingRun = getLatestResumableRun(db, repoName);
            if (existingRun?.status === "complete") {
              const verdictCounts = getVerdictCounts(db, repoName);
              monorepoUI?.updateModule(plan.module.path, { status: "skipped" });
              console.log(
                `  [${index + 1}/${plans.length}] ${plan.module.path} :: SKIPPED (already complete)`,
              );
              return {
                plan,
                module: plan.module,
                repoName,
                runId: existingRun.runId,
                status: "complete",
                stats: undefined,
                verdictCounts,
              } satisfies ModuleExecutionResult;
            }
          } finally {
            db.close();
          }
        }

        const sharedContext = contextIndex.modules.get(plan.module.path);
        if (!sharedContext) {
          throw new Error(`missing shared context for module ${plan.module.path}`);
        }

        const resumeLabel = resuming ? " (resuming)" : "";
        monorepoUI?.updateModule(plan.module.path, {
          status: "scanning",
          detail: plan.tasks.join(", ") || "scanning",
          startedAt: Date.now(),
        });
        console.log(
          `  [${index + 1}/${plans.length}] ${plan.module.path}${resumeLabel} :: ${plan.tasks.join(", ") || "no explicit tasks"}`,
        );

        const moduleConfig = {
          ...config,
          tasks: [...plan.tasks],
          enableDynamicTaskSelection: false,
        };
        const monorepoContext: MonorepoSharedContext = {
          architecturalThreatModel: threatModel,
          modulePlan: plan,
          sharedContext,
          dependencyGraph: staticIntel.dependencyGraph,
          attackSurface: sharedContext.attackSurface,
        };

        // When a module has includePaths, resolve them all for the scanner
        const moduleScanOpts = plan.module.includePaths
          ? {
              ...scanOpts,
              scanPaths: plan.module.includePaths.map((p) => path.resolve(monorepoRoot, p)),
            }
          : scanOpts;

        // When resuming, pass resume:true so each module's pipeline
        // finds its own latest resumable run and picks up from checkpoint
        const moduleOpts = resuming ? { ...opts, resume: true as const } : opts;

        const pipelineResult = await runPipeline({
          repoRoot: monorepoRoot,
          scanPath: moduleRoot,
          repoName,
          runRepoId: repoName,
          config: moduleConfig,
          scanOpts: moduleScanOpts,
          opts: moduleOpts,
          dbPath,
          reportMode: "suppress",
          runtime,
          manageCache: false,
          monorepoContext,
          seedTaskOutputs: new Map([
            [
              "context-gatherer",
              {
                repoContext: sharedContext.repoContext,
                fileIndex: sharedContext.fileIndex,
              },
            ],
          ]),
        });

        const moduleCost = pipelineResult.stats?.totalCostUsd ?? 0;
        recordModuleCost(budget, moduleCost);
        const elapsed = Date.now() - startedAt;
        let verdictCounts = { tp: 0, fp: 0, needs_review: 0, by_design: 0 };
        const db = initDb(dbPath);
        try {
          verdictCounts = getVerdictCounts(db, repoName);
        } finally {
          db.close();
        }
        monorepoUI?.updateModule(plan.module.path, {
          status: pipelineResult.status === "complete" ? "complete" : "error",
          costUsd: moduleCost,
          tp: verdictCounts.tp,
          fp: verdictCounts.fp,
          needsReview: verdictCounts.needs_review,
          elapsedMs: elapsed,
          detail: pipelineResult.status === "error" ? "pipeline error" : undefined,
        });

        return {
          plan,
          module: plan.module,
          repoName,
          runId: pipelineResult.runId,
          status: pipelineResult.status,
          stats: pipelineResult.stats,
          verdictCounts,
        } satisfies ModuleExecutionResult;
      }),
    ),
  );

  return settled.map((entry, index) => {
    if (entry.status === "fulfilled") {
      return entry.value;
    }
    const plan = plans[index]!;
    monorepoUI?.updateModule(plan.module.path, {
      status: "error",
      detail: entry.reason instanceof Error ? entry.reason.message.slice(0, 60) : "error",
    });
    return {
      plan,
      module: plan.module,
      repoName: `${monorepoName}/${plan.module.path}`,
      status: "error",
      stats: undefined,
      verdictCounts: { tp: 0, fp: 0, needs_review: 0, by_design: 0 },
    } satisfies ModuleExecutionResult;
  });
}

async function runFanIn(params: {
  monorepoRoot: string;
  runtime: AgentRuntime;
  model: string;
  results: ModuleExecutionResult[];
  threatModel: MonorepoThreatModel;
  staticIntel: StaticIntelligence;
  contextIndex: MonorepoContextIndex;
  db: ReturnType<typeof initDb>;
  enabled: boolean;
}): Promise<{ summary: MonorepoAggregateSummary; phase3CostUsd: number }> {
  const {
    monorepoRoot,
    runtime,
    model,
    results,
    threatModel,
    staticIntel,
    contextIndex,
    db,
    enabled,
  } = params;

  const perModuleFindings = new Map<string, Finding[]>();
  const boundaries: BoundaryManifest[] = [];
  const dedupeMap = new Map<string, Finding>();

  for (const result of results) {
    const actionable = getActionableFindings(db, result.repoName);
    const canonicalFindings = actionable.map((finding) =>
      canonicalizeStoredFinding(result.module.path, finding),
    );
    perModuleFindings.set(result.module.path, canonicalFindings.map(toTracingFinding));
    for (const finding of canonicalFindings) {
      dedupeMap.set(buildFindingDedupeKey(finding), toTracingFinding(finding));
    }

    const sharedContext = contextIndex.modules.get(result.module.path);
    if (!sharedContext) {
      continue;
    }

    const persistedBoundary = result.runId
      ? loadBoundaryManifest(monorepoRoot, result.runId)
      : null;
    if (persistedBoundary) {
      boundaries.push(persistedBoundary);
    } else if (result.plan.tasks.includes("taint-iris")) {
      boundaries.push(buildBoundaryManifest(result.plan, sharedContext, actionable));
    }
  }

  if (!enabled) {
    return {
      phase3CostUsd: 0,
      summary: {
        dedupedActionableFindings: dedupeMap.size,
        stitchedFindingCount: 0,
        tracedPathCount: 0,
        stitchedFindingSamples: [],
      },
    };
  }

  console.log("\n[Phase 3] Stitching cross-module findings...");
  const traceResult = await traceAcrossModules(
    boundaries,
    perModuleFindings,
    staticIntel.interactionEdges,
    threatModel,
    {
      model,
      runtime,
      monorepoRoot,
    },
  );

  return {
    phase3CostUsd: traceResult.costUsd,
    summary: {
      dedupedActionableFindings: dedupeMap.size,
      stitchedFindingCount: traceResult.findings.length,
      tracedPathCount: traceResult.paths.length,
      stitchedFindingSamples: traceResult.findings.slice(0, 5).map((finding) => ({
        ruleId: finding.ruleId,
        message: finding.message,
      })),
    },
  };
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
    modules.push(
      await buildManualModule(
        monorepoRoot,
        rawName,
        modulePath,
        "standalone",
        "manual --modules flag",
      ),
    );
  }

  const deduped = dedupeModules(modules);
  rejectOverlappingModules(deduped);
  return deduped;
}

export async function normalizeConfiguredModules(
  monorepoRoot: string,
  modules: DiscoveredModule[],
): Promise<DiscoveredModule[]> {
  const normalized: DiscoveredModule[] = [];
  for (const module of modules) {
    const modulePath = normalizeRelativeModulePath(monorepoRoot, module.path);
    const manual = await buildManualModule(
      monorepoRoot,
      module.name,
      modulePath,
      module.moduleKind ?? "standalone",
      "config",
    );
    normalized.push({
      ...manual,
      description: module.description?.trim() || manual.description,
      language: module.language?.trim() || manual.language,
      buildSystem: module.buildSystem?.trim() || manual.buildSystem,
      discoveryEvidence: module.discoveryEvidence?.length
        ? module.discoveryEvidence
        : manual.discoveryEvidence,
    });
  }

  const deduped = dedupeModules(normalized);
  rejectOverlappingModules(deduped);
  return deduped;
}

export function applyModuleFilters(
  modules: DiscoveredModule[],
  filterPattern?: string,
  excludePatterns: string[] = [],
): DiscoveredModule[] {
  return modules.filter((module) => {
    if (
      filterPattern &&
      !matchPattern(module.name, filterPattern) &&
      !matchPattern(module.path, filterPattern)
    ) {
      return false;
    }

    if (
      excludePatterns.some(
        (pattern) => matchPattern(module.name, pattern) || matchPattern(module.path, pattern),
      )
    ) {
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

  const escaped = trimmed
    .replace(/[|\\{}()[\]^$+?.]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\\\?/g, ".");
  return new RegExp(`^${escaped}$`, "i").test(value);
}

const PRIORITY_ORDER: Record<ModulePriority, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function normalizePriorityThreshold(raw: string | undefined): ModulePriority | "all" {
  if (!raw || raw === "all") return "all";
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low") return raw;
  return "high";
}

function applyPlanPriorityFilter(
  plans: ModuleScanPlan[],
  threshold: ModulePriority | "all",
): ModuleScanPlan[] {
  if (threshold === "all") {
    return plans;
  }
  const cutoff = PRIORITY_ORDER[threshold];
  return plans.filter((plan) => PRIORITY_ORDER[plan.riskLevel] <= cutoff);
}

function printPriorityBreakdown(
  allPlans: ModuleScanPlan[],
  filteredPlans: ModuleScanPlan[],
  threshold: ModulePriority | "all",
): void {
  if (threshold === "all" || allPlans.length === filteredPlans.length) {
    return;
  }

  const counts: Record<ModulePriority, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const plan of filteredPlans) {
    counts[plan.riskLevel] += 1;
  }

  const skipped = allPlans.length - filteredPlans.length;
  const scanning = Object.entries(counts)
    .filter(([, count]) => count > 0)
    .map(([priority, count]) => `${priority}: ${count}`)
    .join(", ");

  console.log(
    `\nScanning ${filteredPlans.length}/${allPlans.length} modules (${scanning}) — skipped ${skipped} below priority "${threshold}".`,
  );
  console.log("Use --module-priority all to scan everything.\n");
}

function printModulePlans(plans: ModuleScanPlan[], budget: ReturnType<typeof createBudget>): void {
  if (plans.length === 0) {
    console.log("No modules selected.");
    return;
  }

  console.log(formatScanPlan(plans, budget));
  console.log("");
  for (const plan of plans) {
    console.log(`${plan.module.path} [${plan.riskLevel}]`);
    console.log(`  Tasks: ${plan.tasks.join(", ") || "none"}`);
    console.log(`  Why:   ${plan.rationale}`);
  }
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
  const costStr = result.costUsd > 0 ? ` ($${result.costUsd.toFixed(4)})` : "";
  const productStr = result.products.length > 0 ? `, ${result.products.length} product(s)` : "";
  console.log(`Discovered ${result.modules.length} module(s)${productStr}${costStr}.`);
}

function printModules(modules: DiscoveredModule[]): void {
  if (modules.length === 0) {
    console.log("No modules discovered.");
    return;
  }

  console.log(`Discovered modules (${modules.length}):`);
  for (const module of modules) {
    const details = [module.moduleKind, module.language, module.path].filter(Boolean).join(" | ");
    console.log(`* ${module.name}: ${details}`);
    if (module.productPath) {
      console.log(`  product: ${module.productPath}`);
    }
    if (module.description) {
      console.log(`  ${module.description}`);
    }
  }
}

function createConcurrencyLimiter(limit: number): <T>(fn: () => Promise<T>) => Promise<T> {
  let active = 0;
  const queue: Array<() => void> = [];

  const next = (): void => {
    active -= 1;
    queue.shift()?.();
  };

  return async <T>(fn: () => Promise<T>): Promise<T> => {
    if (active >= limit) {
      await new Promise<void>((resolve) => queue.push(resolve));
    }
    active += 1;
    try {
      return await fn();
    } finally {
      next();
    }
  };
}

function canonicalizeStoredFinding(
  modulePath: string,
  finding: StoredFindingRecord,
): StoredFindingRecord {
  const normalizedModulePath = modulePath.replace(/\\/g, "/");
  const normalizedFilePath = finding.filePath.replace(/\\/g, "/");
  const filePath =
    normalizedFilePath.startsWith(`${normalizedModulePath}/`) ||
    normalizedFilePath === normalizedModulePath
      ? normalizedFilePath
      : path.posix.join(normalizedModulePath, normalizedFilePath);
  return {
    ...finding,
    filePath,
  };
}

function buildFindingDedupeKey(finding: StoredFindingRecord): string {
  return [finding.ruleId, finding.filePath, finding.startLine, finding.message].join("::");
}

function toTracingFinding(finding: StoredFindingRecord): Finding {
  return {
    fingerprint: finding.fingerprint,
    taskId: finding.taskId,
    ruleId: finding.ruleId,
    filePath: finding.filePath,
    startLine: finding.startLine,
    severity: finding.severity as Finding["severity"],
    message: finding.message,
    evidence: finding.rationale,
    scannerConfidence:
      finding.confidence >= 0.8 ? "HIGH" : finding.confidence >= 0.5 ? "MEDIUM" : "LOW",
    subcategory: ["vuln"],
    cwe: [],
    likelihood: "MEDIUM",
    impact: "MEDIUM",
    score: finding.adjustedScore ?? Math.round(finding.confidence * 10),
  };
}

function loadBoundaryManifest(monorepoRoot: string, runId: string): BoundaryManifest | null {
  const boundaryPath = path.join(monorepoRoot, ".kuzushi", "runs", runId, "boundary.json");
  if (!existsSync(boundaryPath)) {
    return null;
  }

  try {
    return JSON.parse(readFileSync(boundaryPath, "utf-8")) as BoundaryManifest;
  } catch {
    return null;
  }
}
