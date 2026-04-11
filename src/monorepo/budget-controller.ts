/**
 * Phase 2 — Budget-aware module scan planning and adaptive depth control.
 *
 * Takes static intelligence (dep graph, attack surfaces) + architectural
 * threat model and produces a prioritized, budget-constrained scan plan.
 * Adapts remaining plans as modules complete and cost data flows in.
 */

import type { DiscoveredModule, ModulePriority } from "../discovery/types.js";
import type { KuzushiConfig } from "../types.js";
import { SCAN_PRESETS } from "../config/presets.js";
import type {
  ModuleDependencyGraph,
  AttackSurfaceAnnotation,
  ModuleRiskAssessment,
  CrossModuleHypothesis,
  MonorepoBudget,
  ModuleScanPlan,
  ScanDepth,
} from "./types.js";

// ── Cost Estimates Per Depth ───────────────────────────────────────────

/** Rough cost estimates per scan depth, used for budget planning. */
const DEPTH_COST_ESTIMATE: Record<ScanDepth, number> = {
  deep: 10,
  standard: 2,
  fast: 0.10,
  skip: 0,
};

const PRIORITY_NUMERIC: Record<ModulePriority, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

// ── Public API ──────────────────────────────────────────────────────────

/**
 * Create an initial budget tracker from config.
 */
export function createBudget(config: KuzushiConfig): MonorepoBudget {
  const total = config.monorepo?.budgetUsd ?? config.costBudgetUsd ?? Infinity;
  const reserveRatio = config.monorepo?.crossModuleReserve ?? 0.10;
  const reserved = Number.isFinite(total) ? total * reserveRatio : 0;

  return {
    totalBudgetUsd: total,
    spentUsd: 0,
    phase0CostUsd: 0,
    phase1CostUsd: 0,
    phase2CostUsd: 0,
    phase3CostUsd: 0,
    reservedForPhase3Usd: reserved,
  };
}

/**
 * Compute the available budget for Phase 2 module scans.
 */
export function availablePhase2Budget(budget: MonorepoBudget): number {
  if (!Number.isFinite(budget.totalBudgetUsd)) return Infinity;
  return Math.max(
    0,
    budget.totalBudgetUsd - budget.spentUsd - budget.reservedForPhase3Usd,
  );
}

/**
 * Sort modules by composite security priority score.
 *
 * Lower score = scanned first. Combines:
 * - LLM-assigned priority (critical > high > medium > low)
 * - External-facing flag (external modules first)
 * - Dependency in-degree rank (more depended-on = higher priority)
 */
export function sortModulesByPriority(
  modules: DiscoveredModule[],
  depGraph: ModuleDependencyGraph,
  attackSurfaces: Map<string, AttackSurfaceAnnotation>,
): DiscoveredModule[] {
  return [...modules].sort((a, b) => {
    const aScore = computePriorityScore(a, depGraph, attackSurfaces);
    const bScore = computePriorityScore(b, depGraph, attackSurfaces);
    return aScore - bScore;
  });
}

function computePriorityScore(
  m: DiscoveredModule,
  depGraph: ModuleDependencyGraph,
  attackSurfaces: Map<string, AttackSurfaceAnnotation>,
): number {
  const priorityBase = PRIORITY_NUMERIC[m.priority ?? "low"] * 100;
  const surface = attackSurfaces.get(m.name);
  const externalPenalty = surface?.isExternalFacing ? 0 : 50;
  const depRank = depGraph.nodes.get(m.name)?.dependencyRank ?? 999;
  return priorityBase + externalPenalty + depRank;
}

/**
 * Build a scan plan for all modules given the budget and risk assessments.
 *
 * Assigns scan depth per module based on:
 * 1. Architectural threat model's `recommendedScanDepth` (if available)
 * 2. Module priority + attack surface (fallback)
 * 3. Budget constraints (downgrade if over budget)
 */
export function planModuleScans(
  modules: DiscoveredModule[],
  riskAssessments: ModuleRiskAssessment[],
  crossModuleHypotheses: CrossModuleHypothesis[],
  budget: MonorepoBudget,
): ModuleScanPlan[] {
  const riskMap = new Map(riskAssessments.map((r) => [r.moduleName, r]));
  const remaining = availablePhase2Budget(budget);

  // First pass: assign depths from risk assessments or defaults
  const plans: ModuleScanPlan[] = modules.map((m) => {
    const risk = riskMap.get(m.name);
    const depth = risk?.recommendedScanDepth ?? defaultDepthForPriority(m.priority);
    const directives = crossModuleHypotheses.filter(
      (h) => h.moduleChain.includes(m.name),
    );

    return {
      module: m,
      scanDepth: depth,
      configOverrides: depthToConfigOverrides(depth),
      scanDirectives: directives,
      estimatedCostUsd: DEPTH_COST_ESTIMATE[depth],
    };
  });

  // Architectural threat model's recommendedScanDepth is authoritative.
  // Budget tracking is for visibility only — never override the LLM's security judgment.

  return plans;
}

/**
 * Re-evaluate remaining plans after a module scan completes.
 * If actual cost exceeded estimate, downgrade remaining modules.
 */
export function adaptRemainingPlan(
  remaining: ModuleScanPlan[],
  _budget: MonorepoBudget,
): ModuleScanPlan[] {
  // Architectural threat model's recommendedScanDepth is authoritative.
  // No budget-driven downgrades — return plans unchanged.
  return remaining;
}

/**
 * Check if the budget allows continuing to the next module.
 */
export function canContinueScanning(budget: MonorepoBudget): boolean {
  if (!Number.isFinite(budget.totalBudgetUsd)) return true;
  return budget.spentUsd < (budget.totalBudgetUsd - budget.reservedForPhase3Usd);
}

/**
 * Record cost from a completed module scan.
 */
export function recordModuleCost(budget: MonorepoBudget, costUsd: number): void {
  budget.spentUsd += costUsd;
  budget.phase2CostUsd += costUsd;
}

// ── Depth Mapping Helpers ──────────────────────────────────────────────

function defaultDepthForPriority(priority?: ModulePriority): ScanDepth {
  switch (priority) {
    case "critical": return "deep";
    case "high": return "standard";
    case "medium": return "fast";
    case "low": return "skip";
    default: return "fast";
  }
}

function downgradeDepth(current: ScanDepth): ScanDepth {
  switch (current) {
    case "deep": return "standard";
    case "standard": return "fast";
    case "fast": return "skip";
    case "skip": return "skip";
  }
}

function depthToConfigOverrides(depth: ScanDepth): Partial<KuzushiConfig> {
  switch (depth) {
    case "deep":
      return { ...SCAN_PRESETS.deep };
    case "standard":
      return { ...SCAN_PRESETS.standard };
    case "fast":
      return { ...SCAN_PRESETS.fast };
    case "skip":
      return {};
  }
}

// ── Formatting ─────────────────────────────────────────────────────────

export function formatScanPlan(plans: ModuleScanPlan[], budget: MonorepoBudget): string {
  const lines: string[] = [];
  const totalEstimated = plans.reduce((sum, p) => sum + p.estimatedCostUsd, 0);
  const budgetStr = Number.isFinite(budget.totalBudgetUsd)
    ? `$${budget.totalBudgetUsd.toFixed(2)}`
    : "unlimited";

  lines.push(`Scan plan (${plans.length} modules, est. $${totalEstimated.toFixed(2)} / ${budgetStr} budget):`);
  for (const plan of plans) {
    const tag = plan.scanDepth.toUpperCase().padEnd(8);
    const directives = plan.scanDirectives.length > 0
      ? ` +${plan.scanDirectives.length} cross-module hypotheses`
      : "";
    lines.push(`  [${tag}] ${plan.module.name} (~$${plan.estimatedCostUsd.toFixed(2)})${directives}`);
  }

  const skipped = plans.filter((p) => p.scanDepth === "skip").length;
  if (skipped > 0) {
    lines.push(`  (${skipped} modules skipped)`);
  }

  return lines.join("\n");
}
