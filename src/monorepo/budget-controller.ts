/**
 * Phase 2 — Budget-aware module scan planning for explicit task lists.
 */

import type { DiscoveredModule, ModulePriority } from "../discovery/types.js";
import type {
  AttackSurfaceAnnotation,
  ModuleDependencyGraph,
  ModuleScanPlan,
  ModuleTaskRecommendation,
  MonorepoBudget,
} from "./types.js";

const BASE_MODULE_SCAN_COST = 0.25;

const TASK_COST_ESTIMATE: Record<string, number> = {
  "secrets-crypto-detect": 0.35,
  "code-config-detect": 0.35,
  "ssrf-detect": 0.75,
  "race-condition-detect": 0.75,
  "nosql-injection-detect": 0.6,
  "prototype-pollution-detect": 0.7,
  "template-injection-detect": 0.7,
  "graphql-security-detect": 0.65,
  "supply-chain-detect": 0.25,
  "command-injection-detect": 0.8,
  "xxe-detect": 0.55,
  "deserialization-detect": 0.75,
  "auth-logic-detect": 0.85,
  "threat-model-randori": 0.6,
  "threat-hunt": 0.9,
  "sharp-edges-detect": 0.5,
  "taint-iris": 1.5,
};

const PRIORITY_NUMERIC: Record<ModulePriority, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

export function createBudget(config: {
  monorepo?: { budgetUsd?: number; crossModuleReserve?: number };
  costBudgetUsd?: number;
}): MonorepoBudget {
  const total = config.monorepo?.budgetUsd ?? config.costBudgetUsd ?? Infinity;
  const reserveRatio = config.monorepo?.crossModuleReserve ?? 0.1;
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

export function availablePhase2Budget(budget: MonorepoBudget): number {
  if (!Number.isFinite(budget.totalBudgetUsd)) {
    return Infinity;
  }
  return Math.max(0, budget.totalBudgetUsd - budget.spentUsd - budget.reservedForPhase3Usd);
}

export function sortModulesByPriority(
  modules: DiscoveredModule[],
  depGraph: ModuleDependencyGraph,
  attackSurfaces: Map<string, AttackSurfaceAnnotation>,
  recommendations: ModuleTaskRecommendation[] = [],
): DiscoveredModule[] {
  const riskByPath = new Map(
    recommendations.map((recommendation) => [recommendation.modulePath, recommendation.riskLevel]),
  );

  return [...modules].sort((left, right) => {
    const leftScore = computePriorityScore(left, depGraph, attackSurfaces, riskByPath);
    const rightScore = computePriorityScore(right, depGraph, attackSurfaces, riskByPath);
    return leftScore - rightScore;
  });
}

function computePriorityScore(
  module: DiscoveredModule,
  depGraph: ModuleDependencyGraph,
  attackSurfaces: Map<string, AttackSurfaceAnnotation>,
  riskByPath: Map<string, ModulePriority>,
): number {
  const riskLevel = riskByPath.get(module.path) ?? module.priority ?? "low";
  const priorityBase = PRIORITY_NUMERIC[riskLevel] * 100;
  const surface = attackSurfaces.get(module.path);
  const externalPenalty = surface?.isExternalFacing ? 0 : 50;
  const depRank = depGraph.nodes.get(module.path)?.dependencyRank ?? 999;
  return priorityBase + externalPenalty + depRank;
}

export function planModuleScans(
  modules: DiscoveredModule[],
  recommendations: ModuleTaskRecommendation[],
): ModuleScanPlan[] {
  const recommendationByPath = new Map(
    recommendations.map((recommendation) => [recommendation.modulePath, recommendation]),
  );

  return modules.map((module) => {
    const recommendation = recommendationByPath.get(module.path);
    const tasks = [...new Set(recommendation?.recommendedTasks ?? [])];
    return {
      module,
      tasks,
      riskLevel: recommendation?.riskLevel ?? module.priority ?? "medium",
      rationale: recommendation?.rationale ?? "No architectural rationale returned.",
      focusAreas: recommendation?.focusAreas ?? [],
      estimatedCostUsd: estimateModuleTaskCost(tasks),
    };
  });
}

export function pruneModulePlans(
  plans: ModuleScanPlan[],
  budget: MonorepoBudget,
  maxModules?: number,
): ModuleScanPlan[] {
  const limited = maxModules != null ? plans.slice(0, Math.max(0, maxModules)) : [...plans];
  const availableBudget = availablePhase2Budget(budget);
  if (!Number.isFinite(availableBudget)) {
    return limited;
  }

  const selected: ModuleScanPlan[] = [];
  let totalEstimated = 0;
  for (const plan of limited) {
    if (selected.length > 0 && totalEstimated + plan.estimatedCostUsd > availableBudget) {
      continue;
    }
    selected.push(plan);
    totalEstimated += plan.estimatedCostUsd;
  }
  return selected;
}

export function recordModuleCost(budget: MonorepoBudget, costUsd: number): void {
  budget.spentUsd += costUsd;
  budget.phase2CostUsd += costUsd;
}

export function estimateModuleTaskCost(taskIds: string[]): number {
  return (
    BASE_MODULE_SCAN_COST +
    taskIds.reduce((sum, taskId) => sum + (TASK_COST_ESTIMATE[taskId] ?? 0.4), 0)
  );
}

export function formatScanPlan(plans: ModuleScanPlan[], budget: MonorepoBudget): string {
  const lines: string[] = [];
  const totalEstimated = plans.reduce((sum, plan) => sum + plan.estimatedCostUsd, 0);
  const budgetStr = Number.isFinite(budget.totalBudgetUsd)
    ? `$${budget.totalBudgetUsd.toFixed(2)}`
    : "unlimited";

  lines.push(
    `Scan plan (${plans.length} modules, est. $${totalEstimated.toFixed(2)} / ${budgetStr} budget):`,
  );
  for (const plan of plans) {
    const risk = plan.riskLevel.toUpperCase().padEnd(8);
    const tasks = plan.tasks.length > 0 ? plan.tasks.join(", ") : "no explicit tasks";
    lines.push(
      `  [${risk}] ${plan.module.path} (~$${plan.estimatedCostUsd.toFixed(2)}) :: ${tasks}`,
    );
  }
  return lines.join("\n");
}
