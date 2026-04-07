import chalk from "chalk";
import type Database from "better-sqlite3";
import type { PipelineStats } from "./bus/events.js";
import type { DiscoveredModule } from "./discovery/types.js";
import { getActionableFindings } from "./store.js";
import type { Verdict } from "./types.js";

export interface MonorepoModuleResult {
  module: DiscoveredModule;
  repoName: string;
  status: "complete" | "error";
  stats?: Partial<PipelineStats>;
  verdictCounts: Record<Verdict, number>;
}

export function printMonorepoSummary(
  db: Database.Database,
  results: MonorepoModuleResult[],
): void {
  const totalCostUsd = results.reduce((sum, item) => sum + (item.stats?.totalCostUsd ?? 0), 0);
  const completed = results.filter((item) => item.status === "complete");
  const failed = results.filter((item) => item.status === "error");

  console.log("");
  console.log(chalk.bold("═".repeat(72)));
  console.log(chalk.bold("  Kuzushi Monorepo Summary"));
  console.log(chalk.bold("═".repeat(72)));
  console.log("");
  console.log(`  ${chalk.dim("Modules scanned:")} ${results.length}`);
  console.log(`  ${chalk.dim("Completed:")}      ${completed.length}`);
  console.log(`  ${chalk.dim("Failed:")}         ${failed.length}`);
  console.log(`  ${chalk.dim("Total cost:")}     $${totalCostUsd.toFixed(4)}`);
  console.log("");
  console.log(chalk.bold("  Module Breakdown"));

  for (const item of sortModules(results)) {
    const indent = item.module.parentModule ? "    " : "  ";
    const prefix = item.module.parentModule ? "·" : "•";
    const counts = item.verdictCounts;
    const cost = item.stats?.totalCostUsd ?? 0;
    const status = item.status === "complete" ? chalk.green("complete") : chalk.red("error");
    console.log(
      `${indent}${prefix} ${item.module.name} ${chalk.dim(`(${item.module.path})`)} `
      + `${chalk.red(`tp=${counts.tp}`)} ${chalk.yellow(`nr=${counts.needs_review}`)} `
      + `${chalk.green(`fp=${counts.fp}`)} ${chalk.dim(`$${cost.toFixed(4)}`)} ${status}`,
    );
  }

  const rulePatterns = collectCrossModuleRuleIds(db, completed);
  if (rulePatterns.length > 0) {
    console.log("");
    console.log(chalk.bold("  Cross-Module Rule Patterns"));
    for (const pattern of rulePatterns.slice(0, 5)) {
      console.log(`  - ${pattern.ruleId}: ${pattern.modules.join(", ")}`);
    }
  }

  const ranked = rankModulesByRisk(db, completed);
  if (ranked.length > 0) {
    console.log("");
    console.log(chalk.bold("  Highest-Risk Modules"));
    for (const item of ranked.slice(0, 5)) {
      console.log(`  - ${item.name}: risk=${item.risk} tp=${item.tp} highOrCritical=${item.highOrCritical}`);
    }
  }

  const parentComparisons = buildParentComparisons(results);
  if (parentComparisons.length > 0) {
    console.log("");
    console.log(chalk.bold("  Parent vs Cluster Coverage"));
    for (const entry of parentComparisons) {
      console.log(
        `  - ${entry.parent.module.name}: parent tp=${entry.parent.verdictCounts.tp}, `
        + `clusters tp=${entry.clusterTp}, clusters=${entry.clusterNames.join(", ")}`,
      );
    }
  }

  console.log(chalk.bold("─".repeat(72)));
}

function sortModules(results: MonorepoModuleResult[]): MonorepoModuleResult[] {
  return [...results].sort((left, right) => {
    const leftParent = left.module.parentModule ?? "";
    const rightParent = right.module.parentModule ?? "";
    if (leftParent !== rightParent) {
      if (!leftParent && rightParent) return -1;
      if (leftParent && !rightParent) return 1;
      return leftParent.localeCompare(rightParent);
    }
    if (left.module.parentModule !== right.module.parentModule) {
      return (left.module.parentModule ?? "").localeCompare(right.module.parentModule ?? "");
    }
    if (left.module.isParent !== right.module.isParent) {
      return left.module.isParent ? -1 : 1;
    }
    return left.module.name.localeCompare(right.module.name);
  });
}

function collectCrossModuleRuleIds(
  db: Database.Database,
  results: MonorepoModuleResult[],
): Array<{ ruleId: string; modules: string[] }> {
  const ruleToModules = new Map<string, Set<string>>();

  for (const item of results) {
    const actionable = getActionableFindings(db, item.repoName);
    for (const finding of actionable) {
      const key = finding.ruleId.trim();
      if (!key) continue;
      const modules = ruleToModules.get(key) ?? new Set<string>();
      modules.add(item.module.name);
      ruleToModules.set(key, modules);
    }
  }

  return [...ruleToModules.entries()]
    .filter(([, modules]) => modules.size > 1)
    .sort((left, right) => right[1].size - left[1].size || left[0].localeCompare(right[0]))
    .map(([ruleId, modules]) => ({ ruleId, modules: [...modules].sort() }));
}

function rankModulesByRisk(
  db: Database.Database,
  results: MonorepoModuleResult[],
): Array<{ name: string; risk: number; tp: number; highOrCritical: number }> {
  return results
    .map((item) => {
      const findings = getActionableFindings(db, item.repoName);
      const highOrCritical = findings.filter((finding) => finding.severity === "HIGH" || finding.severity === "CRITICAL").length;
      const tp = item.verdictCounts.tp;
      return {
        name: item.module.name,
        risk: tp * 100 + item.verdictCounts.needs_review * 25 + highOrCritical * 10,
        tp,
        highOrCritical,
      };
    })
    .sort((left, right) => right.risk - left.risk || left.name.localeCompare(right.name));
}

function buildParentComparisons(results: MonorepoModuleResult[]): Array<{
  parent: MonorepoModuleResult;
  clusterTp: number;
  clusterNames: string[];
}> {
  const parents = results.filter((item) => item.module.isParent);
  const byParent = new Map<string, MonorepoModuleResult[]>();

  for (const item of results) {
    if (!item.module.parentModule) {
      continue;
    }
    const siblings = byParent.get(item.module.parentModule) ?? [];
    siblings.push(item);
    byParent.set(item.module.parentModule, siblings);
  }

  return parents
    .map((parent) => {
      const children = byParent.get(parent.module.name) ?? [];
      return {
        parent,
        clusterTp: children.reduce((sum, child) => sum + child.verdictCounts.tp, 0),
        clusterNames: children.map((child) => child.module.name).sort(),
      };
    })
    .filter((entry) => entry.clusterNames.length > 0);
}
