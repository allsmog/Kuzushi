import type { TaskContext } from "../agents/types.js";
import { createLogger } from "../logger.js";
import { toErrorMessage } from "../utils.js";
import type { CweStrategyProfile } from "./cwe-strategy-map.js";
import type { StrategyRegistry } from "./registry.js";
import type { MultiStrategyMode, StrategyInput, StrategyResult } from "./types.js";

const log = createLogger({ stage: "multi-strategy" });

export interface StrategyBudget {
  totalUsd: number;
  perStrategyUsd?: number;
  timeoutMs: number;
}

/** Resolve multi-strategy execution mode from config. */
export function resolveMultiStrategyMode(config: Record<string, unknown>): MultiStrategyMode {
  const mode = config["multiStrategyMode"];
  if (mode === "adaptive" || mode === "full") return mode;
  return "off";
}

/** Resolve budget constraints from config. */
export function resolveStrategyBudget(config: Record<string, unknown>): StrategyBudget {
  return {
    totalUsd:
      typeof config["multiStrategyBudgetUsd"] === "number" ? config["multiStrategyBudgetUsd"] : 2.0,
    perStrategyUsd:
      typeof config["multiStrategyPerStrategyBudgetUsd"] === "number"
        ? config["multiStrategyPerStrategyBudgetUsd"]
        : 0.5,
    timeoutMs:
      typeof config["multiStrategyTimeoutMs"] === "number"
        ? config["multiStrategyTimeoutMs"]
        : 60_000,
  };
}

/** Execute strategies for a CWE profile according to mode. */
export async function executeStrategies(
  profile: CweStrategyProfile,
  context: TaskContext,
  registry: StrategyRegistry,
  mode: MultiStrategyMode,
  baseInput: Omit<StrategyInput, "budgetUsd">,
): Promise<StrategyResult[]> {
  const budget = resolveStrategyBudget(context.config as unknown as Record<string, unknown>);
  const sortedStrategies = [...profile.strategies].sort((a, b) => a.priority - b.priority);

  const results: StrategyResult[] = [];
  let spentUsd = 0;

  if (mode === "full") {
    // Run ALL strategies in parallel
    const promises = sortedStrategies.map(async (s) => {
      const strategy = registry.getById(s.strategyId);
      if (!strategy) return null;
      const perBudget = budget.perStrategyUsd ?? budget.totalUsd / sortedStrategies.length;
      try {
        return await withTimeout(
          strategy.run({ ...baseInput, budgetUsd: perBudget }, {}),
          budget.timeoutMs,
        );
      } catch (error) {
        log.warn(`Strategy ${s.strategyId} failed: ${toErrorMessage(error)}`);
        return null;
      }
    });

    const settled = await Promise.allSettled(promises);
    for (const result of settled) {
      if (result.status === "fulfilled" && result.value) {
        results.push(result.value);
        spentUsd += result.value.costUsd;
      }
    }
  } else {
    // Adaptive mode: run cheapest first, exit early if confident
    for (const strategyDef of sortedStrategies) {
      if (spentUsd >= budget.totalUsd) {
        log.debug(`Budget exhausted ($${spentUsd.toFixed(4)}), skipping remaining strategies`);
        break;
      }

      const strategy = registry.getById(strategyDef.strategyId);
      if (!strategy) continue;

      const remaining = budget.totalUsd - spentUsd;
      const perBudget = Math.min(budget.perStrategyUsd ?? Infinity, remaining);

      try {
        const result = await withTimeout(
          strategy.run({ ...baseInput, budgetUsd: perBudget }, {}),
          budget.timeoutMs,
        );

        results.push(result);
        spentUsd += result.costUsd;

        // Early exit if this strategy is confident enough
        if (result.confidence >= strategyDef.earlyExitThreshold && result.findings.length > 0) {
          log.debug(
            `Strategy ${strategyDef.strategyId} confidence ${result.confidence} >= threshold ${strategyDef.earlyExitThreshold}, skipping remaining`,
          );
          break;
        }
      } catch (error) {
        log.warn(`Strategy ${strategyDef.strategyId} failed: ${toErrorMessage(error)}`);
      }
    }
  }

  log.info(
    `Executed ${results.length} strategies for ${profile.vulnClass}, total cost $${spentUsd.toFixed(4)}`,
  );
  return results;
}

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error(`Strategy timed out after ${timeoutMs}ms`)), timeoutMs),
    ),
  ]);
}
