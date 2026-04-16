import { CWE_STRATEGY_PROFILES } from "./cwe-strategy-map.js";
import { createDataflowStrategy } from "./dataflow/index.js";
import { createExecutionStrategy } from "./execution/index.js";
import { createReasoningStrategy } from "./reasoning/index.js";
import { StrategyRegistry } from "./registry.js";
import { createSyntacticStrategy } from "./syntactic/index.js";

/** Instantiate all strategies from CWE profiles and return a populated registry. */
export function createPopulatedRegistry(): StrategyRegistry {
  const registry = new StrategyRegistry();
  const registered = new Set<string>();

  for (const profile of CWE_STRATEGY_PROFILES) {
    for (const { strategyId } of profile.strategies) {
      if (registered.has(strategyId)) continue;
      registered.add(strategyId);

      const kind = strategyId.split("-")[0];
      switch (kind) {
        case "syntactic":
          registry.register(createSyntacticStrategy(strategyId, profile.cweIds));
          break;
        case "dataflow":
          registry.register(createDataflowStrategy(strategyId, profile.cweIds));
          break;
        case "reasoning":
          registry.register(createReasoningStrategy(strategyId, profile.cweIds));
          break;
        case "execution":
          registry.register(createExecutionStrategy(strategyId, profile.cweIds));
          break;
      }
    }
  }

  return registry;
}
