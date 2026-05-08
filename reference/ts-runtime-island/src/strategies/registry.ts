import type { RepoContext } from "../types.js";
import type { AnalysisStrategy } from "./types.js";

/** Registry for analysis strategies, queryable by CWE. */
export class StrategyRegistry {
  private readonly strategies = new Map<string, AnalysisStrategy>();

  register(strategy: AnalysisStrategy): void {
    if (this.strategies.has(strategy.id)) {
      throw new Error(`Strategy '${strategy.id}' is already registered.`);
    }
    this.strategies.set(strategy.id, strategy);
  }

  getById(id: string): AnalysisStrategy | undefined {
    return this.strategies.get(id);
  }

  /** Get all strategies applicable to the given CWE IDs. */
  getForCwe(cweIds: string[], repoContext?: RepoContext): AnalysisStrategy[] {
    return [...this.strategies.values()].filter((s) => s.appliesTo(cweIds, repoContext));
  }

  /** Get strategies sorted by costTier (cheapest first). */
  getOrderedForCwe(cweIds: string[], repoContext?: RepoContext): AnalysisStrategy[] {
    return this.getForCwe(cweIds, repoContext).sort((a, b) => a.costTier - b.costTier);
  }

  /** List all registered strategy IDs. */
  ids(): string[] {
    return [...this.strategies.keys()];
  }
}
