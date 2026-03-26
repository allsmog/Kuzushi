import { createLogger } from "../logger.js";
import type { AgentTask, TaskContext } from "../agents/types.js";
import type { StrategyRegistry } from "./registry.js";
import type { CweStrategyProfile } from "./cwe-strategy-map.js";
import { executeStrategies, resolveMultiStrategyMode } from "./executor.js";
import { mergeStrategyResults } from "./merge.js";
import type { Finding } from "../scanners/types.js";
import type { MultiStrategyMode } from "./types.js";

const log = createLogger({ stage: "multi-strategy" });

/**
 * Wrap an existing detection task with multi-strategy analysis.
 * When multi-strategy mode is disabled, delegates directly to the wrapped task.
 * Same task ID — transparent replacement.
 */
export function withMultiStrategy<TInput, TOutput>(
  wrappedTask: AgentTask<TInput, TOutput>,
  profile: CweStrategyProfile,
  getRegistry: () => StrategyRegistry | undefined,
): AgentTask<TInput, TOutput> {
  return {
    ...wrappedTask,
    id: wrappedTask.id,
    displayName: wrappedTask.displayName,
    outputKind: wrappedTask.outputKind,
    dependsOn: wrappedTask.dependsOn,

    async run(input: TInput, context: TaskContext): Promise<TOutput> {
      const mode = resolveMultiStrategyMode(context.config as unknown as Record<string, unknown>);
      if (mode === "off") {
        return wrappedTask.run(input, context);
      }

      const registry = getRegistry();
      if (!registry) {
        log.warn("No strategy registry available, falling back to wrapped task");
        return wrappedTask.run(input, context);
      }

      // Run the primary task
      const primaryResult = await wrappedTask.run(input, context);

      // Run multi-strategy analysis in parallel
      const strategyResults = await executeStrategies(
        profile,
        context,
        registry,
        mode,
        {
          repoRoot: context.repoRoot,
          repoName: context.repoName,
          context,
        },
      );

      if (strategyResults.length === 0) {
        return primaryResult;
      }

      // Merge strategy results
      const merged = mergeStrategyResults(strategyResults);

      // If the primary result is an array of findings, enrich with strategy evidence
      if (Array.isArray(primaryResult)) {
        const enriched = enrichFindingsWithStrategyEvidence(
          primaryResult as Finding[],
          merged.findings,
          merged.strategyAgreement,
        );
        return enriched as TOutput;
      }

      return primaryResult;
    },
  };
}

/** Enrich primary findings with corroborating evidence from strategy results. */
function enrichFindingsWithStrategyEvidence(
  primary: Finding[],
  strategyFindings: Finding[],
  agreement: string,
): Finding[] {
  // Build a map of strategy findings by location
  const strategyByLocation = new Map<string, Finding>();
  for (const f of strategyFindings) {
    const key = `${f.filePath}:${f.startLine}`;
    const existing = strategyByLocation.get(key);
    if (!existing || (f.adjustedScore ?? f.score) > (existing.adjustedScore ?? existing.score)) {
      strategyByLocation.set(key, f);
    }
  }

  return primary.map((finding) => {
    const key = `${finding.filePath}:${finding.startLine}`;
    const strategyMatch = strategyByLocation.get(key);

    if (!strategyMatch) return finding;

    // Merge corroborating signals
    return {
      ...finding,
      adjustedScore: Math.max(
        finding.adjustedScore ?? finding.score,
        strategyMatch.adjustedScore ?? strategyMatch.score,
      ),
      corroboratingSignals: [
        ...(finding.corroboratingSignals ?? []),
        ...(strategyMatch.corroboratingSignals ?? []),
      ],
      engineProvenance: [
        ...(finding.engineProvenance ?? []),
        ...(strategyMatch.engineProvenance ?? []),
      ],
    };
  });
}
