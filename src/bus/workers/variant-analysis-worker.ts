import type { AgentRuntime } from "../../agent-runtime/types.js";
import { resolveStageModel } from "../../agents/tasks/runtime-overrides.js";
import type { Finding } from "../../scanners/types.js";
import type { KuzushiConfig, RepoContext, TriageResult } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { analyzeVariants, analyzeVariantsBatch } from "../../agents/tasks/variant-analysis.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import type { RunContext, TriageCompleteEvent, VariantAnalysisCompleteEvent } from "../events.js";

export interface VariantAnalysisWorkerDeps {
  bus: MessageBus;
  config: KuzushiConfig;
  runtime: AgentRuntime;
}

/**
 * Worker that listens for triage completion and runs variant analysis
 * on confirmed true-positive findings.
 */
export function registerVariantAnalysisWorker(deps: VariantAnalysisWorkerDeps): void {
  const { bus, config } = deps;

  if (!config.variantAnalysis) return;

  bus.subscribe<TriageCompleteEvent>("triage:complete", async (event) => {
    const context = event.payload.context;
    const runId = event.meta.runId;
    const model = resolveStageModel(config, "variant-analysis");
    const maxFindings = config.variantAnalysisMaxFindings ?? 10;

    // We need triage results and scan findings from the event context
    // The orchestrator will emit variant-analysis:start with the confirmed TPs
    // This subscription is handled by the orchestrator integration
    const tag = "[variant-analysis-worker]";
    console.error(`${tag} Triage complete — variant analysis will be triggered by orchestrator`);
  });
}

/**
 * Run variant analysis for a set of confirmed TP findings.
 * Returns all variant findings discovered.
 */
export async function runVariantAnalysis(
  confirmedTPs: Array<{ finding: Finding; triageResult: TriageResult }>,
  context: RunContext,
  config: KuzushiConfig,
  runtime: AgentRuntime,
): Promise<{ findings: Finding[]; costUsd: number }> {
  const model = resolveStageModel(config, "variant-analysis");
  const maxFindingsPerVariant = config.variantAnalysisMaxFindings ?? 10;
  const allFindings: Finding[] = [];
  let totalCost = 0;
  const MAX_BATCH_SIZE = 5;

  const tag = "[variant-analysis]";
  console.error(`${tag} Analyzing ${confirmedTPs.length} confirmed TPs for variants`);

  // Group by rule family (prefix before first '/') for batching
  const ruleGroups = new Map<string, Array<{ finding: Finding; triageResult: TriageResult }>>();
  for (const item of confirmedTPs) {
    const slashIdx = item.finding.ruleId.indexOf("/");
    const family = slashIdx > 0 ? item.finding.ruleId.slice(0, slashIdx) : item.finding.ruleId;
    const group = ruleGroups.get(family);
    if (group) {
      group.push(item);
    } else {
      ruleGroups.set(family, [item]);
    }
  }

  for (const [family, items] of ruleGroups) {
    // Groups of 2+ use batch; singletons use existing single-finding path
    if (items.length >= 2) {
      // Process in chunks of MAX_BATCH_SIZE
      for (let i = 0; i < items.length; i += MAX_BATCH_SIZE) {
        const batch = items.slice(i, i + MAX_BATCH_SIZE);
        try {
          const result = await analyzeVariantsBatch(
            batch,
            context.repoRoot,
            context.repoName,
            model,
            maxFindingsPerVariant,
            runtime,
          );
          allFindings.push(...result.findings);
          totalCost += result.costUsd;
          if (result.findings.length > 0) {
            console.error(`${tag} Found ${result.findings.length} variants in batch for family "${family}"`);
          }
        } catch (error) {
          console.error(`${tag} Batch error for family "${family}": ${toErrorMessage(error)}, falling back to per-finding`);
          // Fallback: process individually
          for (const item of batch) {
            try {
              const result = await analyzeVariants(
                item.finding,
                item.triageResult,
                context.repoRoot,
                context.repoName,
                model,
                maxFindingsPerVariant,
                runtime,
              );
              allFindings.push(...result.findings);
              totalCost += result.costUsd;
            } catch (innerError) {
              console.error(`${tag} Error analyzing variants for ${item.finding.fingerprint}: ${toErrorMessage(innerError)}`);
            }
          }
        }
      }
    } else {
      const { finding, triageResult } = items[0];
      try {
        const result = await analyzeVariants(
          finding,
          triageResult,
          context.repoRoot,
          context.repoName,
          model,
          maxFindingsPerVariant,
          runtime,
        );
        allFindings.push(...result.findings);
        totalCost += result.costUsd;
        if (result.findings.length > 0) {
          console.error(`${tag} Found ${result.findings.length} variants of ${finding.ruleId}`);
        }
      } catch (error) {
        console.error(`${tag} Error analyzing variants for ${finding.fingerprint}: ${toErrorMessage(error)}`);
      }
    }
  }

  console.error(`${tag} Complete: ${allFindings.length} total variants found ($${totalCost.toFixed(4)})`);
  return { findings: allFindings, costUsd: totalCost };
}
