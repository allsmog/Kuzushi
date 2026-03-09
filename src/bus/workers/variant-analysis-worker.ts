import type { Finding } from "../../scanners/types.js";
import type { KuzushiConfig, RepoContext, TriageResult } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import { analyzeVariants } from "../../agents/tasks/variant-analysis.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import type { RunContext, TriageCompleteEvent, VariantAnalysisCompleteEvent } from "../events.js";

export interface VariantAnalysisWorkerDeps {
  bus: MessageBus;
  config: KuzushiConfig;
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
    const model = config.variantAnalysisModel || config.model;
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
): Promise<{ findings: Finding[]; costUsd: number }> {
  const model = config.variantAnalysisModel || config.model;
  const maxFindingsPerVariant = config.variantAnalysisMaxFindings ?? 10;
  const allFindings: Finding[] = [];
  let totalCost = 0;

  const tag = "[variant-analysis]";
  console.error(`${tag} Analyzing ${confirmedTPs.length} confirmed TPs for variants`);

  for (const { finding, triageResult } of confirmedTPs) {
    try {
      const result = await analyzeVariants(
        finding,
        triageResult,
        context.repoRoot,
        context.repoName,
        model,
        maxFindingsPerVariant,
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

  console.error(`${tag} Complete: ${allFindings.length} total variants found ($${totalCost.toFixed(4)})`);
  return { findings: allFindings, costUsd: totalCost };
}
