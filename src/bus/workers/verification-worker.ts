import { verifyFindingWithAgent, verifyFindingsBatch, VerificationExecutionError } from "../../verify.js";
import { withRetry } from "../../retry.js";
import { coerceContextEnrichment, coerceRepoContext } from "../../repo-context.js";
import type { KuzushiConfig } from "../../types.js";
import { toErrorMessage } from "../../utils.js";
import type { VerificationBatchQueuedEvent, VerificationFindingQueuedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import { resolveTemplates } from "../../prompts/loader.js";
import type Database from "better-sqlite3";
import type { KnowledgeRegistry } from "../../knowledge/types.js";
import { knowledgeInjectionModule } from "../../prompts/modules.js";
import { getBypassKnowledge, formatBypassForPrompt } from "../../bypass-knowledge.js";
import { formatPrecedentsForPrompt, type Precedents } from "../../precedents.js";
import {
  extractScannerSignal,
  extractTriageSignal,
  extractVerificationSignal,
  computeCompositeConfidence,
} from "../../scoring/composite-confidence.js";

export interface VerificationWorkerDeps {
  config: KuzushiConfig;
  /** Optional knowledge registry for domain-specific verification prompt enrichment. */
  knowledgeRegistry?: KnowledgeRegistry;
  /** Optional database handle for composite confidence features. */
  db?: Database.Database;
}

/**
 * Verification worker: validates exploitability with concrete source-to-sink analysis.
 */
export function registerVerificationWorker(
  bus: MessageBus,
  deps: VerificationWorkerDeps,
): void {
  const resolvedTemplates = resolveTemplates(deps.config);

  bus.subscribe<VerificationFindingQueuedEvent>("verification:finding-queued", async (event) => {
    const { context, finding, triageResult, repoContext, enrichedContext, index, total } = event.payload;
    const runId = event.meta.runId;
    let attempts = 0;

    try {
      // Build extra prompt context for verification enrichment
      const extraSections: string[] = [];

      // Knowledge registry — inject CWE-specific domain knowledge
      if (deps.knowledgeRegistry) {
        const modules = deps.knowledgeRegistry.query({ cwes: finding.cwe });
        if (modules.length > 0) {
          const sections = deps.knowledgeRegistry.formatForPrompt(modules);
          const knowledgeSection = knowledgeInjectionModule(sections);
          if (knowledgeSection) {
            extraSections.push(knowledgeSection);
          }
        }
      }

      // Precedents — inject org-specific architectural facts
      {
        const precedents = event.payload.precedents as Precedents | undefined;
        if (precedents) {
          const precedentLines = formatPrecedentsForPrompt(precedents);
          if (precedentLines.length > 0) {
            extraSections.push(precedentLines.join("\n"));
          }
        }
      }

      const extraPromptContext = extraSections.length > 0
        ? extraSections.join("\n\n")
        : undefined;

      // TODO: Pass extraPromptContext to verifyFindingWithAgent once verify.ts
      // is updated to accept an additional optional extraPromptContext parameter.
      void extraPromptContext;

      const { result, costUsd } = await withRetry(
        async () => {
          attempts += 1;
          return verifyFindingWithAgent(
            finding,
            triageResult,
            context.scanPath ?? context.repoRoot,
            context.repoName,
            deps.config.verifyModel ?? deps.config.triageModel ?? deps.config.model,
            deps.config.verifyMaxTurns,
            coerceRepoContext(repoContext),
            {
              enrichedContext: coerceContextEnrichment(enrichedContext),
              activityCallback: async (activity) => {
                await bus.publish(
                  createEvent("verification:agent-activity", runId, {
                    context,
                    fingerprint: finding.fingerprint,
                    kind: activity.kind,
                    toolName: activity.toolName,
                    toolInput: activity.toolInput,
                    summary: activity.summary,
                    elapsedSeconds: activity.elapsedSeconds,
                    index,
                    total,
                  }),
                );
              },
            },
            resolvedTemplates.verify,
          );
        },
        {
          maxRetries: deps.config.maxVerifyRetries ?? 2,
          backoffMs: deps.config.retryBackoffMs ?? 5000,
          multiplier: deps.config.retryBackoffMultiplier ?? 2,
        },
      );
      result.verifyCostUsd = costUsd;

      // Compute composite confidence from scanner + triage + verification signals
      {
        const scannerSignal = extractScannerSignal(finding);
        const triageSignal = extractTriageSignal(triageResult.confidence);
        const verificationSignal = extractVerificationSignal(result.exploitable);
        const composite = computeCompositeConfidence([scannerSignal, triageSignal, verificationSignal]);
        result.compositeConfidence = composite.composite;
      }

      await bus.publish(
        createEvent("verification:result", runId, {
          context,
          finding,
          triageResult,
          result,
          costUsd,
          attempts,
          index,
          total,
        }),
      );
    } catch (error) {
      const costUsd = error instanceof VerificationExecutionError ? error.costUsd : undefined;
      await bus.publish(
        createEvent("verification:error", runId, {
          context,
          finding,
          triageResult,
          error: toErrorMessage(error),
          costUsd,
          attempts,
          index,
          total,
        }),
      );
    }
  });

  bus.subscribe<VerificationBatchQueuedEvent>("verification:batch-queued", async (event) => {
    const { context, items, repoContext, enrichedContext } = event.payload;
    const runId = event.meta.runId;

    const batchItems = items.map((item) => ({
      finding: item.finding,
      triageResult: item.triageResult,
    }));

    try {
      const { results, costUsd } = await withRetry(
        () =>
          verifyFindingsBatch(
            batchItems,
            context.scanPath ?? context.repoRoot,
            context.repoName,
            deps.config.verifyModel ?? deps.config.triageModel ?? deps.config.model,
            coerceRepoContext(repoContext),
            { enrichedContext: coerceContextEnrichment(enrichedContext) },
            deps.config.verifyBatchSize ?? 5,
            deps.config.verifyMaxTurns,
            resolvedTemplates.verify,
          ),
        {
          maxRetries: deps.config.maxVerifyRetries ?? 2,
          backoffMs: deps.config.retryBackoffMs ?? 5000,
          multiplier: deps.config.retryBackoffMultiplier ?? 2,
        },
      );

      const perFindingCost = items.length > 0 ? costUsd / items.length : 0;

      for (const item of items) {
        const result = results.get(item.finding.fingerprint);
        if (result) {
          result.verifyCostUsd = perFindingCost;
          await bus.publish(
            createEvent("verification:result", runId, {
              context,
              finding: item.finding,
              triageResult: item.triageResult,
              result,
              costUsd: perFindingCost,
              attempts: 1,
              index: item.index,
              total: item.total,
            }),
          );
        }
      }
    } catch (error) {
      const costUsd = error instanceof VerificationExecutionError ? error.costUsd : undefined;
      const perFindingCost = costUsd != null && items.length > 0
        ? costUsd / items.length
        : undefined;

      for (const item of items) {
        await bus.publish(
          createEvent("verification:error", runId, {
            context,
            finding: item.finding,
            triageResult: item.triageResult,
            error: toErrorMessage(error),
            costUsd: perFindingCost,
            attempts: 1,
            index: item.index,
            total: item.total,
          }),
        );
      }
    }
  });
}
