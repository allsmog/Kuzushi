import { verifyFindingWithAgent, verifyFindingsBatch, VerificationExecutionError } from "../../verify.js";
import { withRetry } from "../../retry.js";
import { coerceRepoContext } from "../../repo-context.js";
import type { KuzushiConfig } from "../../types.js";
import { toErrorMessage } from "../../utils.js";
import type { VerificationBatchQueuedEvent, VerificationFindingQueuedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface VerificationWorkerDeps {
  config: KuzushiConfig;
}

/**
 * Verification worker: validates exploitability with concrete source-to-sink analysis.
 */
export function registerVerificationWorker(
  bus: MessageBus,
  deps: VerificationWorkerDeps,
): void {
  bus.subscribe<VerificationFindingQueuedEvent>("verification:finding-queued", async (event) => {
    const { context, finding, triageResult, repoContext, index, total } = event.payload;
    const runId = event.meta.runId;
    let attempts = 0;

    try {
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
          );
        },
        {
          maxRetries: deps.config.maxVerifyRetries ?? 2,
          backoffMs: deps.config.retryBackoffMs ?? 5000,
          multiplier: deps.config.retryBackoffMultiplier ?? 2,
        },
      );
      result.verifyCostUsd = costUsd;

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
    const { context, items, repoContext } = event.payload;
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
            {},
            deps.config.verifyBatchSize ?? 5,
            deps.config.verifyMaxTurns,
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
