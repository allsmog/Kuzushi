import { verifyFindingWithAgent, VerificationExecutionError } from "../../verify.js";
import { withRetry } from "../../retry.js";
import type { KuzushiConfig, RepoContext } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { VerificationFindingQueuedEvent } from "../events.js";
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
            deps.config.verifyMaxTurns ?? 15,
            asRepoContext(repoContext),
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
}

function asRepoContext(value: unknown): RepoContext | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  const repoContext: RepoContext = {
    languages: asStringArray(value["languages"]),
    frameworks: asStringArray(value["frameworks"]),
    authPatterns: asStringArray(value["authPatterns"]),
    sanitizationLibs: asStringArray(value["sanitizationLibs"]),
    ormOrDb: asStringArray(value["ormOrDb"]),
    entryPoints: asStringArray(value["entryPoints"]),
  };

  const hasAnyValue = (
    repoContext.languages.length > 0
    || repoContext.frameworks.length > 0
    || repoContext.authPatterns.length > 0
    || repoContext.sanitizationLibs.length > 0
    || repoContext.ormOrDb.length > 0
    || repoContext.entryPoints.length > 0
  );

  return hasAnyValue ? repoContext : undefined;
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter(Boolean);
}
