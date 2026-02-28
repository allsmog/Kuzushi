import { generatePocHarness, PocHarnessExecutionError } from "../../poc-harness.js";
import { withRetry } from "../../retry.js";
import type { KuzushiConfig, RepoContext } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { PocHarnessFindingQueuedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface PocHarnessWorkerDeps {
  config: KuzushiConfig;
}

/**
 * PoC harness worker: generates runnable exploit harnesses against verified exploitable findings.
 */
export function registerPocHarnessWorker(
  bus: MessageBus,
  deps: PocHarnessWorkerDeps,
): void {
  bus.subscribe<PocHarnessFindingQueuedEvent>("poc-harness:finding-queued", async (event) => {
    const { context, finding, triageResult, verificationResult, repoContext, index, total } = event.payload;
    const runId = event.meta.runId;
    let attempts = 0;

    try {
      const { result, costUsd } = await withRetry(
        async () => {
          attempts += 1;
          return generatePocHarness(
            finding,
            triageResult,
            verificationResult,
            context.scanPath ?? context.repoRoot,
            context.repoName,
            deps.config.pocHarnessModel
              ?? deps.config.verifyModel
              ?? deps.config.triageModel
              ?? deps.config.model,
            deps.config.pocHarnessMaxTurns ?? 20,
            asRepoContext(repoContext),
            {
              activityCallback: async (activity) => {
                await bus.publish(
                  createEvent("poc-harness:agent-activity", runId, {
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
          maxRetries: deps.config.maxPocHarnessRetries ?? deps.config.maxVerifyRetries ?? 2,
          backoffMs: deps.config.retryBackoffMs ?? 5000,
          multiplier: deps.config.retryBackoffMultiplier ?? 2,
        },
      );
      result.costUsd = costUsd;

      await bus.publish(
        createEvent("poc-harness:result", runId, {
          context,
          finding,
          triageResult,
          verificationResult,
          result,
          costUsd,
          attempts,
          index,
          total,
        }),
      );
    } catch (error) {
      const costUsd = error instanceof PocHarnessExecutionError ? error.costUsd : undefined;
      await bus.publish(
        createEvent("poc-harness:error", runId, {
          context,
          finding,
          triageResult,
          verificationResult,
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
