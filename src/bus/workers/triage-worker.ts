import type { TaskRegistry } from "../../agents/registry.js";
import type { ScannerRegistry } from "../../scanners/registry.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { withRetry } from "../../retry.js";
import { coerceRepoContext } from "../../repo-context.js";
import { triageFindingWithAgent, triageFindingsBatch, BATCH_TRIAGE_FALLBACK_RATIONALE } from "../../triage.js";
import type { KuzushiConfig } from "../../types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../../utils.js";
import type { TriageBatchQueuedEvent, TriageFindingQueuedEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface TriageWorkerDeps {
  registry: ScannerRegistry;
  taskRegistry?: TaskRegistry;
  config: KuzushiConfig;
}

/**
 * Triage worker: invokes an agentic triage pass per finding.
 */
export function registerTriageWorker(bus: MessageBus, deps: TriageWorkerDeps): void {
  const triageConfigProvider = createTriageConfigProvider(deps.registry, deps.taskRegistry);

  bus.subscribe<TriageFindingQueuedEvent>("triage:finding-queued", async (event) => {
    const { context, finding, repoContext, index, total } = event.payload;
    const runId = event.meta.runId;
    let attempts = 0;

    try {
      const { result, costUsd } = await withRetry(
        async () => {
          attempts += 1;
          return triageFindingWithAgent(
            triageConfigProvider,
            finding,
            context.scanPath ?? context.repoRoot,
            context.repoName,
            deps.config.triageModel ?? deps.config.model,
            deps.config.triageMaxTurns,
            coerceRepoContext(repoContext),
            {
              activityCallback: async (activity) => {
                await bus.publish(
                  createEvent("triage:agent-activity", runId, {
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
          maxRetries: deps.config.maxTriageRetries ?? 2,
          backoffMs: deps.config.retryBackoffMs ?? 5000,
          multiplier: deps.config.retryBackoffMultiplier ?? 2,
        },
      );
      result.triageCostUsd = costUsd;

      await bus.publish(
        createEvent("triage:result", runId, {
          context,
          finding,
          result,
          costUsd,
          attempts,
          index,
          total,
        }),
      );
    } catch (error) {
      const costUsd = getErrorCostUsd(error);
      await bus.publish(
        createEvent("triage:error", runId, {
          context,
          finding,
          error: toErrorMessage(error),
          costUsd,
          attempts,
          index,
          total,
        }),
      );
    }
  });

  bus.subscribe<TriageBatchQueuedEvent>("triage:batch-queued", async (event) => {
    const { context, findings, repoContext, total } = event.payload;
    const runId = event.meta.runId;

    try {
      const { results, costUsd } = await triageFindingsBatch(
        findings,
        context.scanPath ?? context.repoRoot,
        context.repoName,
        deps.config.triageModel ?? deps.config.model,
        coerceRepoContext(repoContext),
        {
          activityCallback: async (activity) => {
            await bus.publish(
              createEvent("triage:agent-activity", runId, {
                context,
                fingerprint: "batch",
                kind: activity.kind,
                toolName: activity.toolName,
                toolInput: activity.toolInput,
                summary: activity.summary,
                elapsedSeconds: activity.elapsedSeconds,
                index: 0,
                total,
              }),
            );
          },
        },
        deps.config.triageBatchSize,
        deps.config.triageMaxTurns,
      );

      const perFindingCost = findings.length > 0 ? costUsd / findings.length : 0;

      for (const [idx, finding] of findings.entries()) {
        const result = results.get(finding.fingerprint);
        const isFallback = result?.confidence === 0
          && result?.rationale === BATCH_TRIAGE_FALLBACK_RATIONALE;

        if (result && !isFallback) {
          result.triageCostUsd = perFindingCost;
          await bus.publish(
            createEvent("triage:result", runId, {
              context,
              finding,
              result,
              costUsd: perFindingCost,
              attempts: 1,
              index: idx + 1,
              total,
            }),
          );
        } else {
          await bus.publish(
            createEvent("triage:error", runId, {
              context,
              finding,
              error: isFallback
                ? "Finding omitted from batch triage response"
                : "Finding missing from batch triage response",
              costUsd: perFindingCost,
              attempts: 1,
              index: idx + 1,
              total,
            }),
          );
        }
      }
    } catch (error) {
      const errorCostUsd = getErrorCostUsd(error);
      const perFindingCost = findings.length > 0 && errorCostUsd != null
        ? errorCostUsd / findings.length
        : undefined;

      for (const [idx, finding] of findings.entries()) {
        await bus.publish(
          createEvent("triage:error", runId, {
            context,
            finding,
            error: toErrorMessage(error),
            costUsd: perFindingCost,
            attempts: 1,
            index: idx + 1,
            total,
          }),
        );
      }
    }
  });
}

function createTriageConfigProvider(
  registry: ScannerRegistry,
  taskRegistry?: TaskRegistry,
): {
  has(id: string): boolean;
  get(id: string): { triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig };
} {
  return {
    has(id: string): boolean {
      if (registry.has(id)) {
        return true;
      }

      if (!taskRegistry || !taskRegistry.has(id)) {
        return false;
      }

      return typeof taskRegistry.get(id).triageAgentConfig === "function";
    },
    get(id: string): { triageAgentConfig(finding: Finding, repoName: string): TriageAgentConfig } {
      if (registry.has(id)) {
        return registry.get(id);
      }

      if (!taskRegistry || !taskRegistry.has(id)) {
        throw new Error(`Unknown triage provider: ${id}`);
      }

      const task = taskRegistry.get(id);
      const triageAgentConfig = task.triageAgentConfig;
      if (typeof triageAgentConfig !== "function") {
        throw new Error(`Task "${id}" does not define triageAgentConfig`);
      }

      return {
        triageAgentConfig: (finding: Finding, repoName: string) => triageAgentConfig(finding, repoName),
      };
    },
  };
}

function getErrorCostUsd(error: unknown): number | undefined {
  if (!isRecord(error)) {
    return undefined;
  }

  const raw = error["costUsd"];
  if (typeof raw !== "number" || !Number.isFinite(raw) || raw < 0) {
    return undefined;
  }

  return normalizeCostUsd(raw);
}
