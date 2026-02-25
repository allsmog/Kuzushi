import type { TaskRegistry } from "../../agents/registry.js";
import type { ScannerRegistry } from "../../scanners/registry.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { withRetry } from "../../retry.js";
import { triageFindingWithAgent } from "../../triage.js";
import type { KuzushiConfig, RepoContext } from "../../types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../../utils.js";
import type { TriageFindingQueuedEvent } from "../events.js";
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
            context.repoRoot,
            context.repoName,
            deps.config.triageModel ?? deps.config.model,
            deps.config.triageMaxTurns,
            asRepoContext(repoContext),
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
