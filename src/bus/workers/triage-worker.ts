import type { TaskRegistry } from "../../agents/registry.js";
import type { ScannerRegistry } from "../../scanners/registry.js";
import type { Finding, TriageAgentConfig } from "../../scanners/types.js";
import { triageFindingWithAgent } from "../../triage.js";
import type { KuzushiConfig } from "../../types.js";
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
    const { context, finding, index, total } = event.payload;
    const runId = event.meta.runId;

    try {
      const result = await triageFindingWithAgent(
        triageConfigProvider,
        finding,
        context.repoRoot,
        context.repoName,
        deps.config.triageModel ?? deps.config.model,
        deps.config.triageMaxTurns,
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

      await bus.publish(
        createEvent("triage:result", runId, {
          context,
          finding,
          result,
          index,
          total,
        }),
      );
    } catch (error) {
      await bus.publish(
        createEvent("triage:error", runId, {
          context,
          finding,
          error: toErrorMessage(error),
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

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}
