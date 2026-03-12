import type { TaskRegistry } from "../../agents/registry.js";
import type { TaskContext } from "../../agents/types.js";
import type { KnowledgeRegistry } from "../../knowledge/types.js";
import type { ScannerRegistry } from "../../scanners/registry.js";
import type { ScannerConfig, ScannerId } from "../../scanners/types.js";
import type { KuzushiConfig } from "../../types.js";
import { loadSecurityProfiles } from "../../security-profiles.js";
import { toErrorMessage } from "../../utils.js";
import { executeAgentTask, executeScannerPlugin } from "../task-execution.js";
import type { ScanStartEvent, TaskStartEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface ScanWorkerDeps {
  registry: ScannerRegistry;
  taskRegistry?: TaskRegistry;
  config: KuzushiConfig;
  knowledgeRegistry?: KnowledgeRegistry;
}

/**
 * Scan worker: executes scanner plugins (legacy scan:start) and generic tasks (task:start).
 */
export function registerScanWorker(bus: MessageBus, deps: ScanWorkerDeps): void {
  bus.subscribe<ScanStartEvent>("scan:start", async (event) => {
    const { context, scanners, scanOpts } = event.payload;
    const runId = event.meta.runId;

    try {
      const mode = deps.config.scanMode;
      const counts: number[] = [];

      if (mode === "concurrent") {
        const results = await Promise.all(
          scanners.map((scannerId) => runSingleScanner(bus, deps, runId, context, scanOpts, scannerId)),
        );
        counts.push(...results);
      } else {
        for (const scannerId of scanners) {
          const count = await runSingleScanner(bus, deps, runId, context, scanOpts, scannerId);
          counts.push(count);
        }
      }

      const totalFindings = counts.reduce((sum, count) => sum + count, 0);
      await bus.publish(
        createEvent("scan:complete", runId, {
          context,
          totalFindings,
        }),
      );
    } catch (error) {
      await bus.publish(
        createEvent("pipeline:error", runId, {
          context,
          error: toErrorMessage(error),
          fatal: true,
        }),
      );
    }
  });

  bus.subscribe<TaskStartEvent>("task:start", async (event) => {
    if (!deps.taskRegistry) {
      return;
    }

    const { context, taskId, input, upstreamOutputs } = event.payload;
    const runId = event.meta.runId;

    if (!deps.taskRegistry.has(taskId)) {
      await bus.publish(
        createEvent("task:error", runId, {
          context,
          taskId,
          outputKind: "findings",
          error: `Task "${taskId}" not found in registry`,
        }),
      );
      return;
    }

    const task = deps.taskRegistry.get(taskId);

    try {
      const taskConfig = resolveTaskConfig(deps.config, taskId);

      let securityProfiles;
      try {
        securityProfiles = loadSecurityProfiles(context.repoRoot);
      } catch {
        // Security profiles loading is best-effort.
      }

      const taskContext: TaskContext = {
        runId,
        repoRoot: context.scanPath ?? context.repoRoot,
        scanPath: context.scanPath,
        repoName: context.repoName,
        config: deps.config,
        bus,
        upstreamOutputs,
        securityProfiles,
        knowledgeRegistry: deps.knowledgeRegistry,
      };

      const executed = await executeAgentTask(task, input, taskContext, taskConfig);
      const { output, emittedFindings, durationMs, costUsd } = executed;

      for (const finding of emittedFindings) {
        await bus.publish(
          createEvent("task:progress", runId, {
            context,
            taskId,
            outputKind: task.outputKind,
            progress: finding,
          }),
        );

        await bus.publish(
          createEvent("scan:finding", runId, {
            context,
            finding,
            scannerId: taskId,
          }),
        );
      }

      if (task.outputKind === "findings" || task.outputKind === "threat-model") {
        await bus.publish(
          createEvent("scan:scanner-complete", runId, {
            context,
            scannerId: taskId,
            findingCount: emittedFindings.length,
            durationMs,
          }),
        );
      }

      await bus.publish(
        createEvent("task:complete", runId, {
          context,
          taskId,
          outputKind: task.outputKind,
          output,
          durationMs,
          costUsd,
        }),
      );
    } catch (error) {
      await bus.publish(
        createEvent("task:error", runId, {
          context,
          taskId,
          outputKind: task.outputKind,
          error: toErrorMessage(error),
        }),
      );
    }
  });
}

async function runSingleScanner(
  bus: MessageBus,
  deps: ScanWorkerDeps,
  runId: string,
  context: ScanStartEvent["payload"]["context"],
  scanOpts: ScanStartEvent["payload"]["scanOpts"],
  scannerId: ScannerId,
): Promise<number> {
  const plugin = deps.registry.get(scannerId);
  const pluginConfig = resolveTaskConfig(deps.config, scannerId);
  const { findings, durationMs, costUsd } = await executeScannerPlugin(
    plugin,
    context.scanPath ?? context.repoRoot,
    scanOpts,
    pluginConfig,
  );

  for (const finding of findings) {
    await bus.publish(
      createEvent("task:progress", runId, {
        context,
        taskId: scannerId,
        outputKind: "findings",
        progress: finding,
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding,
        scannerId,
      }),
    );
  }

  await bus.publish(
    createEvent("scan:scanner-complete", runId, {
      context,
      scannerId,
      findingCount: findings.length,
      durationMs,
    }),
  );

  await bus.publish(
    createEvent("task:complete", runId, {
      context,
      taskId: scannerId,
      outputKind: "findings",
      output: findings,
      durationMs,
      costUsd,
    }),
  );

  return findings.length;
}

function resolveTaskConfig(config: KuzushiConfig, taskId: string): ScannerConfig {
  const raw = config.scannerConfig[taskId];
  if (raw && typeof raw === "object" && !Array.isArray(raw)) {
    return raw;
  }
  return {};
}
