import type { TaskRegistry } from "../../agents/registry.js";
import type { TaskContext } from "../../agents/types.js";
import type { ScannerRegistry } from "../../scanners/registry.js";
import type { Finding, ScannerConfig, ScannerId } from "../../scanners/types.js";
import type { KuzushiConfig } from "../../types.js";
import { isRecord, toErrorMessage } from "../../utils.js";
import type { ScanStartEvent, TaskStartEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface ScanWorkerDeps {
  registry: ScannerRegistry;
  taskRegistry?: TaskRegistry;
  config: KuzushiConfig;
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
      return;
    }

    const task = deps.taskRegistry.get(taskId);
    const startedAt = Date.now();

    try {
      const taskConfig = resolveTaskConfig(deps.config, taskId);
      if (task.init) {
        await task.init(taskConfig);
      }

      const taskContext: TaskContext = {
        runId,
        repoRoot: context.scanPath ?? context.repoRoot,
        scanPath: context.scanPath,
        repoName: context.repoName,
        config: deps.config,
        bus,
        upstreamOutputs,
      };

      const output = await task.run(input, taskContext);

      if (task.outputKind === "findings") {
        const findings = asFindings(output);
        for (const finding of findings) {
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

        await bus.publish(
          createEvent("scan:scanner-complete", runId, {
            context,
            scannerId: taskId,
            findingCount: findings.length,
            durationMs: Date.now() - startedAt,
          }),
        );
      }

      await bus.publish(
        createEvent("task:complete", runId, {
          context,
          taskId,
          outputKind: task.outputKind,
          output,
          durationMs: Date.now() - startedAt,
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
  const startedAt = Date.now();

  if (plugin.init) {
    await plugin.init(pluginConfig);
  }

  const findings = await plugin.scan(context.scanPath ?? context.repoRoot, scanOpts, pluginConfig);

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
      durationMs: Date.now() - startedAt,
    }),
  );

  await bus.publish(
    createEvent("task:complete", runId, {
      context,
      taskId: scannerId,
      outputKind: "findings",
      output: findings,
      durationMs: Date.now() - startedAt,
    }),
  );

  return findings.length;
}

function resolveTaskConfig(config: KuzushiConfig, taskId: string): ScannerConfig {
  const raw = config.scannerConfig[taskId];
  if (isRecord(raw)) {
    return raw;
  }
  return {};
}

function asFindings(value: unknown): Finding[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const findings: Finding[] = [];
  for (const item of value) {
    if (!isRecord(item)) {
      continue;
    }

    const finding = asFinding(item);
    if (!finding) {
      continue;
    }

    findings.push(finding);
  }

  return findings;
}

function asFinding(item: Record<string, unknown>): Finding | null {
  const fingerprint = asString(item["fingerprint"]);
  const ruleId = asString(item["ruleId"]);
  const filePath = asString(item["filePath"]);
  const startLine = asNumber(item["startLine"]);
  const severity = asString(item["severity"]);
  const message = asString(item["message"]);
  const evidence = asString(item["evidence"]);
  const scannerConfidence = asString(item["scannerConfidence"]);
  const subcategory = asStringArray(item["subcategory"]);
  const likelihood = asString(item["likelihood"]);
  const impact = asString(item["impact"]);
  const cwe = asStringArray(item["cwe"]);
  const score = asNumber(item["score"]);

  if (
    !fingerprint ||
    !ruleId ||
    !filePath ||
    startLine === null ||
    !severity ||
    !message ||
    !scannerConfidence ||
    !subcategory ||
    !likelihood ||
    !impact ||
    !cwe ||
    score === null
  ) {
    return null;
  }

  const scanner = asString(item["scanner"]) ?? "unknown";

  return {
    scanner,
    fingerprint,
    ruleId,
    filePath,
    startLine,
    severity,
    message,
    evidence,
    scannerConfidence,
    subcategory,
    likelihood,
    impact,
    cwe,
    score,
  };
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function asStringArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) {
    return null;
  }

  if (!value.every((item) => typeof item === "string")) {
    return null;
  }

  return value;
}
