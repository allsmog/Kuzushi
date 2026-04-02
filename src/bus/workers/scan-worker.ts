import type { TaskRegistry } from "../../agents/registry.js";
import type { AgentTask, TaskContext } from "../../agents/types.js";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import type { KnowledgeRegistry } from "../../knowledge/types.js";
import type Database from "better-sqlite3";
import type { ScannerRegistry } from "../../scanners/registry.js";
import type { Finding, ScannerConfig, ScannerId } from "../../scanners/types.js";
import { attachTaskOutputMeta } from "../../task-output-meta.js";
import type { KuzushiConfig } from "../../types.js";
import { resolveScannerConfig } from "../../capabilities.js";
import { loadSecurityProfiles } from "../../security-profiles.js";
import { normalizeCostUsd, toErrorMessage } from "../../utils.js";
import { executeAgentTask, executeScannerPlugin } from "../task-execution.js";
import type { ScanStartEvent, TaskStartEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface ScanWorkerDeps {
  registry: ScannerRegistry;
  taskRegistry?: TaskRegistry;
  config: KuzushiConfig;
  runtime: AgentRuntime;
  knowledgeRegistry?: KnowledgeRegistry;
  db?: Database.Database;
}

const ENSEMBLE_ELIGIBLE_TASK_IDS = new Set([
  "secrets-crypto-detect",
  "code-config-detect",
  "race-condition-detect",
  "ssrf-detect",
  "prototype-pollution-detect",
  "nosql-injection-detect",
  "template-injection-detect",
  "supply-chain-detect",
  "graphql-security-detect",
]);

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
        runtime: deps.runtime,
        bus,
        upstreamOutputs,
        securityProfiles,
        knowledgeRegistry: deps.knowledgeRegistry,
        db: deps.db,
      };

      const executed = await executeTaskWithOptionalEnsemble(task, input, taskContext, taskConfig, deps.config);
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
    deps.runtime,
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
  return resolveScannerConfig(config, taskId);
}

async function executeTaskWithOptionalEnsemble(
  task: AgentTask,
  input: unknown,
  taskContext: TaskContext,
  taskConfig: ScannerConfig,
  config: KuzushiConfig,
) {
  const ensembleModels = normalizeEnsembleModels(config.ensembleModels);
  if (
    ensembleModels.length <= 1
    || task.outputKind !== "findings"
    || !ENSEMBLE_ELIGIBLE_TASK_IDS.has(task.id)
  ) {
    return executeAgentTask(task, input, taskContext, taskConfig);
  }

  const startedAt = Date.now();
  const laneResults = await Promise.all(
    ensembleModels.map(async (model) => {
      try {
        const result = await executeAgentTask(task, input, {
          ...taskContext,
          modelOverride: model,
        }, taskConfig);
        return { kind: "success" as const, model, result };
      } catch (error) {
        return { kind: "error" as const, model, error };
      }
    }),
  );

  const successes = laneResults.filter((lane): lane is Extract<typeof laneResults[number], { kind: "success" }> => lane.kind === "success");
  if (successes.length === 0) {
    const firstError = laneResults.find((lane): lane is Extract<typeof laneResults[number], { kind: "error" }> => lane.kind === "error");
    throw firstError?.error ?? new Error(`All ensemble runs failed for task "${task.id}"`);
  }

  const mergedFindings = mergeEnsembleFindings(
    successes.flatMap((lane) => lane.result.emittedFindings.map((finding) => ({ finding, model: lane.model }))),
  );
  const costUsd = successes.reduce((sum, lane) => sum + normalizeCostUsd(lane.result.costUsd), 0);
  const output = attachTaskOutputMeta(mergedFindings, { costUsd });

  return {
    output,
    emittedFindings: mergedFindings,
    durationMs: Date.now() - startedAt,
    costUsd,
  };
}

function normalizeEnsembleModels(value: KuzushiConfig["ensembleModels"]): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const unique = new Set<string>();
  for (const model of value) {
    if (typeof model !== "string") {
      continue;
    }
    const trimmed = model.trim();
    if (trimmed) {
      unique.add(trimmed);
    }
  }
  return [...unique];
}

function mergeEnsembleFindings(
  findings: Array<{ finding: Finding; model: string }>,
): Finding[] {
  const groups = new Map<string, Array<{ finding: Finding; model: string }>>();
  for (const entry of findings) {
    const key = buildEnsembleKey(entry.finding);
    const group = groups.get(key) ?? [];
    group.push(entry);
    groups.set(key, group);
  }

  const merged: Finding[] = [];
  for (const group of groups.values()) {
    const sorted = [...group].sort(
      (left, right) => getFindingScore(right.finding) - getFindingScore(left.finding),
    );
    const primary = sorted[0].finding;
    const corroboratingSignals = [
      ...(primary.corroboratingSignals ?? []),
      ...sorted.slice(1).map(({ finding, model }) => ({
        scanner: `${finding.scanner}:${model}`,
        fingerprint: finding.fingerprint,
        ruleId: finding.ruleId,
        filePath: finding.filePath,
        startLine: finding.startLine,
        cwe: [...finding.cwe],
        score: finding.score,
      })),
    ];
    const corroboratingModels = new Set(sorted.map(({ model }) => model));
    const corroborationBoost = Math.min(15, Math.max(0, corroboratingModels.size - 1) * 5);
    const adjustedScore = Math.min(100, getFindingScore(primary) + corroborationBoost);

    merged.push({
      ...primary,
      adjustedScore,
      scannerConfidence: boostScannerConfidence(primary.scannerConfidence, corroboratingModels.size),
      corroboratingSignals: corroboratingSignals.length > 0 ? corroboratingSignals : primary.corroboratingSignals,
    });
  }

  merged.sort((left, right) => getFindingScore(right) - getFindingScore(left));
  return merged;
}

function buildEnsembleKey(finding: Finding): string {
  const normalizedCwe = [...new Set(finding.cwe.map((entry) => entry.trim().toUpperCase()).filter(Boolean))]
    .sort((left, right) => left.localeCompare(right))
    .join(",");
  return [
    finding.filePath.replace(/\\/g, "/").toLowerCase(),
    Math.max(1, Math.floor(finding.startLine)),
    normalizedCwe,
  ].join("|");
}

function getFindingScore(finding: Finding): number {
  return finding.adjustedScore ?? finding.score;
}

function boostScannerConfidence(
  confidence: string,
  corroboratingModels: number,
): string {
  if (corroboratingModels <= 1) {
    return confidence;
  }
  if (confidence === "LOW") {
    return "MEDIUM";
  }
  return "HIGH";
}
