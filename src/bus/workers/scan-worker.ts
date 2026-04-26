import type Database from "better-sqlite3";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import type { TaskRegistry } from "../../agents/registry.js";
import type { AgentTask, TaskContext } from "../../agents/types.js";
import { resolveTaskConfig as resolveConfiguredTaskConfig } from "../../capabilities.js";
import type { KnowledgeRegistry } from "../../knowledge/types.js";
import type { Finding, TaskConfig } from "../../scanners/types.js";
import { loadSecurityProfiles } from "../../security-profiles.js";
import { attachTaskOutputMeta, getTaskOutputMeta } from "../../task-output-meta.js";
import type { KuzushiConfig } from "../../types.js";
import { normalizeCostUsd, toErrorMessage } from "../../utils.js";
import type { TaskStartEvent } from "../events.js";
import { createEvent } from "../helpers.js";
import { getRunSignal } from "../run-signals.js";
import { wrapRuntimeWithActivityForwarding } from "../runtime-forwarding.js";
import { extractTaskFindings } from "../task-findings.js";
import type { MessageBus } from "../types.js";

export interface ScanWorkerDeps {
  taskRegistry: TaskRegistry;
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

/** Scan worker: executes finding-producing tasks. */
export function registerScanWorker(bus: MessageBus, deps: ScanWorkerDeps): void {
  bus.subscribe<TaskStartEvent>("task:start", async (event) => {
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
      const taskConfig = resolveConfiguredTaskConfig(deps.config, taskId);
      const projectRoot = context.repoRoot;
      const workRoot = context.scanPath ?? context.repoRoot;

      let securityProfiles: ReturnType<typeof loadSecurityProfiles> | undefined;
      try {
        securityProfiles = loadSecurityProfiles(projectRoot);
      } catch {
        // Security profiles loading is best-effort.
      }

      // Look up the pipeline's abort signal from the run-signal registry.
      // `runPipeline` registers the operator-provided signal under runId
      // before publishing `pipeline:start`; without this hop `TaskContext.signal`
      // stays undefined and tasks like threat-hunt can't honor Ctrl+C.
      const runSignal = getRunSignal(runId);

      const taskContext: TaskContext = {
        runId,
        projectRoot,
        workRoot,
        repoRoot: workRoot,
        scanPath: context.scanPath,
        ...(context.gitRoot ? { gitRoot: context.gitRoot } : {}),
        repoName: context.repoName,
        config: deps.config,
        runtime: wrapRuntimeWithActivityForwarding(deps.runtime, bus, taskId, runId, "scan"),
        bus,
        upstreamOutputs,
        securityProfiles,
        knowledgeRegistry: deps.knowledgeRegistry,
        db: deps.db,
        ...(runSignal ? { signal: runSignal } : {}),
      };

      const executed = await executeTaskWithOptionalEnsemble(
        task,
        input,
        taskContext,
        taskConfig,
        deps.config,
      );
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

/**
 * Run a task once, returning the structured result the scan-worker needs
 * (output, emitted findings, wall-clock, cost). Replaces the legacy
 * `executeAgentTask` helper — the bridge now ensures every DAG node is an
 * `AgentTask` adapter registered through a `CopilotModule`, so this inlined
 * call is the only invocation shape left.
 */
async function runTaskOnce(
  task: AgentTask,
  input: unknown,
  taskContext: TaskContext,
  taskConfig: TaskConfig,
) {
  const startedAt = Date.now();
  if (task.init) {
    await task.init(taskConfig);
  }
  const output = await task.run(input, taskContext);
  return {
    output,
    emittedFindings: extractTaskFindings(task.outputKind, output),
    durationMs: Date.now() - startedAt,
    costUsd: normalizeCostUsd(getTaskOutputMeta(output)?.costUsd),
  };
}

async function executeTaskWithOptionalEnsemble(
  task: AgentTask,
  input: unknown,
  taskContext: TaskContext,
  taskConfig: TaskConfig,
  config: KuzushiConfig,
) {
  const ensembleModels = normalizeEnsembleModels(config.ensembleModels);
  if (
    ensembleModels.length <= 1 ||
    task.outputKind !== "findings" ||
    !ENSEMBLE_ELIGIBLE_TASK_IDS.has(task.id)
  ) {
    return runTaskOnce(task, input, taskContext, taskConfig);
  }

  const startedAt = Date.now();
  const laneResults = await Promise.all(
    ensembleModels.map(async (model) => {
      try {
        const result = await runTaskOnce(
          task,
          input,
          {
            ...taskContext,
            modelOverride: model,
          },
          taskConfig,
        );
        return { kind: "success" as const, model, result };
      } catch (error) {
        return { kind: "error" as const, model, error };
      }
    }),
  );

  const successes = laneResults.filter(
    (lane): lane is Extract<(typeof laneResults)[number], { kind: "success" }> =>
      lane.kind === "success",
  );
  if (successes.length === 0) {
    const firstError = laneResults.find(
      (lane): lane is Extract<(typeof laneResults)[number], { kind: "error" }> =>
        lane.kind === "error",
    );
    throw firstError?.error ?? new Error(`All ensemble runs failed for task "${task.id}"`);
  }

  const mergedFindings = mergeEnsembleFindings(
    successes.flatMap((lane) =>
      lane.result.emittedFindings.map((finding) => ({ finding, model: lane.model })),
    ),
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

function mergeEnsembleFindings(findings: Array<{ finding: Finding; model: string }>): Finding[] {
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
        taskId: `${finding.taskId}:${model}`,
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
      scannerConfidence: boostScannerConfidence(
        primary.scannerConfidence,
        corroboratingModels.size,
      ),
      corroboratingSignals:
        corroboratingSignals.length > 0 ? corroboratingSignals : primary.corroboratingSignals,
    });
  }

  merged.sort((left, right) => getFindingScore(right) - getFindingScore(left));
  return merged;
}

function buildEnsembleKey(finding: Finding): string {
  const normalizedCwe = [
    ...new Set(finding.cwe.map((entry) => entry.trim().toUpperCase()).filter(Boolean)),
  ]
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

function boostScannerConfidence(confidence: string, corroboratingModels: number): string {
  if (corroboratingModels <= 1) {
    return confidence;
  }
  if (confidence === "LOW") {
    return "MEDIUM";
  }
  return "HIGH";
}
