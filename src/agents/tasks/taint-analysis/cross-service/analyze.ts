import { mkdir } from "node:fs/promises";
import path from "node:path";
import { type ExecutedTaskResult, executeAgentTask } from "../../../../bus/task-execution.js";
import type { Finding, TaskConfig } from "../../../../scanners/types.js";
import { attachTaskOutputMeta, getTaskOutputMeta } from "../../../../task-output-meta.js";
import type { ScanOpts } from "../../../../types.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../../../../utils.js";
import type { AgentTask, TaskContext } from "../../../types.js";
import { taintAnalysisRunTask } from "../analyze.js";
import { taintAnalysisLabelTask } from "../label.js";
import { taintAnalysisPreflightTask } from "../preflight.js";
import { resolveTaintAnalysisConfig } from "../types.js";
import { detectServiceBoundaries } from "./boundary-agent.js";
import {
  type BoundaryManifest,
  type CrossServiceAnalysisOutput,
  type CrossServiceDiscoverOutput,
  isTaintAnalysisLanguage,
  type PerServiceAnalysis,
  resolveCrossServiceConfig,
  type ServiceDescriptor,
} from "./types.js";

/**
 * Cross-service analysis task: for each discovered service, runs boundary detection
 * and (when language is supported) the standard taint-analysis pipeline programmatically.
 *
 * Follows the programmatic task invocation pattern from
 * src/bus/workers/taint-analysis-refinement-worker.ts:107-117.
 */
export const taintAnalysisCrossAnalyzeTask: AgentTask<ScanOpts, CrossServiceAnalysisOutput> = {
  id: "taint-analysis-cross-analyze",
  displayName: "Cross-Service Analyze",
  outputKind: "custom",
  dependsOn: ["taint-analysis-discover"],
  condition: (_upstreamOutputs, config) => {
    const cfg = resolveTaintAnalysisConfig(config);
    return resolveCrossServiceConfig(cfg).enabled;
  },
  async run(input, context): Promise<CrossServiceAnalysisOutput> {
    const cfg = resolveTaintAnalysisConfig(context.config);
    const crossCfg = resolveCrossServiceConfig(cfg);

    const discoverOutput = asCrossServiceDiscoverOutput(
      context.upstreamOutputs.get("taint-analysis-discover"),
    );
    if (!discoverOutput) {
      throw new Error(
        "taint-analysis-cross-analyze requires upstream output from taint-analysis-discover",
      );
    }

    const services = discoverOutput.services;
    if (services.length === 0) {
      return attachTaskOutputMeta({ services: [], allBoundaries: [] }, { costUsd: 0 });
    }

    // Process services with concurrency control
    const results: PerServiceAnalysis[] = [];
    const allBoundaries: BoundaryManifest[] = [];
    let totalCostUsd = 0;

    const semaphore = new Semaphore(crossCfg.concurrency);

    const promises = services.map(async (service) => {
      const release = await semaphore.acquire();
      try {
        const result = await analyzeService(
          service,
          input,
          context,
          crossCfg.boundaryModel,
          crossCfg.boundaryThreshold,
          crossCfg.continueOnError,
        );
        results.push(result.analysis);
        allBoundaries.push(result.analysis.boundary);
        totalCostUsd += result.costUsd;
      } catch (error) {
        totalCostUsd += getErrorCostUsd(error);
        if (!crossCfg.continueOnError) throw error;
        const degraded: PerServiceAnalysis = {
          service,
          boundary: {
            serviceId: service.id,
            servicePath: service.rootPath,
            entryPoints: [],
            exitPoints: [],
            errors: [toErrorMessage(error)],
          },
          intraServiceFindings: [],
          taintAnalysisSkipped: true,
          taintAnalysisSkipReason: toErrorMessage(error),
          durationMs: 0,
        };
        results.push(degraded);
        allBoundaries.push(degraded.boundary);
      } finally {
        release();
      }
    });

    const settled = await Promise.allSettled(promises);
    if (!crossCfg.continueOnError) {
      const rejection = settled.find((r) => r.status === "rejected");
      if (rejection) throw (rejection as PromiseRejectedResult).reason;
    }

    return attachTaskOutputMeta({ services: results, allBoundaries }, { costUsd: totalCostUsd });
  },
};

function asCrossServiceDiscoverOutput(value: unknown): CrossServiceDiscoverOutput | undefined {
  if (!isRecord(value)) {
    return undefined;
  }

  if (!Array.isArray(value["services"])) {
    return undefined;
  }

  return {
    services: value["services"].flatMap((service) => {
      if (!isRecord(service)) {
        return [];
      }

      const id = typeof service["id"] === "string" ? service["id"] : "";
      const rootPath = typeof service["rootPath"] === "string" ? service["rootPath"] : "";
      const language = typeof service["language"] === "string" ? service["language"] : "";
      if (!id || !rootPath || !language) {
        return [];
      }

      return [
        {
          id,
          displayName: typeof service["displayName"] === "string" ? service["displayName"] : id,
          rootPath,
          language,
          framework: typeof service["framework"] === "string" ? service["framework"] : null,
          discoveryMethod: service["discoveryMethod"] === "manifest" ? "manifest" : "auto",
          manifestFiles: Array.isArray(service["manifestFiles"])
            ? service["manifestFiles"].map((item) => String(item))
            : [],
        },
      ];
    }),
    usedManifest: Boolean(value["usedManifest"]),
    autoDetectedPaths: Array.isArray(value["autoDetectedPaths"])
      ? value["autoDetectedPaths"].map((item) => String(item))
      : [],
  };
}

// ── Per-Service Analysis ────────────────────────────────────────────────

interface AnalyzedServiceResult {
  analysis: PerServiceAnalysis;
  costUsd: number;
}

async function analyzeService(
  service: ServiceDescriptor,
  input: ScanOpts,
  context: TaskContext,
  boundaryModel: string,
  boundaryThreshold: number,
  continueOnError: boolean,
): Promise<AnalyzedServiceResult> {
  const startTime = Date.now();
  let totalCostUsd = 0;

  // Step 1: Run boundary detection
  let boundary: BoundaryManifest;
  try {
    boundary = await detectServiceBoundaries({
      service,
      repoRoot: context.repoRoot,
      model: boundaryModel,
      confidenceThreshold: boundaryThreshold,
      runtime: context.runtime,
    });
    totalCostUsd += normalizeCostUsd(getTaskOutputMeta(boundary)?.costUsd);
  } catch (error) {
    totalCostUsd += getErrorCostUsd(error);
    if (!continueOnError) throw error;
    boundary = {
      serviceId: service.id,
      servicePath: service.rootPath,
      entryPoints: [],
      exitPoints: [],
      errors: [`Boundary detection failed: ${toErrorMessage(error)}`],
    };
  }

  // Step 2: Run standard taint analysis per service (if language is supported)
  let intraServiceFindings: Finding[] = [];
  let taintAnalysisSkipped = false;
  let taintAnalysisSkipReason: string | undefined;

  if (!isTaintAnalysisLanguage(service.language)) {
    taintAnalysisSkipped = true;
    taintAnalysisSkipReason = `Language "${service.language}" not supported by taint analysis`;
  } else {
    try {
      const taintAnalysis = await runTaintAnalysisForService(service, input, context);
      intraServiceFindings = taintAnalysis.findings;
      totalCostUsd += taintAnalysis.costUsd;
    } catch (error) {
      totalCostUsd += getErrorCostUsd(error);
      if (!continueOnError) throw error;
      taintAnalysisSkipped = true;
      taintAnalysisSkipReason = `Taint analysis failed: ${toErrorMessage(error)}`;
    }
  }

  return {
    analysis: {
      service,
      boundary,
      intraServiceFindings,
      taintAnalysisSkipped,
      taintAnalysisSkipReason,
      durationMs: Date.now() - startTime,
    },
    costUsd: totalCostUsd,
  };
}

/**
 * Invokes the standard 3-step taint-analysis pipeline programmatically for a single service.
 *
 * Pattern from taint-analysis-refinement-worker.ts:107-117:
 * Manually construct TaskContext with appropriate upstreamOutputs and call task.run() directly.
 */
async function runTaintAnalysisForService(
  service: ServiceDescriptor,
  input: ScanOpts,
  parentContext: TaskContext,
): Promise<{ findings: Finding[]; costUsd: number }> {
  const serviceRoot = path.resolve(parentContext.repoRoot, service.rootPath);

  // Set up isolated workspace per service
  const crossServiceWorkspace = path.join(
    parentContext.repoRoot,
    ".kuzushi",
    "cross-service",
    service.id,
    "iris",
  );
  await mkdir(crossServiceWorkspace, { recursive: true });

  // Override the workspace dir for this service
  const serviceConfig = {
    ...parentContext.config,
    taskConfig: {
      ...parentContext.config.taskConfig,
      "taint-analysis": {
        ...(parentContext.config.taskConfig["taint-analysis"] ?? {}),
        workspaceDir: crossServiceWorkspace,
      },
    },
  };

  // Step 1: Preflight
  const preflightContext: TaskContext = {
    runId: parentContext.runId,
    projectRoot: parentContext.projectRoot ?? parentContext.repoRoot,
    workRoot: serviceRoot,
    repoRoot: serviceRoot,
    scanPath: serviceRoot,
    repoName: service.id,
    config: serviceConfig,
    runtime: parentContext.runtime,
    bus: parentContext.bus,
    upstreamOutputs: new Map(),
  };

  const preflight = await executeNestedTask(
    taintAnalysisPreflightTask,
    input,
    preflightContext,
    service.id,
  );
  const preflightOutput = preflight.output;

  // Step 2: Label
  const labelContext: TaskContext = {
    ...preflightContext,
    upstreamOutputs: new Map([["taint-analysis-preflight", preflightOutput]]),
  };

  const label = await executeNestedTask(taintAnalysisLabelTask, input, labelContext, service.id);
  const labelOutput = label.output;

  // Step 3: Run (produces Finding[])
  const runContext: TaskContext = {
    ...preflightContext,
    upstreamOutputs: new Map([["taint-analysis-label", labelOutput]]),
  };

  const run = await executeNestedTask(taintAnalysisRunTask, input, runContext, service.id);

  return {
    findings: run.emittedFindings,
    costUsd: preflight.costUsd + label.costUsd + run.costUsd,
  };
}

async function executeNestedTask<TOutput>(
  task: AgentTask<ScanOpts, TOutput>,
  input: ScanOpts,
  context: TaskContext,
  serviceId: string,
): Promise<ExecutedTaskResult & { output: TOutput }> {
  process.stderr.write(
    `[taint-analysis-cross-analyze] [${serviceId}] Starting nested task ${task.id}\n`,
  );

  try {
    const executed = await executeAgentTask(
      task,
      input,
      context,
      resolveTaskConfig(context.config, task.id),
    );

    process.stderr.write(
      `[taint-analysis-cross-analyze] [${serviceId}] Completed nested task ${task.id} in ${executed.durationMs}ms (cost $${executed.costUsd.toFixed(4)})\n`,
    );

    return executed as ExecutedTaskResult & { output: TOutput };
  } catch (error) {
    process.stderr.write(
      `[taint-analysis-cross-analyze] [${serviceId}] Nested task ${task.id} failed: ${toErrorMessage(error)}\n`,
    );
    throw error;
  }
}

function resolveTaskConfig(config: TaskContext["config"], taskId: string): TaskConfig {
  const raw = config.taskConfig[taskId];
  if (isRecord(raw)) {
    return raw;
  }
  return {};
}

function getErrorCostUsd(error: unknown): number {
  if (!isRecord(error)) {
    return 0;
  }

  return normalizeCostUsd(error["costUsd"]);
}

// ── Semaphore ───────────────────────────────────────────────────────────

class Semaphore {
  private available: number;
  private waitQueue: Array<() => void> = [];

  constructor(concurrency: number) {
    this.available = Math.max(1, concurrency);
  }

  async acquire(): Promise<() => void> {
    if (this.available > 0) {
      this.available -= 1;
      return () => this.release();
    }

    return new Promise<() => void>((resolve) => {
      this.waitQueue.push(() => {
        resolve(() => this.release());
      });
    });
  }

  private release(): void {
    const next = this.waitQueue.shift();
    if (next) {
      next(); // Direct handoff — slot transfers without touching available
    } else {
      this.available += 1;
    }
  }
}

export const __crossAnalyzeInternals = {
  analyzeService,
  runTaintAnalysisForService,
  Semaphore,
};
