import { mkdir } from "node:fs/promises";
import path from "node:path";
import type { Finding } from "../../../../scanners/types.js";
import type { ScanOpts } from "../../../../types.js";
import { toErrorMessage } from "../../../../utils.js";
import type { AgentTask, TaskContext } from "../../../types.js";
import { taintAnalysisPreflightTask } from "../preflight.js";
import { taintAnalysisLabelTask } from "../label.js";
import { taintAnalysisRunTask } from "../analyze.js";
import { resolveTaintAnalysisConfig } from "../types.js";
import { detectServiceBoundaries } from "./boundary-agent.js";
import {
  isTaintAnalysisLanguage,
  resolveCrossServiceConfig,
  type BoundaryManifest,
  type CrossServiceAnalysisOutput,
  type CrossServiceDiscoverOutput,
  type PerServiceAnalysis,
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
  async run(input, context): Promise<CrossServiceAnalysisOutput> {
    const cfg = resolveTaintAnalysisConfig(context.config);
    const crossCfg = resolveCrossServiceConfig(cfg);

    const discoverOutput = context.upstreamOutputs.get("taint-analysis-discover") as
      | CrossServiceDiscoverOutput
      | undefined;
    if (!discoverOutput) {
      throw new Error("taint-analysis-cross-analyze requires upstream output from taint-analysis-discover");
    }

    const services = discoverOutput.services;
    if (services.length === 0) {
      return { services: [], allBoundaries: [] };
    }

    // Process services with concurrency control
    const results: PerServiceAnalysis[] = [];
    const allBoundaries: BoundaryManifest[] = [];

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
        results.push(result);
        allBoundaries.push(result.boundary);
      } catch (error) {
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

    return { services: results, allBoundaries };
  },
};

// ── Per-Service Analysis ────────────────────────────────────────────────

async function analyzeService(
  service: ServiceDescriptor,
  input: ScanOpts,
  context: TaskContext,
  boundaryModel: string,
  boundaryThreshold: number,
  continueOnError: boolean,
): Promise<PerServiceAnalysis> {
  const startTime = Date.now();

  // Step 1: Run boundary detection
  let boundary: BoundaryManifest;
  try {
    boundary = await detectServiceBoundaries({
      service,
      repoRoot: context.repoRoot,
      model: boundaryModel,
      confidenceThreshold: boundaryThreshold,
    });
  } catch (error) {
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
      intraServiceFindings = await runTaintAnalysisForService(service, input, context);
    } catch (error) {
      if (!continueOnError) throw error;
      taintAnalysisSkipped = true;
      taintAnalysisSkipReason = `Taint analysis failed: ${toErrorMessage(error)}`;
    }
  }

  return {
    service,
    boundary,
    intraServiceFindings,
    taintAnalysisSkipped,
    taintAnalysisSkipReason,
    durationMs: Date.now() - startTime,
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
): Promise<Finding[]> {
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
    scannerConfig: {
      ...parentContext.config.scannerConfig,
      "taint-analysis": {
        ...(parentContext.config.scannerConfig["taint-analysis"] ?? {}),
        workspaceDir: crossServiceWorkspace,
      },
    },
  };

  // Step 1: Preflight
  const preflightContext: TaskContext = {
    runId: parentContext.runId,
    repoRoot: serviceRoot,
    scanPath: serviceRoot,
    repoName: service.id,
    config: serviceConfig,
    bus: parentContext.bus,
    upstreamOutputs: new Map(),
  };

  const preflightOutput = await taintAnalysisPreflightTask.run(input, preflightContext);

  // Step 2: Label
  const labelContext: TaskContext = {
    ...preflightContext,
    upstreamOutputs: new Map([["taint-analysis-preflight", preflightOutput]]),
  };

  const labelOutput = await taintAnalysisLabelTask.run(input, labelContext);

  // Step 3: Run (produces Finding[])
  const runContext: TaskContext = {
    ...preflightContext,
    upstreamOutputs: new Map([["taint-analysis-label", labelOutput]]),
  };

  return await taintAnalysisRunTask.run(input, runContext);
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
