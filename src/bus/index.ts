import type Database from "better-sqlite3";
import type { AgentRuntime } from "../agent-runtime/types.js";
import type { TaskRegistry } from "../agents/registry.js";
import { createDefaultKnowledgeRegistry } from "../knowledge/index.js";
import type { ScannerRegistry } from "../scanners/registry.js";
import type { KuzushiConfig } from "../types.js";
import { createBus } from "./adapters/index.js";
import { registerOrchestrator } from "./orchestrator.js";
import type { MessageBus } from "./types.js";
import { registerAuditWorker } from "./workers/audit-worker.js";
import { registerReportWorker } from "./workers/report-worker.js";
import { registerTaintAnalysisArtifactWorker } from "./workers/taint-analysis-artifact-worker.js";
import { registerScanWorker } from "./workers/scan-worker.js";
import { registerStoreWorker } from "./workers/store-worker.js";
import { registerTriageWorker } from "./workers/triage-worker.js";
import { registerPocHarnessWorker } from "./workers/poc-harness-worker.js";
import { registerPocExecutorWorker } from "./workers/poc-executor-worker.js";
import { registerVerificationWorker } from "./workers/verification-worker.js";
import { registerTaintAnalysisRefinementWorker } from "./workers/taint-analysis-refinement-worker.js";
import { registerDynamicAnalysisWorker } from "./workers/dynamic-analysis-worker.js";
import { registerProgressWorker } from "./workers/progress-worker.js";
import { createPocExecutor } from "../poc-executor/index.js";
import { getGlobalLogLevel } from "../logger.js";

export interface RegisterWorkersDeps {
  registry: ScannerRegistry;
  taskRegistry: TaskRegistry;
  db: Database.Database;
  config: KuzushiConfig;
  runtime: AgentRuntime;
}

/** Register orchestrator + all built-in workers on a bus instance. */
export async function registerAllWorkers(bus: MessageBus, deps: RegisterWorkersDeps): Promise<void> {
  const { taskRegistry } = deps;
  const knowledgeRegistry = createDefaultKnowledgeRegistry();

  // Register orchestrator first so workers can reference it for hook resolution
  const orchestrator = registerOrchestrator(bus, {
    registry: deps.registry,
    taskRegistry,
    db: deps.db,
    runtime: deps.runtime,
  });

  registerScanWorker(bus, {
    registry: deps.registry,
    taskRegistry,
    config: deps.config,
    runtime: deps.runtime,
    knowledgeRegistry,
    db: deps.db,
  });

  registerTriageWorker(bus, {
    registry: deps.registry,
    taskRegistry,
    config: deps.config,
    runtime: deps.runtime,
    db: deps.db,
    knowledgeRegistry,
    getRunHooks: (runId) => orchestrator.getRunHooks(runId),
  });

  registerVerificationWorker(bus, {
    config: deps.config,
    runtime: deps.runtime,
    knowledgeRegistry,
    db: deps.db,
  });

  if (deps.config.pocHarness) {
    registerPocHarnessWorker(bus, {
      config: deps.config,
      runtime: deps.runtime,
    });
  }

  if (
    deps.config.pocHarness
    || deps.config.pocExecute === true
    || (deps.config.verifyRefinementMaxIterations ?? 1) > 1
  ) {
    const executor = await createPocExecutor(
      deps.config.pocSandbox ?? "docker",
      deps.config.pocExecTimeoutMs,
    );
    registerPocExecutorWorker(bus, executor);
  }

  registerStoreWorker(bus, {
    db: deps.db,
  });

  registerTaintAnalysisArtifactWorker(bus, {
    db: deps.db,
  });

  registerTaintAnalysisRefinementWorker(bus, {
    db: deps.db,
    registry: deps.registry,
    taskRegistry,
    config: deps.config,
    runtime: deps.runtime,
  });

  if (deps.config.dynamicAnalysisEnabled) {
    registerDynamicAnalysisWorker(bus, {
      config: deps.config,
      runtime: deps.runtime,
      db: deps.db,
    });
  }

  if (deps.config.auditLog) {
    registerAuditWorker(bus, {
      config: deps.config,
    });
  }

  // Register progress worker before report worker so it can signal suppression
  const progressResult = registerProgressWorker(bus, {
    verbose: getGlobalLogLevel() === "debug",
  });

  registerReportWorker(bus, {
    db: deps.db,
    config: deps.config,
    suppressInlineProgress: progressResult.isActive,
  });
}

export { createBus };
export * from "./types.js";
export * from "./events.js";
export * from "./helpers.js";
export * from "./orchestrator.js";
export * from "./adapters/in-process.js";
export * from "./workers/scan-worker.js";
export * from "./workers/triage-worker.js";
export * from "./workers/verification-worker.js";
export * from "./workers/poc-harness-worker.js";
export * from "./workers/store-worker.js";
export * from "./workers/audit-worker.js";
export * from "./workers/report-worker.js";
export * from "./workers/taint-analysis-artifact-worker.js";
export * from "./workers/taint-analysis-refinement-worker.js";
export * from "./workers/dynamic-analysis-worker.js";
export * from "./workers/progress-worker.js";
