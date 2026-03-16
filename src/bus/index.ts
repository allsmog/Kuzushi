import type Database from "better-sqlite3";
import { createDefaultTaskRegistry } from "../agents/index.js";
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
import { registerVerificationWorker } from "./workers/verification-worker.js";
import { registerTaintAnalysisRefinementWorker } from "./workers/taint-analysis-refinement-worker.js";

export interface RegisterWorkersDeps {
  registry: ScannerRegistry;
  taskRegistry?: TaskRegistry;
  db: Database.Database;
  config: KuzushiConfig;
}

/** Register orchestrator + all built-in workers on a bus instance. */
export async function registerAllWorkers(bus: MessageBus, deps: RegisterWorkersDeps): Promise<void> {
  const taskRegistry = deps.taskRegistry ?? await createDefaultTaskRegistry(deps.registry);
  const knowledgeRegistry = createDefaultKnowledgeRegistry();

  registerScanWorker(bus, {
    registry: deps.registry,
    taskRegistry,
    config: deps.config,
    knowledgeRegistry,
  });

  registerTriageWorker(bus, {
    registry: deps.registry,
    taskRegistry,
    config: deps.config,
  });

  registerVerificationWorker(bus, {
    config: deps.config,
  });

  if (deps.config.pocHarness) {
    registerPocHarnessWorker(bus, {
      config: deps.config,
    });
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
  });

  if (deps.config.auditLog) {
    registerAuditWorker(bus, {
      config: deps.config,
    });
  }

  registerReportWorker(bus, {
    db: deps.db,
    config: deps.config,
  });

  registerOrchestrator(bus, {
    registry: deps.registry,
    taskRegistry,
    db: deps.db,
  });
}

export { createBus };
export * from "./types.js";
export * from "./events.js";
export * from "./helpers.js";
export * from "./orchestrator.js";
export * from "./adapters/in-process.js";
export * from "./adapters/redis.js";
export * from "./adapters/google-pubsub.js";
export * from "./adapters/nats.js";
export * from "./workers/scan-worker.js";
export * from "./workers/triage-worker.js";
export * from "./workers/verification-worker.js";
export * from "./workers/poc-harness-worker.js";
export * from "./workers/store-worker.js";
export * from "./workers/audit-worker.js";
export * from "./workers/report-worker.js";
export * from "./workers/taint-analysis-artifact-worker.js";
export * from "./workers/taint-analysis-refinement-worker.js";
