import type Database from "better-sqlite3";
import { createDefaultTaskRegistry } from "../agents/index.js";
import type { TaskRegistry } from "../agents/registry.js";
import type { ScannerRegistry } from "../scanners/registry.js";
import type { KuzushiConfig } from "../types.js";
import { createBus } from "./adapters/index.js";
import { registerOrchestrator } from "./orchestrator.js";
import type { MessageBus } from "./types.js";
import { registerReportWorker } from "./workers/report-worker.js";
import { registerScanWorker } from "./workers/scan-worker.js";
import { registerStoreWorker } from "./workers/store-worker.js";
import { registerTriageWorker } from "./workers/triage-worker.js";

export interface RegisterWorkersDeps {
  registry: ScannerRegistry;
  taskRegistry?: TaskRegistry;
  db: Database.Database;
  config: KuzushiConfig;
}

/** Register orchestrator + all built-in workers on a bus instance. */
export function registerAllWorkers(bus: MessageBus, deps: RegisterWorkersDeps): void {
  const taskRegistry = deps.taskRegistry ?? createDefaultTaskRegistry(deps.registry);

  registerScanWorker(bus, {
    registry: deps.registry,
    taskRegistry,
    config: deps.config,
  });

  registerTriageWorker(bus, {
    registry: deps.registry,
    taskRegistry,
    config: deps.config,
  });

  registerStoreWorker(bus, {
    db: deps.db,
  });

  registerReportWorker(bus, {
    db: deps.db,
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
export * from "./workers/store-worker.js";
export * from "./workers/report-worker.js";
