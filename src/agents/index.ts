import { createDefaultRegistry } from "../scanners/index.js";
import type { ScannerRegistry } from "../scanners/registry.js";
import { adaptScannerPlugin } from "./scanner-adapter.js";
import { TaskRegistry } from "./registry.js";
import { augurAnalyzeTask } from "./tasks/augur-analyze.js";
import { augurLabelTask } from "./tasks/augur-label.js";
import { augurPreflightTask } from "./tasks/augur-preflight.js";
import { contextGathererTask } from "./tasks/context-gatherer.js";

/** Create task registry populated with adapted scanner plugins. */
export function createDefaultTaskRegistry(scannerRegistry?: ScannerRegistry): TaskRegistry {
  const tasks = new TaskRegistry();
  const registry = scannerRegistry ?? createDefaultRegistry();

  tasks.register(contextGathererTask);
  tasks.register(augurPreflightTask);
  tasks.register(augurLabelTask);
  tasks.register(augurAnalyzeTask);

  for (const id of registry.ids()) {
    tasks.register(adaptScannerPlugin(registry.get(id)));
  }

  return tasks;
}

export * from "./types.js";
export * from "./registry.js";
export * from "./scanner-adapter.js";
