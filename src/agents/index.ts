import { createDefaultRegistry } from "../scanners/index.js";
import type { ScannerRegistry } from "../scanners/registry.js";
import { adaptScannerPlugin } from "./scanner-adapter.js";
import { TaskRegistry } from "./registry.js";

/** Create task registry populated with adapted scanner plugins. */
export function createDefaultTaskRegistry(scannerRegistry?: ScannerRegistry): TaskRegistry {
  const tasks = new TaskRegistry();
  const registry = scannerRegistry ?? createDefaultRegistry();

  for (const id of registry.ids()) {
    tasks.register(adaptScannerPlugin(registry.get(id)));
  }

  return tasks;
}

export * from "./types.js";
export * from "./registry.js";
export * from "./scanner-adapter.js";
