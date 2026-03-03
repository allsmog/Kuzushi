import { createDefaultRegistry } from "../scanners/index.js";
import type { ScannerRegistry } from "../scanners/registry.js";
import { adaptScannerPlugin } from "./scanner-adapter.js";
import { TaskRegistry } from "./registry.js";
import { taintAnalysisRunTask } from "./tasks/taint-analysis/analyze.js";
import { taintAnalysisCrossAnalyzeTask } from "./tasks/taint-analysis/cross-service/analyze.js";
import { taintAnalysisDiscoverTask } from "./tasks/taint-analysis/cross-service/discover.js";
import { taintAnalysisStitchTask } from "./tasks/taint-analysis/cross-service/stitch.js";
import { taintAnalysisLabelTask } from "./tasks/taint-analysis/label.js";
import { taintAnalysisPreflightTask } from "./tasks/taint-analysis/preflight.js";
import { contextGathererTask } from "./tasks/context-gatherer.js";
import { cryptoMisuseTask } from "./tasks/crypto-misuse.js";
import { authAccessTask } from "./tasks/auth-access.js";
import { raceConditionTask } from "./tasks/race-condition.js";
import { invariantExtractTask } from "./tasks/invariant-analysis/extract.js";
import { invariantCheckTask } from "./tasks/invariant-analysis/check.js";
import { threatModelStrideTask } from "./tasks/threat-modeling/stride.js";
import { threatModelPastaTask } from "./tasks/threat-modeling/pasta.js";

/** Create task registry populated with adapted scanner plugins. */
export function createDefaultTaskRegistry(scannerRegistry?: ScannerRegistry): TaskRegistry {
  const tasks = new TaskRegistry();
  const registry = scannerRegistry ?? createDefaultRegistry();

  tasks.register(contextGathererTask);
  tasks.register(taintAnalysisPreflightTask);
  tasks.register(taintAnalysisLabelTask);
  tasks.register(taintAnalysisRunTask);
  tasks.register(taintAnalysisDiscoverTask);
  tasks.register(taintAnalysisCrossAnalyzeTask);
  tasks.register(taintAnalysisStitchTask);

  // Agentic analysis tasks
  tasks.register(cryptoMisuseTask);
  tasks.register(authAccessTask);
  tasks.register(raceConditionTask);

  // Invariant analysis tasks
  tasks.register(invariantExtractTask);
  tasks.register(invariantCheckTask);

  // Threat modeling tasks
  tasks.register(threatModelStrideTask);
  tasks.register(threatModelPastaTask);

  for (const id of registry.ids()) {
    tasks.register(adaptScannerPlugin(registry.get(id)));
  }

  return tasks;
}

export * from "./types.js";
export * from "./registry.js";
export * from "./scanner-adapter.js";
