import { createDefaultRegistry } from "../scanners/index.js";
import type { ScannerRegistry } from "../scanners/registry.js";
import type { KuzushiConfig } from "../types.js";
import { adaptScannerPlugin } from "./scanner-adapter.js";
import { TaskRegistry } from "./registry.js";
import { loadAllExternalTasksWithManifest } from "./task-loader.js";
import { withMultiStrategy } from "../strategies/multi-strategy-task.js";
import { createPopulatedRegistry } from "../strategies/init.js";
import { getProfileForTask } from "../strategies/task-profile-map.js";
import type { AgentTask } from "./types.js";
import { taintAnalysisRunTask } from "./tasks/taint-analysis/analyze.js";
import { taintAnalysisCrossAnalyzeTask } from "./tasks/taint-analysis/cross-service/analyze.js";
import { taintAnalysisDiscoverTask } from "./tasks/taint-analysis/cross-service/discover.js";
import { taintAnalysisStitchTask } from "./tasks/taint-analysis/cross-service/stitch.js";
import { taintAnalysisLabelTask } from "./tasks/taint-analysis/label.js";
import { taintAnalysisPreflightTask } from "./tasks/taint-analysis/preflight.js";
import { contextGathererTask } from "./tasks/context-gatherer.js";
import { contextEnricherTask } from "./tasks/context-enricher.js";
import { secretsCryptoDetectTask } from "./tasks/secrets-crypto-detect.js";
import { cryptoBehavioralTestTask } from "./tasks/crypto-behavioral-test.js";
import { codeConfigDetectTask } from "./tasks/code-config-detect.js";
import { raceConditionTask } from "./tasks/race-condition.js";
import { diffReviewTask } from "./tasks/diff-review.js";
import { invariantExtractTask } from "./tasks/invariant-analysis/extract.js";
import { invariantCheckTask } from "./tasks/invariant-analysis/check.js";
import { threatModelStrideTask } from "./tasks/threat-modeling/stride.js";
import { threatModelPastaTask } from "./tasks/threat-modeling/pasta.js";
import { ssrfDetectionTask } from "./tasks/ssrf-detection.js";
import { prototypePollutionTask } from "./tasks/prototype-pollution.js";
import { nosqlInjectionTask } from "./tasks/nosql-injection.js";
import { templateInjectionTask } from "./tasks/template-injection.js";
import { supplyChainTask } from "./tasks/supply-chain.js";
import { graphqlSecurityTask } from "./tasks/graphql-security.js";
import { authLogicDetectTask } from "./tasks/auth-logic-detect.js";
import { taskSelectorTask } from "./tasks/task-selector.js";
import { reachabilityCheckTask } from "./tasks/reachability-check.js";
import { callGraphAssistTask } from "./tasks/call-graph-assist.js";
import { codeGraphBuildTask } from "./tasks/code-graph/build.js";
import { codeGraphEnrichTask } from "./tasks/code-graph/enrich.js";
import { appModelBuildTask } from "./tasks/app-model-build.js";
import { threatScenarioBuildTask } from "./tasks/threat-scenario-build.js";
import { commandInjectionTask } from "./tasks/command-injection.js";
import { xxeDetectionTask } from "./tasks/xxe-detection.js";
import { deserializationDetectionTask } from "./tasks/deserialization-detection.js";

/** Create task registry populated with adapted scanner plugins. */
export async function createDefaultTaskRegistry(
  scannerRegistry?: ScannerRegistry,
  config?: KuzushiConfig,
  repoRoot?: string,
): Promise<TaskRegistry> {
  const tasks = new TaskRegistry();
  const registry = scannerRegistry ?? createDefaultRegistry();

  // Multi-strategy registry — wraps eligible detection tasks with parallel strategy analysis.
  // When multiStrategyMode === "off" (default), the wrapper is a no-op.
  const strategyRegistry = createPopulatedRegistry();
  const wrapTask = <TI, TO>(task: AgentTask<TI, TO>): AgentTask<TI, TO> => {
    const profile = getProfileForTask(task.id);
    return profile ? withMultiStrategy(task, profile, () => strategyRegistry) : task;
  };

  tasks.register(contextGathererTask);
  tasks.register(taintAnalysisPreflightTask);
  tasks.register(taintAnalysisLabelTask);
  tasks.register(taintAnalysisRunTask);
  tasks.register(taintAnalysisDiscoverTask);
  tasks.register(taintAnalysisCrossAnalyzeTask);
  tasks.register(taintAnalysisStitchTask);

  // Merged agentic detection tasks — wrapped with multi-strategy
  tasks.register(wrapTask(secretsCryptoDetectTask));
  tasks.register(cryptoBehavioralTestTask);
  tasks.register(codeConfigDetectTask);

  // Agentic analysis tasks — wrapped with multi-strategy
  tasks.register(wrapTask(raceConditionTask));
  tasks.register(diffReviewTask);

  // LLM context enrichment
  tasks.register(contextEnricherTask);

  // Invariant analysis tasks
  tasks.register(invariantExtractTask);
  tasks.register(invariantCheckTask);

  // Threat modeling tasks
  tasks.register(threatModelStrideTask);
  tasks.register(threatModelPastaTask);

  // Upstream modeling tasks
  tasks.register(appModelBuildTask);
  tasks.register(threatScenarioBuildTask);

  // Additional agentic detection tasks — wrapped with multi-strategy
  tasks.register(wrapTask(ssrfDetectionTask));
  tasks.register(wrapTask(prototypePollutionTask));
  tasks.register(wrapTask(nosqlInjectionTask));
  tasks.register(wrapTask(templateInjectionTask));
  tasks.register(wrapTask(supplyChainTask));
  tasks.register(wrapTask(graphqlSecurityTask));
  tasks.register(wrapTask(commandInjectionTask));
  tasks.register(wrapTask(xxeDetectionTask));
  tasks.register(wrapTask(deserializationDetectionTask));

  // Authorization logic detection
  tasks.register(authLogicDetectTask);

  // Reachability pre-filter
  tasks.register(reachabilityCheckTask);

  // Call-graph evidence enrichment
  tasks.register(callGraphAssistTask);

  // LLM-powered code graph
  tasks.register(codeGraphBuildTask);
  tasks.register(codeGraphEnrichTask);

  // Dynamic task selection
  tasks.register(taskSelectorTask);

  for (const id of registry.ids()) {
    tasks.register(adaptScannerPlugin(registry.get(id)));
  }

  // Load external tasks from config
  if (config?.externalTasks && config.externalTasks.length > 0) {
    if (config.enableExternalTasks) {
      const resolvedRoot = repoRoot ?? process.cwd();
      const loaded = await loadAllExternalTasksWithManifest(config.externalTasks, resolvedRoot);
      for (const info of loaded) {
        tasks.register(info.task);
        if (info.manifest) {
          tasks.setManifest(info.task.id, info.manifest);
        }
      }
    } else {
      console.warn(
        "Warning: externalTasks are configured but enableExternalTasks is not true. "
        + "Set enableExternalTasks to true or pass --enable-external-tasks to load them.",
      );
    }
  }

  tasks.validate();

  return tasks;
}

export * from "./types.js";
export * from "./registry.js";
export * from "./scanner-adapter.js";
