import type { KuzushiConfig, ScanOpts } from "../types.js";
import { TaskRegistry } from "./registry.js";
import { loadAllExternalTasksWithManifest } from "./task-loader.js";
import { withMultiStrategy } from "../strategies/multi-strategy-task.js";
import { createPopulatedRegistry } from "../strategies/init.js";
import { getProfileForTask } from "../strategies/task-profile-map.js";
import type { AgentTask } from "./types.js";
import type { Finding, ScannerPlugin, TaskConfig } from "../scanners/types.js";
import { SemgrepPlugin } from "../scanners/semgrep.js";
import { CodeQLPlugin } from "../scanners/codeql.js";
import { AgenticPlugin } from "../scanners/agentic.js";
import { contextGathererTask } from "./tasks/context-gatherer.js";
import { contextEnricherTask } from "./tasks/context-enricher.js";
import { secretsCryptoDetectTask } from "./tasks/secrets-crypto-detect.js";
import { cryptoBehavioralTestTask } from "./tasks/crypto-behavioral-test.js";
import { codeConfigDetectTask } from "./tasks/code-config-detect.js";
import { raceConditionTask } from "./tasks/race-condition.js";
import { diffReviewTask } from "./tasks/diff-review.js";
import { invariantExtractTask } from "./tasks/invariant-analysis/extract.js";
import { invariantCheckTask } from "./tasks/invariant-analysis/check.js";
import { threatModelRandoriTask } from "./tasks/threat-modeling/randori.js";
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
import { threatHuntTask } from "./tasks/threat-hunt.js";
import { sharpEdgesDetectTask } from "./tasks/sharp-edges-detect.js";
import { tobAuditTask } from "./tasks/tob-audit/tob-audit.js";
import { vulnScoutTask } from "./tasks/vuln-scout/vuln-scout.js";
import { taintCweSelectTask } from "./tasks/taint-iris/cwe-select.js";
import { taintIrisTask } from "./tasks/taint-iris/iris.js";
import { deepSemanticCweSelectTask } from "./tasks/deep-semantic/cwe-select.js";
import { deepSemanticHuntTask } from "./tasks/deep-semantic/hunt.js";
import { systemsContextGathererTask } from "./tasks/systems-hunt/context.js";
import { systemsInvariantExtractTask } from "./tasks/systems-hunt/invariant-extract.js";
import { systemsTriggerSynthTask } from "./tasks/systems-hunt/trigger-synth.js";
import { systemsHuntTask } from "./tasks/systems-hunt/hunt.js";

function createNativeFindingTask(plugin: ScannerPlugin): AgentTask<ScanOpts, Finding[]> {
  let taskConfig: TaskConfig = {};

  const task: AgentTask<ScanOpts, Finding[]> = {
    id: plugin.id,
    displayName: plugin.displayName,
    outputKind: "findings",
    dependsOn: [],
    async init(config: Record<string, unknown>): Promise<void> {
      taskConfig = config;
      if (plugin.init) {
        await plugin.init(config);
      }
    },
    async run(input: ScanOpts, context): Promise<Finding[]> {
      return plugin.scan(
        context.workRoot ?? context.repoRoot,
        input,
        taskConfig,
        context.runtime,
        {
          bus: context.bus,
          taskId: plugin.id,
          runId: context.runId,
          runContext: {
            runId: context.runId,
            repoRoot: context.projectRoot ?? context.repoRoot,
            scanPath: context.scanPath,
            repoName: context.repoName,
            dbPath: context.dbPath ?? "",
          },
        },
      );
    },
  };

  if (typeof plugin.triageAgentConfig === "function") {
    task.triageAgentConfig = (finding, repoName) => plugin.triageAgentConfig!(finding, repoName);
  }

  return task;
}

/** Create task registry populated with native and external tasks. */
export async function createDefaultTaskRegistry(
  config?: KuzushiConfig,
  repoRoot?: string,
): Promise<TaskRegistry> {
  const tasks = new TaskRegistry();

  // Multi-strategy registry — wraps eligible detection tasks with parallel strategy analysis.
  // When multiStrategyMode === "off" (default), the wrapper is a no-op.
  const strategyRegistry = createPopulatedRegistry();
  const wrapTask = <TI, TO>(task: AgentTask<TI, TO>): AgentTask<TI, TO> => {
    const profile = getProfileForTask(task.id);
    return profile ? withMultiStrategy(task, profile, () => strategyRegistry) : task;
  };

  tasks.register(createNativeFindingTask(new SemgrepPlugin()));
  tasks.register(createNativeFindingTask(new CodeQLPlugin()));
  tasks.register(createNativeFindingTask(new AgenticPlugin()));

  tasks.register(contextGathererTask);

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

  // Threat modeling (Randori PASTA plugin)
  tasks.register(threatModelRandoriTask);

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

  // Threat-driven hunt (Carlini-style, one agent per DFD threat actor)
  tasks.register(wrapTask(threatHuntTask));

  // Sharp-edges detection (Trail of Bits, three adversarial personas)
  tasks.register(wrapTask(sharpEdgesDetectTask));

  // Trail of Bits audit (loads ToB security skills plugin)
  tasks.register(wrapTask(tobAuditTask));

  // Vuln Scout pentest (loads vuln-scout whitebox pentesting plugin)
  tasks.register(wrapTask(vulnScoutTask));

  // Authorization logic detection
  tasks.register(authLogicDetectTask);

  // IRIS-style taint analysis (LLM-driven CodeQL)
  tasks.register(taintCweSelectTask);
  tasks.register(taintIrisTask);

  // Systems-code hunt for low-level memory-safety and protocol bugs
  tasks.register(systemsContextGathererTask);
  tasks.register(systemsInvariantExtractTask);
  tasks.register(systemsTriggerSynthTask);
  tasks.register(systemsHuntTask);

  // Backward-compatible deep-semantic tasks retained while systems-hunt is the public path.
  // @deprecated deep-semantic-cwe-select and deep-semantic-hunt are superseded by the
  // systems-hunt task chain (systems-context-gatherer -> systems-invariant-extract ->
  // systems-trigger-synth -> systems-hunt). The systems-hunt pipeline covers the same
  // memory-safety and low-level vulnerability classes with better invariant extraction
  // and trigger synthesis. These registrations remain so that existing configs referencing
  // "deep-semantic-cwe-select" or "deep-semantic-hunt" continue to resolve. Migrate
  // task selections to "systems-hunt" and remove these entries in a future major version.
  tasks.register(deepSemanticCweSelectTask);
  tasks.register(wrapTask(deepSemanticHuntTask));

  // Reachability pre-filter
  tasks.register(reachabilityCheckTask);

  // Call-graph evidence enrichment
  tasks.register(callGraphAssistTask);

  // LLM-powered code graph
  tasks.register(codeGraphBuildTask);
  tasks.register(codeGraphEnrichTask);

  // Dynamic task selection
  tasks.register(taskSelectorTask);

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
