import type { KuzushiConfig } from "../types.js";
import { TaskRegistry } from "./registry.js";
import { appModelBuildTask } from "./tasks/app-model-build.js";
import { callGraphAssistTask } from "./tasks/call-graph-assist.js";
import { codeConfigDetectTask } from "./tasks/code-config-detect.js";
import { codeGraphBuildTask } from "./tasks/code-graph/build.js";
import { codeGraphEnrichTask } from "./tasks/code-graph/enrich.js";
import { contextEnricherTask } from "./tasks/context-enricher.js";
import { contextGathererTask } from "./tasks/context-gatherer.js";
import { deepSemanticCweSelectTask } from "./tasks/deep-semantic/cwe-select.js";
import { deepSemanticHuntTask } from "./tasks/deep-semantic/hunt.js";
import { invariantCheckTask } from "./tasks/invariant-analysis/check.js";
import { invariantExtractTask } from "./tasks/invariant-analysis/extract.js";
import { systemsContextGathererTask } from "./tasks/systems-hunt/context.js";
import { systemsHuntTask } from "./tasks/systems-hunt/hunt.js";
import { systemsInvariantExtractTask } from "./tasks/systems-hunt/invariant-extract.js";
import { systemsTriggerSynthTask } from "./tasks/systems-hunt/trigger-synth.js";
import { taintCweSelectTask } from "./tasks/taint-iris/cwe-select.js";
import { taintIrisTask } from "./tasks/taint-iris/iris.js";
import { threatScenarioBuildTask } from "./tasks/threat-scenario-build.js";

/**
 * Create task registry populated with the handful of infrastructure and
 * systems-hunt tasks that are not yet migrated to module-exposed DagTools.
 *
 * Everything else — semgrep, codeql, agentic-sast, all 16 agentic
 * detectors (SSRF, NoSQL, command injection, template injection,
 * deserialization, XXE, prototype-pollution, GraphQL, secrets/crypto,
 * race-condition, auth-logic, sharp-edges, supply-chain, reachability-
 * check, diff-review, crypto-behavioral-test), threat-hunt, threat-model-
 * randori, tob-audit, vuln-scout, taint-iris — is registered through the
 * module registry's DAG bridge (see `src/modules/dag-bridge.ts`).
 *
 * This function seeds the orchestrator's TaskRegistry with the tasks that
 * either (a) have no corresponding module yet (deep-semantic, systems-
 * hunt, invariant-analysis, code-graph) or (b) are purely infrastructure
 * (context-gatherer, context-enricher, app-model-build, call-graph-assist,
 * code-config-detect). The bridge populates the rest when each
 * `CopilotModule` is loaded.
 *
 * Task-registry validation (dependsOn lookups) still runs here, so
 * anything in this file must not depend on module-bridged tasks — those
 * aren't registered yet at this point in the bootstrap.
 */
export async function createDefaultTaskRegistry(
  _config?: KuzushiConfig,
  _repoRoot?: string,
): Promise<TaskRegistry> {
  const tasks = new TaskRegistry();

  // ---------- Context / application-model / scenario infrastructure ----------
  tasks.register(contextGathererTask);
  tasks.register(contextEnricherTask);
  tasks.register(appModelBuildTask);
  tasks.register(threatScenarioBuildTask);
  tasks.register(codeConfigDetectTask);

  // ---------- Invariant analysis infrastructure ----------
  tasks.register(invariantExtractTask);
  tasks.register(invariantCheckTask);

  // ---------- Taint-analysis chain (CWE select → IRIS) ----------
  tasks.register(taintCweSelectTask);
  tasks.register(taintIrisTask);

  // ---------- Systems-hunt chain ----------
  tasks.register(systemsContextGathererTask);
  tasks.register(systemsInvariantExtractTask);
  tasks.register(systemsTriggerSynthTask);
  tasks.register(systemsHuntTask);

  // Backward-compatible deep-semantic tasks retained while systems-hunt is the public path.
  // @deprecated deep-semantic-cwe-select and deep-semantic-hunt are superseded by the
  // systems-hunt task chain. The systems-hunt pipeline covers the same memory-safety
  // and low-level vulnerability classes with better invariant extraction and trigger
  // synthesis. These registrations remain so that existing configs referencing
  // "deep-semantic-cwe-select" or "deep-semantic-hunt" continue to resolve. Migrate
  // task selections to "systems-hunt" and remove these entries in a future major version.
  tasks.register(deepSemanticCweSelectTask);
  tasks.register(deepSemanticHuntTask);

  // ---------- Call-graph + code-graph enrichment ----------
  tasks.register(callGraphAssistTask);
  tasks.register(codeGraphBuildTask);
  tasks.register(codeGraphEnrichTask);

  // IMPORTANT: Do not call `tasks.validate()` here. Many orchestrator
  // dependencies (threat-model-randori, threat-hunt, agentic-sast detectors,
  // tob-audit, vuln-scout, task-selector, etc.) are registered by the
  // module registry bridge later in the bootstrap. The orchestrator runs
  // validation after modules load.

  return tasks;
}

export * from "./registry.js";
export * from "./types.js";
