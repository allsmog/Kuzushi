import { normalizeTaskIds, type TaskRegistry } from "../../agents/registry.js";
import type { KuzushiConfig } from "../../types.js";

const THREAT_AWARE_DETECTOR_TASK_IDS = new Set([
  "code-config-detect",
  "ssrf-detect",
  "nosql-injection-detect",
  "prototype-pollution-detect",
  "template-injection-detect",
  "graphql-security-detect",
  "race-condition-detect",
  "command-injection-detect",
  "xxe-detect",
  "deserialization-detect",
  "supply-chain-detect",
  "auth-logic-detect",
  "threat-scenario-build",
]);

const THREAT_MODEL_TASK_ID = "threat-model-randori";

export interface InitialTaskPlan {
  baseTaskIds: string[];
  candidateIds: string[];
  enabledTaskIds: string[];
  dynamicSelectionActive: boolean;
  useAllTasks: boolean;
  contextGatheringForced: boolean;
}

export function resolveInitialTaskPlan(
  registry: TaskRegistry,
  tasks: string[],
  config: Pick<
    KuzushiConfig,
    "tasks" | "enableContextGathering" | "enableContextEnrichment" | "enableDynamicTaskSelection"
  >,
): InitialTaskPlan {
  const configuredTasks = config.tasks ?? [];
  const allRegisteredTasks = registry.ids();
  const useAllTasks = configuredTasks.length === 1 && configuredTasks[0] === "*";
  const dynamicSelectionActive = config.enableDynamicTaskSelection === true
    && registry.has("task-selector");
  const enableContextExplicit = config.enableContextGathering !== false
    && registry.has("context-gatherer");
  const enableContextEnrichment = config.enableContextEnrichment === true
    && registry.has("context-enricher");
  const baseTaskIds = useAllTasks ? allRegisteredTasks : configuredTasks;

  const candidateIds = injectThreatModelPolicyCandidates(registry, [
    ...tasks,
    ...(enableContextExplicit ? ["context-gatherer"] : []),
    ...(enableContextEnrichment ? ["context-enricher"] : []),
    ...baseTaskIds,
    ...(dynamicSelectionActive ? ["task-selector"] : []),
  ]);

  let enabledTaskIds = collectTransitiveDeps(registry, candidateIds);
  let contextGatheringForced = false;

  if (config.enableContextGathering === false) {
    const othersDepend = enabledTaskIds.some(
      (id) =>
        id !== "context-gatherer"
        && registry.has(id)
        && registry.get(id).dependsOn.includes("context-gatherer"),
    );

    if (!othersDepend) {
      enabledTaskIds = enabledTaskIds.filter((id) => id !== "context-gatherer");
    } else if (dynamicSelectionActive) {
      contextGatheringForced = true;
    }
  }

  return {
    baseTaskIds: normalizeTaskIds(baseTaskIds),
    candidateIds,
    enabledTaskIds,
    dynamicSelectionActive,
    useAllTasks,
    contextGatheringForced,
  };
}

export function injectThreatModelPolicyCandidates(
  registry: TaskRegistry,
  candidateIds: string[],
): string[] {
  const normalized = normalizeTaskIds(candidateIds);
  if (
    normalized.some((id) => THREAT_AWARE_DETECTOR_TASK_IDS.has(id))
    && registry.has(THREAT_MODEL_TASK_ID)
  ) {
    return normalizeTaskIds([...normalized, THREAT_MODEL_TASK_ID]);
  }

  return normalized;
}

export function resolveOrderWithPolicyEdges(
  registry: TaskRegistry,
  enabledIds: string[],
): string[][] {
  const enabled = dedupeTaskIds(normalizeTaskIds(enabledIds));
  if (enabled.length === 0) {
    return [];
  }

  for (const id of enabled) {
    if (!registry.has(id)) {
      throw new Error(`Unknown enabled task: ${id}`);
    }
  }

  const enabledSet = new Set(enabled);
  const priority = new Map<string, number>(enabled.map((id, idx) => [id, idx]));
  const indegree = new Map<string, number>();
  const edges = new Map<string, string[]>();
  const policyDeps = buildThreatModelPolicyDeps(enabled);

  for (const id of enabled) {
    indegree.set(id, 0);
    edges.set(id, []);
  }

  for (const id of enabled) {
    const task = registry.get(id);
    const dependencies = new Set(task.dependsOn);
    for (const dep of policyDeps.get(id) ?? []) {
      dependencies.add(dep);
    }

    for (const dep of dependencies) {
      if (!registry.has(dep)) {
        throw new Error(`Task "${id}" depends on unknown task "${dep}"`);
      }
      if (!enabledSet.has(dep)) {
        throw new Error(`Task "${id}" depends on "${dep}" but it is not enabled`);
      }

      indegree.set(id, (indegree.get(id) ?? 0) + 1);
      edges.get(dep)?.push(id);
    }
  }

  const groups: string[][] = [];
  const processed = new Set<string>();

  while (processed.size < enabled.length) {
    const group = enabled
      .filter((id) => !processed.has(id) && (indegree.get(id) ?? 0) === 0)
      .sort((a, b) => (priority.get(a) ?? 0) - (priority.get(b) ?? 0));

    if (group.length === 0) {
      const stuck = enabled.filter((id) => !processed.has(id));
      throw new Error(`Task dependency cycle detected among: ${stuck.join(", ")}`);
    }

    groups.push(group);

    for (const id of group) {
      processed.add(id);
      for (const dependent of edges.get(id) ?? []) {
        indegree.set(dependent, (indegree.get(dependent) ?? 0) - 1);
      }
    }
  }

  return groups;
}

export function collectTransitiveDeps(registry: TaskRegistry, candidateIds: string[]): string[] {
  const all = new Set(candidateIds);
  const queue = [...candidateIds];

  while (queue.length > 0) {
    const id = queue.pop()!;
    if (!registry.has(id)) {
      continue;
    }

    for (const dep of registry.get(id).dependsOn) {
      if (!all.has(dep) && registry.has(dep)) {
        all.add(dep);
        queue.push(dep);
      }
    }
  }

  return normalizeTaskIds([...all]);
}

function buildThreatModelPolicyDeps(enabledIds: string[]): Map<string, Set<string>> {
  const enabled = new Set(enabledIds);
  const policyDeps = new Map<string, Set<string>>();

  if (!enabled.has(THREAT_MODEL_TASK_ID)) return policyDeps;

  // All threat-aware detectors must wait for the threat model
  for (const detectorId of enabledIds) {
    if (!THREAT_AWARE_DETECTOR_TASK_IDS.has(detectorId)) continue;
    let deps = policyDeps.get(detectorId);
    if (!deps) {
      deps = new Set<string>();
      policyDeps.set(detectorId, deps);
    }
    deps.add(THREAT_MODEL_TASK_ID);
  }

  return policyDeps;
}

function dedupeTaskIds(ids: string[]): string[] {
  const deduped: string[] = [];
  const seen = new Set<string>();
  for (const id of ids) {
    if (!id || seen.has(id)) {
      continue;
    }
    seen.add(id);
    deduped.push(id);
  }
  return deduped;
}
