import { normalizeTaskCapabilityIds } from "../../capabilities.js";
import { type DagRegistry, normalizeDagIds } from "../../modules/dag-registry.js";
import type { KuzushiConfig } from "../../types.js";

const THREAT_AWARE_DETECTOR_TASK_IDS = new Set([
  "context:code-config-detect",
  "agentic-sast:ssrf-detect",
  "agentic-sast:nosql-injection-detect",
  "agentic-sast:prototype-pollution-detect",
  "agentic-sast:template-injection-detect",
  "agentic-sast:graphql-security-detect",
  "agentic-sast:race-condition-detect",
  "agentic-sast:command-injection-detect",
  "agentic-sast:xxe-detect",
  "agentic-sast:deserialization-detect",
  "agentic-sast:supply-chain-detect",
  "agentic-sast:auth-logic-detect",
  "threat-model:threat-scenario-build",
]);

const THREAT_MODEL_TASK_ID = "threat-model:threat-model-randori";
const CONTEXT_GATHERER_ID = "context:context-gatherer";
const CONTEXT_ENRICHER_ID = "context:context-enricher";
const TASK_SELECTOR_ID = "pipeline:task-selector";

export interface InitialTaskPlan {
  baseTaskIds: string[];
  candidateIds: string[];
  enabledTaskIds: string[];
  disabledTaskIds: string[];
  dynamicSelectionActive: boolean;
  useAllTasks: boolean;
  contextGatheringForced: boolean;
}

export interface TaskPolicyOptions {
  disabledTasks?: readonly string[];
}

export function resolveInitialTaskPlan(
  registry: DagRegistry,
  tasks: string[],
  config: Pick<
    KuzushiConfig,
    "tasks" | "enableContextGathering" | "enableContextEnrichment" | "enableDynamicTaskSelection"
  >,
  options: TaskPolicyOptions = {},
): InitialTaskPlan {
  const disabledTaskIds = normalizeDisabledTaskIds(registry, options.disabledTasks ?? []);
  const disabledSet = new Set(disabledTaskIds);
  const configuredTasksRaw = config.tasks ?? [];
  const configuredTasks = filterDisabledTaskIds(configuredTasksRaw, disabledSet);
  const explicitTasks = filterDisabledTaskIds(tasks, disabledSet);
  const allRegisteredTasks = registry.ids().filter((id) => !disabledSet.has(id));
  const useAllTasks = configuredTasksRaw.length === 1 && configuredTasksRaw[0] === "*";
  const dynamicSelectionActive =
    config.enableDynamicTaskSelection === true && registry.has(TASK_SELECTOR_ID);
  const enableContextExplicit =
    config.enableContextGathering !== false && registry.has(CONTEXT_GATHERER_ID);
  const enableContextEnrichment =
    config.enableContextEnrichment === true && registry.has(CONTEXT_ENRICHER_ID);
  const baseTaskIds = useAllTasks ? allRegisteredTasks : configuredTasks;

  const candidateIds = injectThreatModelPolicyCandidates(registry, [
    ...explicitTasks,
    ...(enableContextExplicit ? [CONTEXT_GATHERER_ID] : []),
    ...(enableContextEnrichment ? [CONTEXT_ENRICHER_ID] : []),
    ...baseTaskIds,
    ...(dynamicSelectionActive ? [TASK_SELECTOR_ID] : []),
  ]).filter((id) => !disabledSet.has(id));

  let enabledTaskIds = collectTransitiveDeps(registry, candidateIds).filter(
    (id) => !disabledSet.has(id),
  );
  let contextGatheringForced = false;

  if (config.enableContextGathering === false) {
    const othersDepend = enabledTaskIds.some(
      (id) =>
        id !== CONTEXT_GATHERER_ID &&
        registry.has(id) &&
        registry.get(id).dependsOn.includes(CONTEXT_GATHERER_ID),
    );

    if (!othersDepend) {
      enabledTaskIds = enabledTaskIds.filter((id) => id !== CONTEXT_GATHERER_ID);
    } else if (dynamicSelectionActive) {
      contextGatheringForced = true;
    }
  }

  return {
    baseTaskIds: normalizeDagIds(baseTaskIds, registry),
    candidateIds,
    enabledTaskIds,
    disabledTaskIds,
    dynamicSelectionActive,
    useAllTasks,
    contextGatheringForced,
  };
}

export function normalizeDisabledTaskIds(
  registry: DagRegistry,
  disabledTasks: readonly string[],
): string[] {
  const raw = disabledTasks
    .map((id) => (id.trim() === "agentic" ? "agentic-sast" : id.trim()))
    .filter((id) => id.length > 0);
  if (raw.length === 0) return [];

  const normalized = normalizeDagIds(normalizeTaskCapabilityIds(raw), registry);
  const unknown = normalized.filter((id) => !registry.has(id));
  if (unknown.length > 0) {
    throw new Error(
      `Unknown disabled task${unknown.length === 1 ? "" : "s"}: ${unknown.join(", ")}`,
    );
  }
  return normalized;
}

export function filterDisabledTaskIds(ids: string[], disabledSet: ReadonlySet<string>): string[] {
  if (disabledSet.size === 0) return normalizeDagIds(ids);
  return normalizeDagIds(ids).filter((id) => !disabledSet.has(id));
}

export function injectThreatModelPolicyCandidates(
  registry: DagRegistry,
  candidateIds: string[],
): string[] {
  const normalized = normalizeDagIds(candidateIds, registry);
  if (
    normalized.some((id) => THREAT_AWARE_DETECTOR_TASK_IDS.has(id)) &&
    registry.has(THREAT_MODEL_TASK_ID)
  ) {
    return normalizeDagIds([...normalized, THREAT_MODEL_TASK_ID], registry);
  }

  return normalized;
}

export function resolveOrderWithPolicyEdges(
  registry: DagRegistry,
  enabledIds: string[],
): string[][] {
  const enabled = dedupeTaskIds(normalizeDagIds(enabledIds, registry));
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

export function collectTransitiveDeps(registry: DagRegistry, candidateIds: string[]): string[] {
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

  return normalizeDagIds([...all], registry);
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
