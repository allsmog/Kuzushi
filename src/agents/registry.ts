import { normalizeTaskCapabilityIds } from "../capabilities.js";
import type { AgentTask, TaskOutputKind } from "./types.js";

/** Summary info returned by TaskRegistry.list(). */
export interface TaskInfo {
  id: string;
  displayName: string;
  outputKind: TaskOutputKind;
  dependsOn: string[];
}

/** Registry and DAG resolver for generic agent tasks. */
export class TaskRegistry {
  private readonly tasks = new Map<string, AgentTask>();

  register(task: AgentTask): void {
    this.tasks.set(task.id, task);
  }

  get(id: string): AgentTask {
    const task = this.tasks.get(id);
    if (!task) {
      throw new Error(`Unknown task: ${id}`);
    }
    return task;
  }

  has(id: string): boolean {
    return this.tasks.has(id);
  }

  ids(): string[] {
    return [...this.tasks.keys()];
  }

  /** List all registered tasks with their metadata. */
  list(): TaskInfo[] {
    return [...this.tasks.values()].map((task) => ({
      id: task.id,
      displayName: task.displayName,
      outputKind: task.outputKind,
      dependsOn: [...task.dependsOn],
    }));
  }

  /** Validate all dependsOn references exist. */
  validate(): void {
    for (const task of this.tasks.values()) {
      for (const dep of task.dependsOn) {
        if (!this.tasks.has(dep)) {
          throw new Error(`Task "${task.id}" depends on unknown task "${dep}"`);
        }
      }
    }
  }

  /** Resolve execution order as parallel groups. Throws on cycles. */
  resolveOrder(enabledIds: string[]): string[][] {
    const enabled = dedupePreservingRegisteredIds(this, enabledIds);
    if (enabled.length === 0) return [];

    for (const id of enabled) {
      if (!this.has(id)) {
        throw new Error(`Unknown enabled task: ${id}`);
      }
    }

    const enabledSet = new Set(enabled);
    const priority = new Map<string, number>(enabled.map((id, idx) => [id, idx]));
    const indegree = new Map<string, number>();
    const edges = new Map<string, string[]>();

    for (const id of enabled) {
      indegree.set(id, 0);
      edges.set(id, []);
    }

    for (const id of enabled) {
      const task = this.get(id);
      for (const dep of task.dependsOn) {
        if (!this.has(dep)) {
          throw new Error(`Task "${id}" depends on unknown task "${dep}"`);
        }

        if (!enabledSet.has(dep)) {
          throw new Error(`Task "${id}" depends on "${dep}" but it is not enabled`);
        }

        indegree.set(id, (indegree.get(id) ?? 0) + 1);
        const dependents = edges.get(dep);
        if (dependents) {
          dependents.push(id);
        }
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
}

/**
 * Preserve the caller's requested order where possible. When the caller
 * submits ids that aren't registered, they're filtered out silently so
 * resolveOrder can deliver a helpful `Unknown enabled task` error later.
 */
function dedupePreservingRegisteredIds(registry: TaskRegistry, ids: string[]): string[] {
  const seen = new Set<string>();
  const unique: string[] = [];
  for (const id of normalizeTaskCapabilityIds(ids)) {
    if (seen.has(id)) continue;
    seen.add(id);
    if (!registry.has(id)) continue;
    unique.push(id);
  }
  return unique;
}
