import type { AgentTask } from "./types.js";

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

  /** Validate all dependsOn references exist. */
  validate(): void {
    for (const task of this.tasks.values()) {
      for (const dep of task.dependsOn) {
        if (!this.tasks.has(dep)) {
          throw new Error(`Task \"${task.id}\" depends on unknown task \"${dep}\"`);
        }
      }
    }
  }

  /** Resolve execution order as parallel groups. Throws on cycles. */
  resolveOrder(enabledIds: string[]): string[][] {
    const enabled = normalizeTaskIds(enabledIds);
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
          throw new Error(`Task \"${id}\" depends on \"${dep}\" but it is not enabled`);
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
          indegree.set(dependent, (indegree.get(dependent) ?? 1) - 1);
        }
      }
    }

    return groups;
  }
}

export function normalizeTaskIds(ids: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();

  for (const raw of ids) {
    const id = raw.trim();
    if (!id || seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }

  return out;
}
