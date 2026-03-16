import type { AgentTask } from "./types.js";
import * as path from "node:path";
import { pathToFileURL } from "node:url";

export interface TaskSpecifier {
  type: "file" | "package";
  path: string;
  exportName?: string;  // for named exports from packages
}

/**
 * Parse a task specifier string into a structured format.
 *
 * Supported formats:
 * - "file://./my-scanner.ts" — local file, default export
 * - "package:my-scanner-plugin" — npm package, default export
 * - "package:my-scanner-plugin:MyTask" — npm package, named export
 */
export function parseTaskSpecifier(specifier: string): TaskSpecifier {
  if (specifier.startsWith("file://")) {
    return { type: "file", path: specifier.slice(7) };
  }
  if (specifier.startsWith("package:")) {
    const parts = specifier.slice(8).split(":");
    return {
      type: "package",
      path: parts[0],
      exportName: parts[1],
    };
  }
  throw new Error(`Invalid task specifier: ${specifier}. Must start with "file://" or "package:"`);
}

/**
 * Load an external task from a specifier.
 */
export async function loadExternalTask(
  spec: TaskSpecifier,
  repoRoot: string,
): Promise<AgentTask> {
  let mod: Record<string, unknown>;

  if (spec.type === "file") {
    const resolved = path.resolve(repoRoot, spec.path);
    const url = pathToFileURL(resolved).href;
    mod = await import(url);
  } else {
    mod = await import(spec.path);
  }

  const task = spec.exportName ? mod[spec.exportName] : (mod.default ?? mod);
  validateLoadedTask(task, `${spec.type}:${spec.path}`);
  return task as AgentTask;
}

/**
 * Validate that a loaded module export conforms to the AgentTask interface.
 */
export function validateLoadedTask(task: unknown, specifier: string): asserts task is AgentTask {
  if (typeof task !== "object" || task === null) {
    throw new Error(`External task from ${specifier} must be an object`);
  }
  const t = task as Record<string, unknown>;
  if (typeof t.id !== "string" || !t.id) {
    throw new Error(`External task from ${specifier} must have a string 'id' property`);
  }
  if (typeof t.displayName !== "string" || !t.displayName) {
    throw new Error(`External task from ${specifier} must have a string 'displayName' property`);
  }
  if (typeof t.run !== "function") {
    throw new Error(`External task from ${specifier} must have a 'run' method`);
  }
  if (typeof t.outputKind !== "string") {
    throw new Error(`External task from ${specifier} must have an 'outputKind' property`);
  }
}

/**
 * Load all external tasks from config specifiers.
 */
export async function loadAllExternalTasks(
  specifiers: string[],
  repoRoot: string,
): Promise<AgentTask[]> {
  const tasks: AgentTask[] = [];
  for (const specifier of specifiers) {
    const spec = parseTaskSpecifier(specifier);
    const task = await loadExternalTask(spec, repoRoot);
    tasks.push(task);
  }
  return tasks;
}
