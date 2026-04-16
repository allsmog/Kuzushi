import { lstatSync, realpathSync } from "node:fs";
import * as path from "node:path";
import { pathToFileURL } from "node:url";
import { isPathWithinRoot } from "../utils.js";
import {
  checkRequirements,
  fingerprintTaskCode,
  loadManifestForTaskFile,
  type TaskManifest,
} from "./task-manifest.js";
import type { AgentTask } from "./types.js";

export interface TaskSpecifier {
  type: "file" | "package";
  path: string;
  exportName?: string; // for named exports from packages
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
export async function loadExternalTask(spec: TaskSpecifier, repoRoot: string): Promise<AgentTask> {
  let mod: Record<string, unknown>;

  if (spec.type === "file") {
    const resolved = path.resolve(repoRoot, spec.path);

    // Security: reject path traversal outside repo root
    if (!isPathWithinRoot(repoRoot, resolved)) {
      throw new Error(
        `External task path "${spec.path}" resolves outside repo root. Path traversal is not allowed.`,
      );
    }

    // Security: reject symlinks pointing outside repo root
    try {
      const stats = lstatSync(resolved);
      if (stats.isSymbolicLink()) {
        const realPath = realpathSync(resolved);
        if (!isPathWithinRoot(repoRoot, realPath)) {
          throw new Error(
            `External task "${spec.path}" is a symlink pointing outside repo root. This is not allowed.`,
          );
        }
      }
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
        throw err;
      }
    }

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

/** Result of loading an external task with manifest and fingerprint. */
export interface LoadedTaskInfo {
  task: AgentTask;
  manifest?: TaskManifest;
  fingerprint?: string;
}

/**
 * Load an external task with manifest validation and fingerprinting.
 */
export async function loadExternalTaskWithManifest(
  spec: TaskSpecifier,
  repoRoot: string,
): Promise<LoadedTaskInfo> {
  const task = await loadExternalTask(spec, repoRoot);

  let resolvedPath: string | undefined;
  if (spec.type === "file") {
    resolvedPath = path.resolve(repoRoot, spec.path);
  }

  // Load manifest if available
  let manifest: TaskManifest | undefined;
  if (resolvedPath) {
    const manifestResult = loadManifestForTaskFile(resolvedPath);
    if (manifestResult?.valid && manifestResult.manifest) {
      manifest = manifestResult.manifest;

      // Check requirements and warn
      const reqCheck = checkRequirements(manifest);
      if (!reqCheck.satisfied) {
        const warnings: string[] = [];
        if (reqCheck.missing.env.length > 0) {
          warnings.push(`Missing env: ${reqCheck.missing.env.join(", ")}`);
        }
        if (reqCheck.missing.bins.length > 0) {
          warnings.push(`Missing bins: ${reqCheck.missing.bins.join(", ")}`);
        }
        if (reqCheck.missing.nodeVersion) {
          warnings.push(`Node version: ${reqCheck.missing.nodeVersion}`);
        }
        console.warn(
          `[task-loader] Task "${task.id}" requirements not met: ${warnings.join("; ")}`,
        );
      }
    } else if (manifestResult && !manifestResult.valid) {
      console.warn(
        `[task-loader] Task "${task.id}" has invalid manifest: ${manifestResult.errors?.join(", ")}`,
      );
    }
  }

  // Compute fingerprint for change detection
  const fingerprint = resolvedPath ? fingerprintTaskCode(resolvedPath) : undefined;

  return { task, manifest, fingerprint };
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

/**
 * Load all external tasks with manifest and fingerprint info.
 */
export async function loadAllExternalTasksWithManifest(
  specifiers: string[],
  repoRoot: string,
): Promise<LoadedTaskInfo[]> {
  const results: LoadedTaskInfo[] = [];
  for (const specifier of specifiers) {
    const spec = parseTaskSpecifier(specifier);
    const info = await loadExternalTaskWithManifest(spec, repoRoot);
    results.push(info);
  }
  return results;
}
