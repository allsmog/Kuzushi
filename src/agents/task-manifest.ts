/**
 * Task manifest format for external task metadata.
 *
 * A task.manifest.json file can be placed adjacent to a task module
 * to declare metadata, version, requirements, and configuration schema.
 */

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { z } from "zod";

/** Output kinds must match TaskOutputKind from agents/types.ts. */
const TaskOutputKindSchema = z.enum(["findings", "threat-model", "verdict", "report", "custom"]);

/** Schema for a task manifest configuration entry. */
const ManifestConfigEntrySchema = z.object({
  type: z.string(),
  default: z.unknown().optional(),
  description: z.string(),
});

/** Zod schema for task manifest validation. */
export const TaskManifestSchema = z.object({
  id: z.string().min(1),
  displayName: z.string().min(1),
  version: z.string().regex(/^\d+\.\d+\.\d+/, "Must be semver format (e.g., 1.0.0)"),
  description: z.string(),
  outputKind: TaskOutputKindSchema,
  dependsOn: z.array(z.string()).default([]),
  requires: z
    .object({
      env: z.array(z.string()).optional(),
      bins: z.array(z.string()).optional(),
      nodeVersion: z.string().optional(),
    })
    .optional(),
  config: z.record(z.string(), ManifestConfigEntrySchema).optional(),
  author: z.string().optional(),
  license: z.string().optional(),
});

export type TaskManifest = z.infer<typeof TaskManifestSchema>;

/** Result of manifest validation. */
export interface ManifestValidationResult {
  valid: boolean;
  manifest?: TaskManifest;
  errors?: string[];
}

/** Result of requirements check. */
export interface RequirementsCheckResult {
  satisfied: boolean;
  missing: {
    env: string[];
    bins: string[];
    nodeVersion?: string;
  };
}

/**
 * Parse and validate a task manifest from a JSON string.
 */
export function parseTaskManifest(json: string): ManifestValidationResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (err) {
    return {
      valid: false,
      errors: [`Invalid JSON: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  const result = TaskManifestSchema.safeParse(parsed);
  if (!result.success) {
    return {
      valid: false,
      errors: result.error.issues.map(
        (issue) => `${issue.path.join(".") || "<root>"}: ${issue.message}`,
      ),
    };
  }

  return { valid: true, manifest: result.data };
}

/**
 * Load a task manifest from a directory.
 *
 * Looks for `task.manifest.json` in the given directory.
 * Returns undefined if the file doesn't exist.
 */
export function loadTaskManifest(taskDir: string): ManifestValidationResult | undefined {
  const manifestPath = path.join(taskDir, "task.manifest.json");
  if (!existsSync(manifestPath)) {
    return undefined;
  }

  const content = readFileSync(manifestPath, "utf-8");
  return parseTaskManifest(content);
}

/**
 * Load a manifest adjacent to a task file path.
 *
 * Given a path like `/path/to/my-task.ts`, looks for
 * `/path/to/task.manifest.json`.
 */
export function loadManifestForTaskFile(
  taskFilePath: string,
): ManifestValidationResult | undefined {
  const dir = path.dirname(taskFilePath);
  return loadTaskManifest(dir);
}

/**
 * Check whether a manifest's requirements are satisfied.
 *
 * Checks:
 * - Required environment variables are set
 * - Required CLI binaries exist on PATH
 * - Node.js version satisfies the constraint (basic major.minor check)
 */
export function checkRequirements(manifest: TaskManifest): RequirementsCheckResult {
  const missing: RequirementsCheckResult["missing"] = {
    env: [],
    bins: [],
  };

  if (manifest.requires?.env) {
    for (const envVar of manifest.requires.env) {
      if (!process.env[envVar]) {
        missing.env.push(envVar);
      }
    }
  }

  if (manifest.requires?.bins) {
    for (const bin of manifest.requires.bins) {
      if (!isBinaryOnPath(bin)) {
        missing.bins.push(bin);
      }
    }
  }

  if (manifest.requires?.nodeVersion) {
    const required = manifest.requires.nodeVersion;
    if (!satisfiesNodeVersion(required)) {
      missing.nodeVersion = `Required: ${required}, Current: ${process.version}`;
    }
  }

  const satisfied = missing.env.length === 0 && missing.bins.length === 0 && !missing.nodeVersion;

  return { satisfied, missing };
}

/**
 * Compute a SHA-256 fingerprint of task code for change detection.
 */
export function fingerprintTaskCode(filePath: string): string | undefined {
  if (!existsSync(filePath)) return undefined;
  const content = readFileSync(filePath);
  return createHash("sha256").update(content).digest("hex");
}

/**
 * Check if a binary exists on the system PATH.
 */
function isBinaryOnPath(bin: string): boolean {
  const { execFileSync } = require("node:child_process");
  try {
    execFileSync("which", [bin], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

/**
 * Basic semver range check for Node.js version.
 * Supports simple patterns: ">=18", ">=20.0.0", "22"
 */
function satisfiesNodeVersion(required: string): boolean {
  const current = process.version.replace(/^v/, "");
  const cleaned = required.replace(/^[>=<^~]+/, "");

  const [reqMajor] = cleaned.split(".").map(Number);
  const [curMajor] = current.split(".").map(Number);

  if (required.startsWith(">=")) {
    return curMajor >= reqMajor;
  }

  // Default: exact major version match
  return curMajor >= reqMajor;
}
