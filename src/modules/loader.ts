/**
 * Module loading utilities — validates manifests, checks requirements,
 * and dynamically imports CopilotModule entry points.
 */

import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import type { CopilotModule, ModuleManifest } from "./types.js";

/**
 * Load and validate a module manifest from a directory.
 * Looks for `module.manifest.json` in the given path.
 */
export function loadManifestFromPath(dirPath: string): ModuleManifest {
  const manifestPath = path.join(dirPath, "module.manifest.json");
  if (!existsSync(manifestPath)) {
    throw new Error(
      `No module.manifest.json found in "${dirPath}". ` +
        `Kuzushi modules must include a manifest file.`,
    );
  }

  const raw = JSON.parse(readFileSync(manifestPath, "utf-8")) as unknown;
  return validateManifest(raw, manifestPath);
}

/**
 * Validate a raw parsed manifest object.
 * Returns a typed ModuleManifest or throws with a descriptive error.
 */
export function validateManifest(raw: unknown, source?: string): ModuleManifest {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`Invalid module manifest${source ? ` at ${source}` : ""}: expected an object.`);
  }

  const obj = raw as Record<string, unknown>;
  const errors: string[] = [];

  if (typeof obj.id !== "string" || !obj.id) errors.push("missing or invalid 'id' (string)");
  if (typeof obj.displayName !== "string" || !obj.displayName)
    errors.push("missing or invalid 'displayName' (string)");
  if (typeof obj.version !== "string" || !obj.version)
    errors.push("missing or invalid 'version' (string)");
  if (typeof obj.entry !== "string" || !obj.entry)
    errors.push("missing or invalid 'entry' (string)");

  const validCategories = ["offense", "defense", "governance", "intel"];
  if (typeof obj.category !== "string" || !validCategories.includes(obj.category)) {
    errors.push(`invalid 'category': expected one of ${validCategories.join(", ")}`);
  }

  if (errors.length > 0) {
    throw new Error(
      `Invalid module manifest${source ? ` at ${source}` : ""}:\n  ${errors.join("\n  ")}`,
    );
  }

  return {
    id: obj.id as string,
    displayName: obj.displayName as string,
    version: obj.version as string,
    entry: obj.entry as string,
    category: obj.category as ModuleManifest["category"],
    description: typeof obj.description === "string" ? obj.description : "",
    requires: obj.requires as ModuleManifest["requires"],
    configSchema: obj.configSchema as ModuleManifest["configSchema"],
  };
}

/**
 * Check if module requirements are satisfied.
 * Returns a result with satisfaction status and any missing items.
 */
export function checkRequirements(reqs: NonNullable<ModuleManifest["requires"]>): {
  satisfied: boolean;
  missing: string[];
} {
  const missing: string[] = [];

  if (reqs.env) {
    for (const envVar of reqs.env) {
      if (!process.env[envVar]) {
        missing.push(`env: ${envVar}`);
      }
    }
  }

  if (reqs.nodeVersion) {
    const current = process.versions.node;
    if (!satisfiesVersion(current, reqs.nodeVersion)) {
      missing.push(`node: ${reqs.nodeVersion} (current: ${current})`);
    }
  }

  // Binary checks deferred — would need async which() calls.
  // For now, trust that binaries are documented in the manifest.

  return { satisfied: missing.length === 0, missing };
}

/**
 * Dynamically import a module entry point and validate it exports a CopilotModule.
 */
export async function dynamicImportModule(entryPath: string): Promise<CopilotModule> {
  const absolutePath = path.resolve(entryPath);
  if (!existsSync(absolutePath)) {
    throw new Error(`Module entry point not found: "${absolutePath}"`);
  }

  const imported = (await import(absolutePath)) as Record<string, unknown>;

  // Check for default export or named module export
  const mod = (imported.default ?? imported.module ?? imported) as unknown;
  validateModuleExport(mod);
  return mod as CopilotModule;
}

/**
 * Runtime shape check for CopilotModule interface.
 */
export function validateModuleExport(mod: unknown): asserts mod is CopilotModule {
  if (!mod || typeof mod !== "object") {
    throw new Error("Module must export an object with CopilotModule shape.");
  }

  const obj = mod as Record<string, unknown>;
  const errors: string[] = [];

  if (typeof obj.id !== "string" || !obj.id) errors.push("missing 'id' (string)");
  if (typeof obj.displayName !== "string") errors.push("missing 'displayName' (string)");
  if (typeof obj.category !== "string") errors.push("missing 'category' (string)");
  if (typeof obj.version !== "string") errors.push("missing 'version' (string)");
  if (!Array.isArray(obj.tools)) errors.push("missing 'tools' (array)");

  if (Array.isArray(obj.tools)) {
    for (let i = 0; i < obj.tools.length; i++) {
      const tool = obj.tools[i] as Record<string, unknown> | undefined;
      if (!tool || typeof tool !== "object") {
        errors.push(`tools[${i}]: expected an object`);
        continue;
      }
      if (typeof tool.name !== "string") errors.push(`tools[${i}]: missing 'name'`);
      if (typeof tool.execute !== "function")
        errors.push(`tools[${i}]: missing 'execute' function`);
    }
  }

  if (errors.length > 0) {
    throw new Error(`Invalid CopilotModule export:\n  ${errors.join("\n  ")}`);
  }
}

/** Simple semver major-version check (e.g. ">=22"). */
function satisfiesVersion(current: string, constraint: string): boolean {
  const match = constraint.match(/^>=(\d+)/);
  if (!match) return true;
  const required = parseInt(match[1]!, 10);
  const actual = parseInt(current.split(".")[0]!, 10);
  return actual >= required;
}
