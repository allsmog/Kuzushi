/**
 * Module loading utilities — validates manifests, checks requirements,
 * and dynamically imports CopilotModule entry points.
 *
 * All load-time failures surface as `ModuleLoadError` with a machine-readable
 * `code` so callers can programmatically distinguish "manifest missing" from
 * "entry not found" without string-matching.
 */

import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { ModuleLoadError } from "./errors.js";
import { zModuleManifest } from "./schema.js";
import type { CopilotModule, ModuleManifest } from "./types.js";

/**
 * Load and validate a module manifest from a directory.
 * Looks for `module.manifest.json` in the given path.
 */
export function loadManifestFromPath(dirPath: string): ModuleManifest {
  const manifestPath = path.join(dirPath, "module.manifest.json");
  if (!existsSync(manifestPath)) {
    throw new ModuleLoadError(
      "MANIFEST_MISSING",
      `No module.manifest.json found in "${dirPath}". ` +
        `Kuzushi modules must include a manifest file.`,
      { path: dirPath },
    );
  }

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(manifestPath, "utf-8")) as unknown;
  } catch (err) {
    throw new ModuleLoadError(
      "MANIFEST_INVALID",
      `Failed to parse module manifest at ${manifestPath}: ${err instanceof Error ? err.message : String(err)}`,
      { path: manifestPath, cause: err instanceof Error ? err.message : String(err) },
    );
  }
  const manifest = validateManifest(raw, manifestPath);
  checkSdkCompatibility(manifest, manifestPath);
  return manifest;
}

/**
 * Validate a raw parsed manifest object via the Zod schema.
 * Returns a typed ModuleManifest or throws `ModuleLoadError` on failure.
 */
export function validateManifest(raw: unknown, source?: string): ModuleManifest {
  const parsed = zModuleManifest.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => ({
      path: i.path.join("."),
      message: i.message,
    }));
    const summary = issues.map((i) => `${i.path || "<root>"}: ${i.message}`).join("\n  ");
    throw new ModuleLoadError(
      "MANIFEST_INVALID",
      `Invalid module manifest${source ? ` at ${source}` : ""}:\n  ${summary}`,
      { source, issues },
    );
  }

  const obj = parsed.data as Record<string, unknown> & ModuleManifest;
  const result: ModuleManifest = {
    id: obj.id,
    displayName: obj.displayName,
    version: obj.version,
    entry: obj.entry,
    category: obj.category,
    description: typeof obj.description === "string" ? obj.description : "",
  };
  if (obj.requires) result.requires = obj.requires;
  if (obj.configSchema) result.configSchema = obj.configSchema;
  if (obj.author) result.author = obj.author;
  if (obj.license) result.license = obj.license;
  if (obj.kuzushiSdkVersion) result.kuzushiSdkVersion = obj.kuzushiSdkVersion;
  return result;
}

/**
 * Warn (don't throw) when the manifest's declared `kuzushiSdkVersion` is
 * absent or major-incompatible with the host `kuzushi` package version.
 * A warning-only strategy keeps the first release of SDK-versioning
 * backward-compatible — older manifests still load.
 */
function checkSdkCompatibility(manifest: ModuleManifest, source: string): void {
  const hostVersion = readHostKuzushiVersion();
  if (!hostVersion) return; // can't compare; stay silent

  if (!manifest.kuzushiSdkVersion) {
    emitWarn(
      `Module "${manifest.id}" manifest (${source}) omits kuzushiSdkVersion. ` +
        `Current host is kuzushi@${hostVersion}. Future releases will require this field.`,
    );
    return;
  }

  const mismatch = sdkMajorMismatch(manifest.kuzushiSdkVersion, hostVersion);
  if (mismatch) {
    emitWarn(
      `Module "${manifest.id}" declares kuzushiSdkVersion "${manifest.kuzushiSdkVersion}" ` +
        `but host is kuzushi@${hostVersion} (${mismatch}). Loading anyway — breakage possible.`,
    );
  }
}

function emitWarn(msg: string): void {
  // Keep this lightweight — the host wires a proper UI warning channel
  // separately; the loader itself just needs the author to see the notice.
  // eslint-disable-next-line no-console
  console.warn(`[kuzushi] ${msg}`);
}

/**
 * Return the installed `kuzushi` package version, or undefined if the
 * package.json can't be located (e.g. vendored/worktree checkouts).
 */
export function readHostKuzushiVersion(): string | undefined {
  try {
    const require = createRequire(import.meta.url);
    const pkg = require("../../package.json") as { version?: string };
    return typeof pkg.version === "string" ? pkg.version : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Very light major-version mismatch check. Returns a description of the
 * mismatch ("host major N, module requires M") or null when compatible.
 */
export function sdkMajorMismatch(constraint: string, hostVersion: string): string | null {
  const hostMajor = parseInt(hostVersion.split(".")[0] ?? "", 10);
  if (!Number.isFinite(hostMajor)) return null;

  // Extract the first integer at the start of the constraint (after any
  // leading operators like ^ ~ >= <= >). Handles ">=0.19", "^1.0.0", "1.2.3".
  const match = constraint.match(/(\d+)/);
  if (!match) return null;
  const requiredMajor = parseInt(match[1]!, 10);
  if (!Number.isFinite(requiredMajor)) return null;
  if (requiredMajor === hostMajor) return null;
  return `major host=${hostMajor} vs required=${requiredMajor}`;
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
    throw new ModuleLoadError(
      "ENTRY_NOT_FOUND",
      `Module entry point not found: "${absolutePath}"`,
      { entry: absolutePath },
    );
  }

  const imported = (await import(absolutePath)) as Record<string, unknown>;

  // Check for default export or named module export
  const mod = (imported.default ?? imported.module ?? imported) as unknown;
  validateModuleExport(mod);
  return mod as CopilotModule;
}

/** Regex enforced on `tool.name` — lowercase kebab prefix, colon, action. */
const TOOL_NAME_RE = /^[a-z][a-z0-9-]*:[a-z][a-z0-9_-]*$/;

/**
 * Runtime shape check for CopilotModule interface.
 *
 * Also enforces (at load time) that:
 *   - every tool name matches `<moduleId>:<action>`
 *   - tool names are syntactically valid (`^[a-z][a-z0-9-]*:[a-z][a-z0-9_-]*$`)
 *   - no two tools in the same module share a name
 */
export function validateModuleExport(mod: unknown): asserts mod is CopilotModule {
  if (!mod || typeof mod !== "object") {
    throw new ModuleLoadError(
      "SHAPE_INVALID",
      "Module must export an object with CopilotModule shape.",
    );
  }

  const obj = mod as Record<string, unknown>;
  const errors: string[] = [];

  if (typeof obj.id !== "string" || !obj.id) errors.push("missing 'id' (string)");
  if (typeof obj.displayName !== "string") errors.push("missing 'displayName' (string)");
  if (typeof obj.category !== "string") errors.push("missing 'category' (string)");
  if (typeof obj.version !== "string") errors.push("missing 'version' (string)");
  if (!Array.isArray(obj.tools)) errors.push("missing 'tools' (array)");

  const moduleId = typeof obj.id === "string" ? obj.id : "";

  if (Array.isArray(obj.tools)) {
    const seenNames = new Set<string>();
    for (let i = 0; i < obj.tools.length; i++) {
      const tool = obj.tools[i] as Record<string, unknown> | undefined;
      if (!tool || typeof tool !== "object") {
        errors.push(`tools[${i}]: expected an object`);
        continue;
      }
      if (typeof tool.name !== "string") {
        errors.push(`tools[${i}]: missing 'name'`);
      } else {
        if (!TOOL_NAME_RE.test(tool.name)) {
          errors.push(
            `tools[${i}].name "${tool.name}": must match ` +
              `^[a-z][a-z0-9-]*:[a-z][a-z0-9_-]*$ (kebab-case module prefix, colon, kebab-case action)`,
          );
        }
        if (moduleId && !tool.name.startsWith(`${moduleId}:`)) {
          errors.push(
            `tools[${i}].name "${tool.name}": must start with "${moduleId}:" (module id prefix)`,
          );
        }
        if (seenNames.has(tool.name)) {
          errors.push(`tools[${i}].name "${tool.name}": duplicate tool name in module`);
        }
        seenNames.add(tool.name);
      }
      if (typeof tool.execute !== "function")
        errors.push(`tools[${i}]: missing 'execute' function`);
    }
  }

  if (errors.length > 0) {
    throw new ModuleLoadError(
      "SHAPE_INVALID",
      `Invalid CopilotModule export:\n  ${errors.join("\n  ")}`,
      { moduleId, errors },
    );
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
