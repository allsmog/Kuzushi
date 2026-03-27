import type { PipelineHooks } from "./types.js";
import * as path from "node:path";
import { existsSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { getLogger } from "../logger.js";
import { isPathWithinRoot } from "../utils.js";

const log = getLogger("hooks");

/**
 * Load pipeline hooks from an external JS/TS file.
 *
 * The file must export (default or named) an object conforming to PipelineHooks.
 */
export async function loadHooksFromFile(filePath: string, repoRoot: string): Promise<PipelineHooks> {
  const resolved = path.resolve(repoRoot, filePath);
  if (!isPathWithinRoot(repoRoot, resolved)) {
    throw new Error(`Hooks file path escapes repo root: ${filePath}`);
  }

  if (!existsSync(resolved)) {
    throw new Error(`Hooks file not found: ${resolved}`);
  }

  const url = pathToFileURL(resolved).href;
  const mod = await import(url);
  const hooks = mod.default ?? mod;
  validateHooks(hooks, filePath);
  log.info(`Loaded pipeline hooks from ${filePath}`);
  return hooks;
}

function validateHooks(hooks: unknown, source: string): asserts hooks is PipelineHooks {
  if (typeof hooks !== "object" || hooks === null) {
    throw new Error(`Hooks file ${source} must export an object`);
  }

  const validKeys = new Set(["beforeScan", "afterScan", "beforeTriage", "afterTriage", "afterAll"]);
  for (const key of Object.keys(hooks)) {
    if (!validKeys.has(key)) {
      log.warn(`Unknown hook key "${key}" in ${source} ignored`);
    }
    if (validKeys.has(key) && typeof (hooks as Record<string, unknown>)[key] !== "function") {
      throw new Error(`Hook "${key}" in ${source} must be a function`);
    }
  }
}
