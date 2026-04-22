/**
 * Test helper around `validateModuleExport` that throws a friendlier
 * `ModuleShapeError` with a parsed list of issues.
 *
 * The loader's `validateModuleExport` asserts a module's shape and throws
 * `ModuleLoadError` (code: `SHAPE_INVALID`) with a multi-line message. That
 * shape is fine for the host loader, but test authors benefit from a helper
 * that exposes the structured issue list as an array property.
 */

import { ModuleLoadError } from "../modules/errors.js";
import { validateModuleExport } from "../modules/loader.js";
import type { CopilotModule } from "../modules/types.js";

/**
 * Error thrown by `expectModuleShape` when the input does not satisfy the
 * `CopilotModule` contract. `issues` is the structured list of violations
 * parsed from the underlying `ModuleLoadError.details.errors` (or
 * reconstructed from the error message when the details bag is absent).
 */
export class ModuleShapeError extends Error {
  readonly issues: string[];
  readonly cause?: unknown;

  constructor(issues: string[], cause?: unknown) {
    const summary = issues.length === 1 ? issues[0] : `${issues.length} shape issues`;
    super(`Module shape invalid: ${summary}\n  ${issues.join("\n  ")}`);
    this.name = "ModuleShapeError";
    this.issues = issues;
    if (cause !== undefined) this.cause = cause;
    Object.setPrototypeOf(this, ModuleShapeError.prototype);
  }
}

/**
 * Assert that `mod` is a well-formed `CopilotModule` — same rules as the
 * host loader enforces at load time (id/displayName/category/version/tools,
 * tool-name prefix + syntax, no duplicates). Throws `ModuleShapeError`
 * with the list of issues on failure.
 *
 * @example
 *   import myModule from "./src/index.js";
 *   expectModuleShape(myModule);     // throws on bad shape
 *   // now safe to assume the loader will accept it
 */
export function expectModuleShape(mod: unknown): asserts mod is CopilotModule {
  try {
    validateModuleExport(mod);
  } catch (error) {
    if (error instanceof ModuleLoadError) {
      const issues = extractIssues(error);
      throw new ModuleShapeError(issues, error);
    }
    // Anything else is unexpected — re-wrap with a single-item issues list
    // so test authors still see the helper-level error type.
    throw new ModuleShapeError([error instanceof Error ? error.message : String(error)], error);
  }
}

function extractIssues(error: ModuleLoadError): string[] {
  const fromDetails = error.details?.errors;
  if (Array.isArray(fromDetails) && fromDetails.every((i) => typeof i === "string")) {
    return fromDetails as string[];
  }
  // Fall back to parsing the multi-line message. Loader emits messages like:
  //   Invalid CopilotModule export:
  //     missing 'id' (string)
  //     tools[0]: missing 'name'
  const lines = error.message.split("\n");
  const body = lines
    .slice(1)
    .map((l) => l.trim())
    .filter(Boolean);
  return body.length > 0 ? body : [error.message];
}
