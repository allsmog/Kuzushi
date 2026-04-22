/**
 * Structured error types for the module loader + lifecycle.
 *
 * `ModuleLoadError` replaces the plain `throw new Error(...)` pattern so
 * programmatic callers can branch on `err.code` instead of pattern-matching
 * on `err.message`. Existing `catch (err: Error)` or `err.message` reads
 * keep working — `ModuleLoadError extends Error`.
 */

/**
 * Discriminator for module load failures. Matches the failure categories
 * surfaced by `src/modules/loader.ts` and the manifest/ID validation that
 * lives in `src/copilot/core.ts`.
 */
export type ModuleLoadErrorCode =
  | "MANIFEST_MISSING"
  | "MANIFEST_INVALID"
  | "REQUIREMENTS_UNMET"
  | "ENTRY_NOT_FOUND"
  | "SHAPE_INVALID"
  | "ID_MISMATCH"
  | "SDK_INCOMPATIBLE"
  | "CONFIG_INVALID";

/**
 * Error thrown by the loader / registry / core when a module fails to load
 * or initialize. `code` is the machine-readable discriminator; `details`
 * carries structured context (path, issues list, tool index, etc.).
 */
export class ModuleLoadError extends Error {
  readonly code: ModuleLoadErrorCode;
  readonly details?: Record<string, unknown>;

  constructor(code: ModuleLoadErrorCode, message: string, details?: Record<string, unknown>) {
    super(message);
    this.name = "ModuleLoadError";
    this.code = code;
    if (details !== undefined) {
      this.details = details;
    }
    // Preserve prototype chain across module boundaries (avoid ES target caveat).
    Object.setPrototypeOf(this, ModuleLoadError.prototype);
  }
}
