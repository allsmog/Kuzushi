/**
 * Shared types for the codegen system.
 */

export interface Generator {
  /** Stable identifier. Must be a path-safe slug. */
  name: string;
  /** Human-readable one-liner shown during `pnpm codegen`. */
  description: string;
  /**
   * Write every output file under `outDir`. Must be deterministic:
   * same inputs produce byte-identical outputs across runs.
   */
  run(outDir: string): Promise<void>;
}
