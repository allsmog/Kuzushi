import { FatalError } from "./errors.js";

/**
 * Runtime assertion that narrows `condition` to truthy.
 *
 * Use instead of `as unknown as T` double-casts when the invariant can be
 * checked at runtime.
 */
export function invariant(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new FatalError(message);
  }
}
