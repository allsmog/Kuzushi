/**
 * Safe JSON serialization utilities with circular reference protection.
 *
 * Prevents `TypeError: Converting circular structure to JSON` when serializing
 * data that may contain back-references (e.g. LLM output, scanner results,
 * event payloads that reference shared objects).
 */

/**
 * JSON.stringify replacement that replaces circular references with the
 * string `"[Circular]"` instead of throwing.
 *
 * Handles edge cases:
 * - Circular / repeated object references -> `"[Circular]"`
 * - BigInt values -> string representation
 * - Functions and symbols are omitted by the native replacer (standard behavior)
 *
 * For simple primitive values the call falls through to the native
 * `JSON.stringify` without allocating a WeakSet (fast path).
 */
export function safeJsonStringify(value: unknown, space?: number): string {
  // Fast path: primitives and null never cause circular reference errors.
  if (value === null || value === undefined || typeof value !== "object") {
    return JSON.stringify(value, bigIntReplacer, space);
  }

  // Track the ancestor chain (not a flat set) so that diamond-shaped
  // references (shared objects reachable from multiple paths) are serialized
  // correctly while true circular references are still caught.
  const ancestors: unknown[] = [];

  // Must be a regular function (not arrow) so `this` refers to the parent
  // object being serialized — JSON.stringify sets `this` for each call.
  const replacer = function (this: unknown, _key: string, val: unknown): unknown {
    if (typeof val === "bigint") {
      return val.toString();
    }

    if (val !== null && typeof val === "object") {
      // Trim ancestors back to the current parent. When JSON.stringify
      // backtracks from a subtree, `this` will be an ancestor that is
      // already in the array, so we truncate everything after it.
      const idx = ancestors.indexOf(this);
      if (idx !== -1) {
        ancestors.length = idx + 1;
      }

      if (ancestors.includes(val)) {
        return "[Circular]";
      }
      ancestors.push(val);
    }

    return val;
  };

  return JSON.stringify(value, replacer, space);
}

/**
 * JSON.parse wrapper that returns a typed fallback instead of throwing on
 * malformed input.
 *
 * - When a `fallback` is provided the function never throws; parse failures
 *   silently return the fallback value.
 * - When no `fallback` is provided the original `SyntaxError` is re-thrown
 *   so callers that expect valid JSON still get a clear error.
 */
export function safeJsonParse<T>(text: string): T;
export function safeJsonParse<T>(text: string, fallback: T): T;
export function safeJsonParse<T>(text: string, ...rest: [] | [T]): T {
  try {
    return JSON.parse(text) as T;
  } catch (error) {
    // `rest.length === 1` distinguishes "caller passed a fallback" (even
    // if that fallback is literally `undefined`) from "caller relied on
    // the single-arg overload and expects us to rethrow". Using `rest`
    // instead of `arguments.length` keeps us out of the non-arrow
    // function's magic `arguments` object (banned by biome).
    if (rest.length === 1) {
      return rest[0] as T;
    }
    throw error;
  }
}

/** Standalone replacer for the primitive fast-path (BigInt only). */
function bigIntReplacer(_key: string, value: unknown): unknown {
  if (typeof value === "bigint") {
    return value.toString();
  }
  return value;
}
