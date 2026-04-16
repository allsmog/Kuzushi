/**
 * Shared helpers for generators.
 */

/**
 * Deterministically format a value as JSON. Uses 2-space indent, sorts
 * object keys, and ends with a single trailing newline so files work
 * cleanly with `git diff` and POSIX tooling.
 */
export function formatJson(value: unknown): string {
  const sorted = sortKeys(value);
  return `${JSON.stringify(sorted, null, 2)}\n`;
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeys);
  }
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    );
    const out: Record<string, unknown> = {};
    for (const [k, v] of entries) {
      out[k] = sortKeys(v);
    }
    return out;
  }
  return value;
}
