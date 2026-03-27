import path from "node:path";

/** True when value is a non-null, non-array object record. */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** True when candidate resolves inside root (or exactly equals it). */
export function isPathWithinRoot(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

/** Normalize unknown errors into a readable message string. */
export function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

/** Normalize USD costs to non-negative finite numbers. */
export function normalizeCostUsd(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    return 0;
  }

  return value;
}
