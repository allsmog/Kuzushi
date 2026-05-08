/**
 * Phase 4.2 — context staleness detector.
 *
 * Pure mapping from a list of changed-file paths to the
 * `ContextGenerationSlice`s that would be invalidated. The heuristics here
 * are intentionally coarse — better to over-mark slices stale (and incur a
 * partial rebuild) than to silently run a downstream module against a map
 * that no longer matches the repo.
 *
 * Callers (the shell, the staleness checks) are responsible for computing
 * `gitChangedPaths` (e.g. via `git diff --name-only` since the snapshot's
 * `timestamp`) and feeding it in. This module stays git-free so it's
 * trivially testable from fixtures.
 */

import type { ContextGenerationSlice, ContextSnapshot } from "../ui/state.js";

/** Heuristic file-path globs that flag the `enrichment` slice as stale. */
const ENRICHMENT_PATH_HINTS: ReadonlyArray<RegExp> = [
  /(^|\/)src\/security\//i,
  /(^|\/)middleware\//i,
  /(^|\/)sanitiz/i,
  /(^|\/)auth\//i,
  /(^|\/)guards?\//i,
  /(^|\/)policy\//i,
];

const SOURCE_FILE_RE =
  /\.(ts|tsx|js|jsx|mjs|cjs|py|go|rs|rb|java|kt|kts|scala|cs|php|cpp|cc|c|h|hpp)$/i;

const CONFIG_FILE_RE =
  /(^|\/)(package\.json|pyproject\.toml|Cargo\.toml|go\.mod|pom\.xml|build\.gradle|tsconfig\.json|yarn\.lock|pnpm-lock\.yaml|requirements\.txt|Pipfile|composer\.json)$/i;

/** Source-file change → app-model + repo are stale. */
function isSourceFile(path: string): boolean {
  return SOURCE_FILE_RE.test(path);
}

/** Config-file change → repo is stale (frameworks / languages may have shifted). */
function isConfigFile(path: string): boolean {
  return CONFIG_FILE_RE.test(path);
}

/** Path matches an enrichment heuristic → enrichment slice is stale. */
function touchesEnrichment(path: string): boolean {
  return ENRICHMENT_PATH_HINTS.some((re) => re.test(path));
}

/**
 * Compute the set of `ContextGenerationSlice`s that should be considered
 * stale given the changed-path set. Returns an empty array when nothing
 * needs refreshing.
 *
 * The `"all"` slice is reserved for the case where the snapshot itself is
 * missing or the caller asks for a full rebuild — this function never
 * emits it, callers fall back to it when no snapshot is present.
 */
export function computeStaleSlices(
  snapshot: ContextSnapshot | null | undefined,
  gitChangedPaths: ReadonlyArray<string>,
): ContextGenerationSlice[] {
  if (!snapshot) return [];
  if (gitChangedPaths.length === 0) return [];

  const stale = new Set<ContextGenerationSlice>();
  for (const path of gitChangedPaths) {
    if (!path) continue;
    if (isSourceFile(path)) {
      stale.add("app-model");
      stale.add("repo");
    }
    if (isConfigFile(path)) {
      stale.add("repo");
    }
    if (touchesEnrichment(path)) {
      stale.add("enrichment");
    }
  }

  // Order the result so callers get deterministic output: repo → enrichment
  // → app-model. Mirrors the dependency order of the live `context:build`
  // sub-DAG so partial-refresh consumers can iterate top-down.
  const order: ContextGenerationSlice[] = ["repo", "enrichment", "app-model"];
  return order.filter((slice) => stale.has(slice));
}

/**
 * Roll-up classification used by the status footer. Maps the structured
 * stale-slice list into the simple state field the footer renders.
 */
export type ContextFreshness = "fresh" | "stale" | "missing";

export function classifyContextFreshness(
  snapshot: ContextSnapshot | null | undefined,
  gitChangedPaths: ReadonlyArray<string>,
): ContextFreshness {
  if (!snapshot) return "missing";
  return computeStaleSlices(snapshot, gitChangedPaths).length === 0 ? "fresh" : "stale";
}
