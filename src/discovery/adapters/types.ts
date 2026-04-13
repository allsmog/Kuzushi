import type { ProductKind } from "../types.js";

export interface RawDiscoveryNode {
  /** Repo-relative path (forward slashes, no trailing slash). */
  path: string;
  name: string;
  language: string;
  buildSystem: string;
  description: string;
  /** Files/signals that triggered detection. */
  evidence: string[];
  /** True for workspace roots, .sln dirs, Bazel workspace roots, etc. */
  isContainer: boolean;
  containerKind?: ProductKind;
  /** Expanded child paths (only meaningful when isContainer is true). */
  childPaths: string[];
}

export interface DiscoveryAdapter {
  /** Human-readable name for diagnostics. */
  readonly id: string;

  /**
   * Scan the repo root and return all nodes this adapter can detect.
   * Must be deterministic, pure filesystem, zero LLM.
   */
  discover(repoRoot: string, maxDepth: number): Promise<RawDiscoveryNode[]>;
}
