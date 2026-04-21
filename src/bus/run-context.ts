/**
 * Run context shape shared across bus events and scanner types.
 *
 * Extracted to its own file to break the circular type dependency
 * between bus/events.ts and scanners/types.ts.
 */

export interface RunContext {
  runId: string;
  repoRoot: string;
  scanPath?: string;
  /** Enclosing git toplevel when different from `repoRoot`. Only set when
   * the operator targeted a subdirectory of a larger git repo, and only
   * consumed by the handful of tasks that genuinely need to reach beyond
   * the scan scope (cross-service taint analysis). */
  gitRoot?: string;
  repoName: string;
  dbPath: string;
  postProcessMode?: "full" | "scan-only";
  reportMode?: "full" | "suppress";
}
