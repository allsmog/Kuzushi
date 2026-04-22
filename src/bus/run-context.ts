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
  /** True when the pipeline was kicked off from a shell-embedded single-
   * task run (threat-hunt:run, semgrep:scan, ...). Inline runs stay on
   * the current shell view — report-worker must NOT flip `mode` to
   * `"running"`, must NOT build the scan-stage sub-task tree, and must
   * NOT flip to `"summary"` on `report:requested`. The `sast:scan`
   * orchestrator and the `kuzushi scan` CLI leave this undefined. */
  inline?: boolean;
}
