/**
 * ScanOpts type definition.
 *
 * Extracted to its own file to break the circular type dependency
 * between types.ts and scanners/types.ts. Uses inline string instead
 * of TaskId to avoid importing back into scanners/types.ts.
 */

/** Options for running a scan. */
export interface ScanOpts {
  severity: string[];
  maxFindings?: number;
  /**
   * Soft cap on raw scanner findings collected during scan stage.
   * Once exceeded, new findings are dropped and a warning is logged.
   * Distinct from `maxFindings` (triage cap). Field-test issue #34.
   */
  maxRawFindings?: number;
  excludePatterns: string[];
  tasks?: string[];
  taskMode?: "auto" | "manual";
  disabledTasks?: string[];
  fresh: boolean;
  /** Git ref to diff against for differential review (e.g. "main", "HEAD~5"). */
  diffBase?: string;
  /** Injected summary of first-pass findings for agentic two-pass review mode. */
  agenticReviewContext?: string;
  /** Additional target directories for tasks (resolved absolute paths). */
  scanPaths?: string[];
}
