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
  repoName: string;
  dbPath: string;
  postProcessMode?: "full" | "scan-only";
  reportMode?: "full" | "suppress";
}
