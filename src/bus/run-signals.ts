/**
 * Per-runId abort-signal registry.
 *
 * Why this exists: `runPipeline` in `src/cli/commands/scan-pipeline.ts`
 * owns the AbortSignal the shell / tool-dispatcher hands it for the
 * current scan. Workers registered on the bus (scan-worker, triage-worker,
 * etc.) need that signal so they can forward it into `DagRunContext.signal`
 * — otherwise a long-running task (e.g. a carlini-threat-hunt actor on
 * Opus + max thinking) ignores Ctrl+C because its runtime.query never
 * receives an AbortController.
 *
 * The bus can't carry the signal itself (AbortSignal is not serialisable
 * and `in-process` adapters still rebuild envelopes). A module-level Map
 * keyed by runId is the narrowest fix: `runPipeline` registers the signal
 * before publishing `pipeline:start`, workers read it when a `task:start`
 * for that runId arrives, and `runPipeline`'s `finally` clears the entry.
 *
 * All lookups return `undefined` when the signal is absent (runs that
 * never provided a signal, or post-cleanup reads), so callers can
 * gracefully degrade to "no-op abort" rather than crash.
 */

const runSignals = new Map<string, AbortSignal>();

/** Attach an abort signal to a runId so downstream workers can read it. */
export function registerRunSignal(runId: string, signal: AbortSignal): void {
  runSignals.set(runId, signal);
}

/** Look up the abort signal for a runId, if any. */
export function getRunSignal(runId: string): AbortSignal | undefined {
  return runSignals.get(runId);
}

/** Remove the runId entry — call from the pipeline's finally block. */
export function unregisterRunSignal(runId: string): void {
  runSignals.delete(runId);
}

/** Test-only: clear all registered signals. */
export function __clearRunSignalsForTest(): void {
  runSignals.clear();
}
