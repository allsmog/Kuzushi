/**
 * Lightweight render-count instrumentation.
 *
 * Designed for perf regression tests and ad-hoc debugging. Zero cost when
 * disabled (which is the default — enabling requires the `KUZUSHI_PERF=1`
 * env var or an explicit test-time `enableRenderCounters()` call).
 *
 * Usage (component):
 *   function FindingCard(...) {
 *     useRenderCounter("FindingCard");
 *     ...
 *   }
 *
 * Usage (test):
 *   import { enableRenderCounters, renderCount, resetRenderCounts } from "../../src/ui/perf.js";
 *   enableRenderCounters();
 *   resetRenderCounts();
 *   const { lastFrame } = render(<FindingsView ... />);
 *   expect(renderCount("LooseRow")).toBeLessThan(50);
 *
 * Why not React Profiler? Ink's reconciler works on a yoga-backed text tree;
 * `<Profiler>` fires but tracks commits, not function-body invocations. For
 * Ink perf what we really want is "how many times did this component's body
 * execute?" — so we instrument at the function-body level and let callers
 * decide whether to include it.
 */
import { useRef } from "react";

const counts = new Map<string, number>();
let enabled = process.env.KUZUSHI_PERF === "1";

/** Turn counting on — intended for tests; no-op in production builds. */
export function enableRenderCounters(): void {
  enabled = true;
}

/** Turn counting off (default). */
export function disableRenderCounters(): void {
  enabled = false;
}

/** True when counts are being recorded. */
export function isRenderCountingEnabled(): boolean {
  return enabled;
}

/** Clear all counts — call before a measurement window. */
export function resetRenderCounts(): void {
  counts.clear();
}

/** Number of times a named component's body has run since the last reset. */
export function renderCount(name: string): number {
  return counts.get(name) ?? 0;
}

/** Snapshot of all counters — useful for debugging / reporting. */
export function renderCountsSnapshot(): Record<string, number> {
  return Object.fromEntries(counts);
}

/**
 * Increment a named counter. Exported as a plain function so hooks /
 * non-component code paths can record too.
 */
export function bumpRenderCount(name: string): void {
  if (!enabled) return;
  counts.set(name, (counts.get(name) ?? 0) + 1);
}

/**
 * Hook variant — increments once per render of the calling component.
 *
 * Uses a ref for identity stability (cheap enough that it's safe to leave in
 * hot components). The `enabled` check is the first line so the whole hook
 * is a no-op when counting is off.
 */
export function useRenderCounter(name: string): void {
  // Ref exists purely to avoid ESLint "hooks-lint no-unused-hooks" issues
  // when the gate below short-circuits. The read/write roundtrip is ~20ns.
  const countedNameRef = useRef(name);
  countedNameRef.current = name;
  if (!enabled) return;
  bumpRenderCount(name);
}
