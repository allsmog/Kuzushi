/**
 * React hooks for subscribing to the UIStore.
 */
import { useRef, useSyncExternalStore } from "react";
import { useUiNow } from "./clock.js";
import { useTerminalSize } from "./hooks/useTerminalSize.js";
import type { Phase, UIState, UIStore } from "./state.js";
import { clampTerminalCardWidth } from "./terminal.js";

/**
 * Subscribe to the full UIState — triggers re-render on any store change.
 */
export function useUIState(store: UIStore): UIState {
  return useSyncExternalStore(
    (callback) => store.subscribe(callback),
    () => store.getState(),
  );
}

/**
 * Subscribe to just the current phase.
 */
export function usePhase(store: UIStore): Phase {
  return useSyncExternalStore(
    (callback) => store.subscribe(callback),
    () => store.getState().phase,
  );
}

/**
 * Subscribe to a narrow slice of UIState.
 *
 * Unlike `useUIState` (which re-renders on any store mutation), this hook
 * only re-renders when the selector's return value actually changes per the
 * provided equality function (default `Object.is`).
 *
 * For object slices, pass `shallowEqual` to avoid re-renders when the object
 * reference changes but its fields haven't.
 *
 * Caching the selected value in a ref avoids tearing between subscribe /
 * getSnapshot calls within a single render.
 */
export function useUISelector<T>(
  store: UIStore,
  selector: (state: UIState) => T,
  equalityFn: (a: T, b: T) => boolean = Object.is,
): T {
  const cacheRef = useRef<{ state: UIState; value: T } | null>(null);

  const getSnapshot = (): T => {
    const state = store.getState();
    const cache = cacheRef.current;
    if (cache && cache.state === state) {
      return cache.value;
    }
    const next = selector(state);
    if (cache && equalityFn(cache.value, next)) {
      // State reference changed but selected slice didn't — reuse value
      // so useSyncExternalStore sees referential equality and skips render.
      cacheRef.current = { state, value: cache.value };
      return cache.value;
    }
    cacheRef.current = { state, value: next };
    return next;
  };

  return useSyncExternalStore((callback) => store.subscribe(callback), getSnapshot);
}

/**
 * Shallow-equal helper suitable for selector slices — works on objects,
 * arrays, and nullable values. Falls back to `Object.is` for non-object
 * values and references that can't be iterated.
 */
export function shallowEqual<T>(a: T, b: T): boolean {
  if (Object.is(a, b)) return true;
  if (a == null || b == null) return false;
  if (typeof a !== "object" || typeof b !== "object") return false;

  // Arrays: same length + same elements (Object.is per position).
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (!Object.is(a[i], b[i])) return false;
    }
    return true;
  }
  if (Array.isArray(a) !== Array.isArray(b)) return false;

  // Plain objects: same keys + same per-key values.
  const ao = a as Record<string, unknown>;
  const bo = b as Record<string, unknown>;
  const ak = Object.keys(ao);
  const bk = Object.keys(bo);
  if (ak.length !== bk.length) return false;
  for (const k of ak) {
    if (!Object.is(ao[k], bo[k])) return false;
  }
  return true;
}

/**
 * Live elapsed-ms since `startedAt`. Re-renders at `tickMs` cadence
 * (default 1s) and cleans up when the component unmounts or `startedAt`
 * becomes null.
 *
 * Isolates elapsed-time re-renders to the component that uses it, so a
 * 1s footer tick doesn't re-render the rest of the UI.
 */
export function useElapsed(startedAt: number | undefined, tickMs = 1000): number {
  const now = useUiNow(startedAt != null ? tickMs : null);
  return startedAt != null ? Math.max(0, now - startedAt) : 0;
}

/**
 * Live terminal width in columns — SIGWINCH-driven via `useTerminalSize`.
 *
 * Convenience wrapper for components that only care about the horizontal
 * axis (tables, header rails, findings rows). Non-TTY fallback is 80.
 *
 * Use alongside the accessibility helpers to classify:
 *   - `< 60`  → hide chrome, stack cells vertically
 *   - `< 80`  → shorten labels, drop optional columns
 *   - `>= 80` → full layout
 *
 * Example:
 *   const width = useTerminalWidth();
 *   const narrow = width < 80;
 *   const rowWidth = Math.min(width - 4, 88);
 */
export function useTerminalWidth(): number {
  return useTerminalSize().columns;
}

export function useTerminalCardWidth(maxWidth = 88, minWidth = 56): number {
  return clampTerminalCardWidth(useTerminalWidth(), maxWidth, minWidth);
}

/**
 * Thresholds for narrow-terminal handling. Use `classifyTerminalWidth` to
 * pick a layout bucket rather than hard-coding `< 80` all over the codebase.
 */
export type TerminalWidthClass = "tiny" | "narrow" | "standard" | "wide";

/**
 * Classify a terminal width into a named bucket for layout decisions.
 *
 *   tiny     < 60 — stack vertically, glyph + label only
 *   narrow   < 80 — single-line, abbreviated labels
 *   standard < 120 — full layout, default
 *   wide     >= 120 — may enable optional detail columns
 */
export function classifyTerminalWidth(columns: number): TerminalWidthClass {
  if (columns < 60) return "tiny";
  if (columns < 80) return "narrow";
  if (columns < 120) return "standard";
  return "wide";
}

/** Minimum shape `useHeartbeat` needs — compatible with `SubTask`, stage entries,
 *  or any future task list that tracks start/last-event timestamps. */
interface HeartbeatTask {
  startedAt?: number;
  lastEventAt?: number;
  status: string;
}

/**
 * Re-render-driving hook for "still working" heartbeats on long-running tasks.
 *
 * While the task is `active`, ticks a local counter every 5s so elapsed-time
 * displays stay current, and exposes an `isStale` flag that flips true once
 * the task has been silent (no `lastEventAt` update) for `staleSeconds`.
 *
 * Returns `elapsedMs` computed from `startedAt` (or 0 if not started). Pair
 * with `formatDuration()` at the call site.
 */
export function useHeartbeat(
  task: HeartbeatTask,
  staleSeconds = 15,
): { isStale: boolean; elapsedMs: number } {
  const isActive = task.status === "active";
  const now = useUiNow(isActive ? 5000 : null);
  const elapsedMs = task.startedAt ? now - task.startedAt : 0;
  const isStale =
    isActive &&
    task.startedAt != null &&
    (!task.lastEventAt || now - task.lastEventAt > staleSeconds * 1000);

  return { isStale, elapsedMs };
}
