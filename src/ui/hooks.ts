/**
 * React hooks for subscribing to the UIStore.
 */
import { useEffect, useState, useSyncExternalStore } from "react";
import type { Phase, UIState, UIStore } from "./state.js";

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
  const [, setTick] = useState(0);
  const isActive = task.status === "active";

  useEffect(() => {
    if (!isActive) return;
    const id = setInterval(() => setTick((t) => t + 1), 5000);
    return () => clearInterval(id);
  }, [isActive]);

  const now = Date.now();
  const elapsedMs = task.startedAt ? now - task.startedAt : 0;
  const isStale =
    isActive &&
    task.startedAt != null &&
    (!task.lastEventAt || now - task.lastEventAt > staleSeconds * 1000);

  return { isStale, elapsedMs };
}
