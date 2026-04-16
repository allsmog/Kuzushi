/**
 * React hooks for subscribing to the UIStore.
 */
import { useSyncExternalStore } from "react";
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
