/**
 * In-memory implementation of `HostUiHandle` for unit tests.
 *
 * Maintains an opaque `state` bag that `update()` shallow-merges into. Every
 * patch is recorded on `.patches` so tests can assert a tool wrote expected
 * keys without standing up the real Ink `UIStore`.
 */

import type { HostUiHandle, UiStatePatch } from "../../modules/host-handles.js";

export interface MockHostUiHandle extends HostUiHandle {
  /** Every patch observed by `update()`, in order. */
  readonly patches: UiStatePatch[];
  /** Current shallow-merged state. Typed as `Record` for ergonomic reads. */
  readonly state: Record<string, unknown>;
  /** Replace the backing state (for test seed). */
  seed(state: Record<string, unknown>): void;
  /** Drop every recorded patch + reset state to `{}`. */
  clear(): void;
}

/**
 * Build a `HostUiHandle` stub that captures `update()` calls into `.patches`
 * and shallow-merges them into `.state`. Use for tools that render progress
 * through `ctx.uiStore?.update({...})`.
 *
 * @example
 *   const uiStore = createMockUiStore();
 *   await tool.execute(input, createMockToolContext({ uiStore }));
 *   expect(uiStore.patches.some((p) => p.phase === "scanning")).toBe(true);
 */
export function createMockUiStore(initial: Record<string, unknown> = {}): MockHostUiHandle {
  let state: Record<string, unknown> = { ...initial };
  const patches: UiStatePatch[] = [];
  const handle: MockHostUiHandle = {
    patches,
    get state() {
      return state;
    },
    getState() {
      return state;
    },
    update(partial) {
      patches.push(partial);
      state = { ...state, ...partial };
    },
    seed(next) {
      state = { ...next };
    },
    clear() {
      patches.length = 0;
      state = {};
    },
  };
  return handle;
}
