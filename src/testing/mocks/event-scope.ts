/**
 * In-memory implementation of `ModuleEventScope` for unit tests.
 *
 * Records every emitted event in `.emitted` and dispatches synchronously to
 * subscribers registered via `on` / `once`. Handler exceptions are swallowed
 * (and surfaced on `.errors`) so a bad handler cannot mask a test assertion.
 */

import type {
  ModuleEventHandler,
  ModuleEventPayload,
  ModuleEventScope,
} from "../../modules/host-handles.js";

export interface MockEventScope extends ModuleEventScope {
  /** Every `emit()` call, in order, for test assertions. */
  readonly emitted: Array<{ event: string; payload: unknown }>;
  /** Errors thrown by subscriber handlers (does not fail emit). */
  readonly errors: Array<{ event: string; error: unknown }>;
  /** Clear recorded emissions + errors without disturbing subscriptions. */
  clear(): void;
}

/**
 * Build a `ModuleEventScope` stub that records emissions and fans them out
 * to `on`/`once` subscribers. Subscriber exceptions are captured on
 * `.errors` rather than propagated.
 *
 * @example
 *   const events = createMockEventScope();
 *   events.on("scan:done", (p) => assert.equal(p, { count: 3 }));
 *   events.emit("scan:done", { count: 3 });
 *   assert.equal(events.emitted.length, 1);
 */
export function createMockEventScope(): MockEventScope {
  const emitted: Array<{ event: string; payload: unknown }> = [];
  const errors: Array<{ event: string; error: unknown }> = [];
  const handlers = new Map<string, Set<ModuleEventHandler>>();
  const onceFlags = new WeakSet<ModuleEventHandler>();

  const addHandler = (event: string, handler: ModuleEventHandler): (() => void) => {
    let set = handlers.get(event);
    if (!set) {
      set = new Set();
      handlers.set(event, set);
    }
    set.add(handler);
    return () => {
      set?.delete(handler);
    };
  };

  const scope: MockEventScope = {
    emitted,
    errors,
    emit(event: string, payload?: ModuleEventPayload): void {
      emitted.push({ event, payload });
      const subs = handlers.get(event);
      if (!subs || subs.size === 0) return;
      // Snapshot so once-handlers can self-remove without mutating the
      // set mid-iteration.
      for (const handler of Array.from(subs)) {
        try {
          const maybe = handler(payload);
          if (maybe && typeof (maybe as Promise<unknown>).then === "function") {
            (maybe as Promise<unknown>).catch((error) => {
              errors.push({ event, error });
            });
          }
        } catch (error) {
          errors.push({ event, error });
        }
        if (onceFlags.has(handler)) {
          subs.delete(handler);
        }
      }
    },
    on(event: string, handler: ModuleEventHandler): () => void {
      return addHandler(event, handler);
    },
    once(event: string, handler: ModuleEventHandler): () => void {
      onceFlags.add(handler);
      return addHandler(event, handler);
    },
    disposeAll(): void {
      handlers.clear();
    },
    clear(): void {
      emitted.length = 0;
      errors.length = 0;
    },
  };
  return scope;
}
