/**
 * ModuleEventBus — lightweight pub/sub for cross-module coordination.
 *
 * Inspired by Metasploit's `framework.events` (see
 * `lib/msf/core/framework.rb` — on_module_run / on_session_open /
 * on_cred_captured). Any module can subscribe to any other module's
 * events without a direct reference; the bus is the coordination plane.
 *
 * Design:
 *   - One root `EventEmitter` per shell/scan lifetime.
 *   - Each module gets a `ModuleEventScope` on load; the scope tracks
 *     the subscriptions it creates so `dispose()` can yank them all.
 *   - Well-known event names are free-form strings, but we recommend
 *     the conventions documented below so producers and consumers line up.
 *
 * Well-known events (producers are the module ids in brackets):
 *   scan:finding          [sast]         new finding stored
 *   triage:result         [triage]       finding triaged
 *   verify:result         [verify]       exploitability verdict
 *   session:open          [blackbox]     new live session
 *   session:close         [blackbox]     session ended
 *   cred:captured         [*]            credential captured
 *   host:discovered       [recon]        new host row
 *   service:discovered    [recon]        new service row
 *   job:complete          [jobs]         background job terminal state
 *   recipe:run            [shell]        recipe invoked by operator
 *
 * Keep handlers fast and non-throwing — a slow handler stalls every
 * other subscriber. Anything expensive should schedule work on the
 * JobManager instead.
 */

import { EventEmitter } from "node:events";

export type EventPayload = unknown;
export type EventHandler = (payload: EventPayload) => void | Promise<void>;

export interface ModuleEventScope {
  /** Emit an event — all scopes (and the root) receive it. */
  emit(type: string, payload?: EventPayload): void;
  /** Subscribe. Returns an unsubscribe closure. */
  on(type: string, handler: EventHandler): () => void;
  /** One-shot subscribe; auto-unsubs after first delivery. */
  once(type: string, handler: EventHandler): () => void;
  /** Tear down every subscription created via this scope. */
  disposeAll(): void;
}

/**
 * Root bus — backed by Node's EventEmitter so we get battle-tested delivery.
 * The scope wrappers are thin and only exist to enforce lifecycle hygiene.
 */
export class ModuleEventBus {
  private readonly emitter = new EventEmitter();

  constructor() {
    // Module handlers can leak if authors forget `disposeAll()`. Raise the
    // cap generously — real leaks still surface as slowness.
    this.emitter.setMaxListeners(100);
  }

  /** Emit on the root — every subscribing scope gets the event. */
  emit(type: string, payload?: EventPayload): void {
    this.emitter.emit(type, payload);
  }

  /**
   * Open a lifecycle-scoped handle for a module. Subscriptions made through
   * the returned scope are torn down by `disposeAll()`.
   */
  scope(moduleId: string): ModuleEventScope {
    const subs: Array<{ type: string; handler: EventHandler }> = [];
    return {
      emit: (type, payload) => this.emitter.emit(type, payload),
      on: (type, handler) => {
        this.emitter.on(type, handler);
        subs.push({ type, handler });
        return () => {
          this.emitter.off(type, handler);
          const idx = subs.findIndex((s) => s.type === type && s.handler === handler);
          if (idx >= 0) subs.splice(idx, 1);
        };
      },
      once: (type, handler) => {
        const wrapped: EventHandler = (payload) => {
          try {
            void handler(payload);
          } finally {
            // `once` self-removes; keep the scope's tracker in sync.
            const idx = subs.findIndex((s) => s.type === type && s.handler === wrapped);
            if (idx >= 0) subs.splice(idx, 1);
          }
        };
        this.emitter.once(type, wrapped);
        subs.push({ type, handler: wrapped });
        return () => {
          this.emitter.off(type, wrapped);
          const idx = subs.findIndex((s) => s.type === type && s.handler === wrapped);
          if (idx >= 0) subs.splice(idx, 1);
        };
      },
      disposeAll: () => {
        for (const { type, handler } of subs.splice(0)) this.emitter.off(type, handler);
        // Touch moduleId so it shows in stack traces when we log teardown.
        void moduleId;
      },
    };
  }

  /** Subscriber count for a given event type (test helper). */
  listenerCount(type: string): number {
    return this.emitter.listenerCount(type);
  }
}
