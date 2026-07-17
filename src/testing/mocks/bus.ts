/** In-memory MessageBus whose subscribers observe production EventEnvelope values. */

import type {
  AnyEvent,
  EventEnvelope,
  EventHandler,
  EventMeta,
  MessageBus,
} from "../../bus/types.js";

export interface MockMessageBus extends MessageBus {
  /** Every published envelope, including envelopes created by `emit`. */
  readonly published: AnyEvent[];
  /** Back-compatible payload summary for every published envelope. */
  readonly emitted: Array<{ eventType: string; payload: unknown }>;
  /** Payload convenience that creates an envelope before publishing. */
  emit(eventType: string, payload: unknown): Promise<void>;
}

function mockEventMeta(sequence: number): EventMeta {
  return {
    id: `mock-event-${sequence}`,
    timestamp: new Date(sequence).toISOString(),
    runId: "test-run",
  };
}

function addHandler(
  handlers: Map<string, Set<EventHandler>>,
  eventType: string,
  handler: EventHandler,
): void {
  const registered = handlers.get(eventType) ?? new Set<EventHandler>();
  registered.add(handler);
  handlers.set(eventType, registered);
}

function removeHandler(
  handlers: Map<string, Set<EventHandler>>,
  eventType: string,
  handler: EventHandler,
): void {
  const registered = handlers.get(eventType);
  registered?.delete(handler);
  if (registered?.size === 0) handlers.delete(eventType);
}

function waitForEnvelope<E extends AnyEvent>(
  bus: MessageBus,
  eventType: E["type"],
  predicate?: (event: E) => boolean,
  timeoutMs?: number,
): Promise<E> {
  return new Promise<E>((resolve, reject) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const cleanup = () => {
      if (timer !== undefined) clearTimeout(timer);
      bus.unsubscribe(eventType, handler);
    };
    const handler: EventHandler = (event) => {
      try {
        const typed = event as E;
        if (predicate && !predicate(typed)) return;
        cleanup();
        resolve(typed);
      } catch (error) {
        cleanup();
        reject(error);
      }
    };
    bus.subscribe(eventType, handler);
    if (timeoutMs !== undefined) {
      timer = setTimeout(() => {
        cleanup();
        reject(new Error(`MessageBus.waitFor timed out after ${timeoutMs}ms for ${eventType}`));
      }, timeoutMs);
    }
  });
}

/** Build a deterministic recording MessageBus for module tests. */
export function createMockBus(): MockMessageBus {
  const published: AnyEvent[] = [];
  const emitted: Array<{ eventType: string; payload: unknown }> = [];
  const handlers = new Map<string, Set<EventHandler>>();

  const bus: MockMessageBus = {
    published,
    emitted,
    async emit(eventType, payload) {
      const envelope: EventEnvelope = {
        type: eventType,
        meta: mockEventMeta(published.length + 1),
        payload,
      };
      await bus.publish(envelope);
    },
    async publish(event) {
      published.push(event);
      emitted.push({ eventType: event.type, payload: event.payload });
      for (const handler of [...(handlers.get(event.type) ?? [])]) await handler(event);
    },
    subscribe(eventType, handler) {
      addHandler(handlers, eventType, handler as EventHandler);
    },
    unsubscribe(eventType, handler) {
      removeHandler(handlers, eventType, handler);
    },
    waitFor(eventType, predicate, timeoutMs) {
      return waitForEnvelope(bus, eventType, predicate, timeoutMs);
    },
    async close() {
      handlers.clear();
    },
  };
  return bus;
}
