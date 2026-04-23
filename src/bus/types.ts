export interface EventMeta {
  id: string;
  timestamp: string;
  runId: string;
}

export type EventEnvelope<T extends string = string, P = unknown> = {
  type: T;
  meta: EventMeta;
  payload: P;
};

export type AnyEvent = EventEnvelope<string, unknown>;

/**
 * Shape of a handler registered with the bus. Kept as a structural type
 * (rather than the banned `Function`) so it can key a Map for unsubscribe
 * while still allowing async handlers that return `void | Promise<void>`.
 */
export type EventHandler<E extends AnyEvent = AnyEvent> = (event: E) => void | Promise<void>;

export interface MessageBus {
  /** Publish an event. Transport-specific (emit, XADD, pubsub publish, etc.) */
  publish<E extends AnyEvent>(event: E): Promise<void>;

  /** Subscribe to events of a given type */
  subscribe<E extends AnyEvent>(
    eventType: E["type"],
    handler: (event: E) => Promise<void> | void,
  ): void;

  /** Remove a handler */
  unsubscribe(eventType: string, handler: EventHandler): void;

  /** Wait for a specific event */
  waitFor<E extends AnyEvent>(
    eventType: E["type"],
    predicate?: (event: E) => boolean,
    timeoutMs?: number,
  ): Promise<E>;

  /** Graceful shutdown */
  close(): Promise<void>;
}
