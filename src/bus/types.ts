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

export interface MessageBus {
  /** Publish an event. Transport-specific (emit, XADD, pubsub publish, etc.) */
  publish<E extends AnyEvent>(event: E): Promise<void>;

  /** Subscribe to events of a given type */
  subscribe<E extends AnyEvent>(
    eventType: E["type"],
    handler: (event: E) => Promise<void> | void,
  ): void;

  /** Remove a handler */
  unsubscribe(eventType: string, handler: Function): void;

  /** Wait for a specific event */
  waitFor<E extends AnyEvent>(
    eventType: E["type"],
    predicate?: (event: E) => boolean,
    timeoutMs?: number,
  ): Promise<E>;

  /** Graceful shutdown */
  close(): Promise<void>;
}
