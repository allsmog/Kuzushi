import type { AnyEvent, MessageBus } from "../types.js";

/**
 * Placeholder NATS adapter.
 * Implement this class to provide production NATS transport.
 */
export class NatsBus implements MessageBus {
  constructor() {
    throw new Error(
      "busBackend=nats is not available in this build. "
      + "Add a NATS MessageBus adapter implementation before enabling it.",
    );
  }

  async publish<E extends AnyEvent>(_event: E): Promise<void> {
    throw new Error("NatsBus.publish is not implemented");
  }

  subscribe<E extends AnyEvent>(
    _eventType: E["type"],
    _handler: (event: E) => Promise<void> | void,
  ): void {
    throw new Error("NatsBus.subscribe is not implemented");
  }

  unsubscribe(_eventType: string, _handler: Function): void {
    throw new Error("NatsBus.unsubscribe is not implemented");
  }

  async waitFor<E extends AnyEvent>(
    _eventType: E["type"],
    _predicate?: (event: E) => boolean,
    _timeoutMs?: number,
  ): Promise<E> {
    throw new Error("NatsBus.waitFor is not implemented");
  }

  async close(): Promise<void> {
    throw new Error("NatsBus.close is not implemented");
  }
}
