import type { AnyEvent, MessageBus } from "../types.js";

/**
 * Placeholder Redis Streams adapter.
 * Implement this class to provide production Redis transport.
 */
export class RedisBus implements MessageBus {
  constructor() {
    throw new Error(
      "busBackend=redis is not available in this build. "
      + "Add a Redis MessageBus adapter implementation before enabling it.",
    );
  }

  async publish<E extends AnyEvent>(_event: E): Promise<void> {
    throw new Error("RedisBus.publish is not implemented");
  }

  subscribe<E extends AnyEvent>(
    _eventType: E["type"],
    _handler: (event: E) => Promise<void> | void,
  ): void {
    throw new Error("RedisBus.subscribe is not implemented");
  }

  unsubscribe(_eventType: string, _handler: Function): void {
    throw new Error("RedisBus.unsubscribe is not implemented");
  }

  async waitFor<E extends AnyEvent>(
    _eventType: E["type"],
    _predicate?: (event: E) => boolean,
    _timeoutMs?: number,
  ): Promise<E> {
    throw new Error("RedisBus.waitFor is not implemented");
  }

  async close(): Promise<void> {
    throw new Error("RedisBus.close is not implemented");
  }
}
