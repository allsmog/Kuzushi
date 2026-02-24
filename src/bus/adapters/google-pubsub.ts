import type { AnyEvent, MessageBus } from "../types.js";

/**
 * Placeholder Google Pub/Sub adapter.
 * Implement this class to provide production Pub/Sub transport.
 */
export class GooglePubSubBus implements MessageBus {
  constructor() {
    throw new Error(
      "busBackend=google-pubsub is not available in this build. "
      + "Add a Google Pub/Sub MessageBus adapter implementation before enabling it.",
    );
  }

  async publish<E extends AnyEvent>(_event: E): Promise<void> {
    throw new Error("GooglePubSubBus.publish is not implemented");
  }

  subscribe<E extends AnyEvent>(
    _eventType: E["type"],
    _handler: (event: E) => Promise<void> | void,
  ): void {
    throw new Error("GooglePubSubBus.subscribe is not implemented");
  }

  unsubscribe(_eventType: string, _handler: Function): void {
    throw new Error("GooglePubSubBus.unsubscribe is not implemented");
  }

  async waitFor<E extends AnyEvent>(
    _eventType: E["type"],
    _predicate?: (event: E) => boolean,
    _timeoutMs?: number,
  ): Promise<E> {
    throw new Error("GooglePubSubBus.waitFor is not implemented");
  }

  async close(): Promise<void> {
    throw new Error("GooglePubSubBus.close is not implemented");
  }
}
