import { randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import type { AnyEvent, EventHandler, MessageBus } from "../types.js";

const DEFAULT_WAIT_TIMEOUT_MS = 12 * 60 * 60 * 1000;
const HANDLER_ERROR_EVENT_TYPE = "bus:handler-error";

type WrappedHandler = (event: AnyEvent) => void;

export class InProcessBus implements MessageBus {
  private readonly emitter = new EventEmitter();
  private readonly handlerMap = new Map<string, Map<EventHandler, WrappedHandler>>();

  constructor() {
    this.emitter.setMaxListeners(50);
  }

  async publish<E extends AnyEvent>(event: E): Promise<void> {
    this.emitter.emit(event.type, event);
  }

  subscribe<E extends AnyEvent>(
    eventType: E["type"],
    handler: (event: E) => Promise<void> | void,
  ): void {
    const key = String(eventType);
    let handlers = this.handlerMap.get(key);

    if (!handlers) {
      handlers = new Map<EventHandler, WrappedHandler>();
      this.handlerMap.set(key, handlers);
    }

    if (handlers.has(handler as EventHandler)) {
      return;
    }

    const wrapped: WrappedHandler = (event) => {
      try {
        const result = handler(event as E);
        if (isPromiseLike(result)) {
          void result.catch((error) => {
            this.emitHandlerError(key, event, error);
          });
        }
      } catch (error) {
        this.emitHandlerError(key, event, error);
      }
    };

    handlers.set(handler as EventHandler, wrapped);
    this.emitter.on(key, wrapped);
  }

  unsubscribe(eventType: string, handler: EventHandler): void {
    const handlers = this.handlerMap.get(eventType);
    if (!handlers) {
      return;
    }

    const wrapped = handlers.get(handler);
    if (!wrapped) {
      return;
    }

    this.emitter.off(eventType, wrapped);
    handlers.delete(handler);

    if (handlers.size === 0) {
      this.handlerMap.delete(eventType);
    }
  }

  waitFor<E extends AnyEvent>(
    eventType: E["type"],
    predicate?: (event: E) => boolean,
    timeoutMs: number = DEFAULT_WAIT_TIMEOUT_MS,
  ): Promise<E> {
    const key = String(eventType);
    const emitter = this.emitter;

    return new Promise<E>((resolve, reject) => {
      // Forward-declare the listener + timer so `cleanup` can reference them.
      let timer: NodeJS.Timeout | undefined;
      let settled = false;

      // Centralized settlement — guarantees `emitter.off(...)` runs exactly
      // once regardless of which path (match, predicate-throw, timeout) fires
      // first. A settled=true guard prevents a second predicate-match event
      // from double-resolving the promise, and a second cleanup() call is a
      // no-op on EventEmitter.
      const cleanup = () => {
        if (settled) return;
        settled = true;
        if (timer !== undefined) clearTimeout(timer);
        emitter.off(key, onEvent);
      };

      const onEvent = (event: AnyEvent) => {
        if (settled) return;
        let matched: boolean;
        try {
          const typedEvent = event as E;
          matched = predicate ? predicate(typedEvent) : true;
          if (!matched) return;
        } catch (error) {
          // Predicate threw — fully detach before surfacing the error so
          // a subsequent event doesn't re-enter this handler.
          try {
            cleanup();
          } finally {
            reject(error);
          }
          return;
        }

        try {
          cleanup();
        } finally {
          resolve(event as E);
        }
      };

      timer = setTimeout(() => {
        try {
          cleanup();
        } finally {
          reject(new Error(`Timed out waiting for event: ${key}`));
        }
      }, timeoutMs);

      // Prevent the timeout from keeping the node process alive after bus.close().
      if (typeof timer === "object" && "unref" in timer) {
        timer.unref();
      }

      emitter.on(key, onEvent);
    });
  }

  async close(): Promise<void> {
    this.handlerMap.clear();
    this.emitter.removeAllListeners();
  }

  private emitHandlerError(sourceEventType: string, sourceEvent: AnyEvent, error: unknown): void {
    const message = toErrorMessage(error);
    if (sourceEventType === HANDLER_ERROR_EVENT_TYPE) {
      console.error(`[bus] handler error for ${sourceEventType}: ${message}`);
      return;
    }

    const handlerErrorEvent: AnyEvent = {
      type: HANDLER_ERROR_EVENT_TYPE,
      meta: {
        id: randomUUID(),
        timestamp: new Date().toISOString(),
        runId: sourceEvent.meta?.runId ?? "unknown",
      },
      payload: {
        sourceEventType,
        sourceEventId: sourceEvent.meta?.id,
        error: message,
      },
    };

    this.emitter.emit(HANDLER_ERROR_EVENT_TYPE, handlerErrorEvent);
  }
}

function isPromiseLike(value: unknown): value is Promise<unknown> {
  return !!value && typeof value === "object" && "then" in value;
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}
