import { EventEmitter } from "node:events";
import { randomUUID } from "node:crypto";
import type { AnyEvent, MessageBus } from "../types.js";

const DEFAULT_WAIT_TIMEOUT_MS = 12 * 60 * 60 * 1000;
const HANDLER_ERROR_EVENT_TYPE = "bus:handler-error";

type WrappedHandler = (event: AnyEvent) => void;

export class InProcessBus implements MessageBus {
  private readonly emitter = new EventEmitter();
  private readonly handlerMap = new Map<string, Map<Function, WrappedHandler>>();

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
      handlers = new Map<Function, WrappedHandler>();
      this.handlerMap.set(key, handlers);
    }

    if (handlers.has(handler as Function)) {
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

    handlers.set(handler as Function, wrapped);
    this.emitter.on(key, wrapped);
  }

  unsubscribe(eventType: string, handler: Function): void {
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

    return new Promise<E>((resolve, reject) => {
      const onEvent = (event: AnyEvent) => {
        try {
          const typedEvent = event as E;
          if (predicate && !predicate(typedEvent)) {
            return;
          }

          cleanup();
          resolve(typedEvent);
        } catch (error) {
          cleanup();
          reject(error);
        }
      };

      const timer = setTimeout(() => {
        cleanup();
        reject(new Error(`Timed out waiting for event: ${key}`));
      }, timeoutMs);

      // Prevent the timeout from keeping the node process alive after bus.close().
      if (typeof timer === "object" && "unref" in timer) {
        timer.unref();
      }

      const cleanup = () => {
        clearTimeout(timer);
        this.emitter.off(key, onEvent);
      };

      this.emitter.on(key, onEvent);
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
