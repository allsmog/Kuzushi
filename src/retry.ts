import type { MessageBus } from "./bus/types.js";
import type { RetryAttemptEvent, RetryExhaustedEvent } from "./bus/events.js";
import { toErrorMessage } from "./utils.js";

export interface RetryOptions {
  maxRetries: number;
  backoffMs: number;
  multiplier: number;
  /** Optional operation label for observability events. */
  operation?: string;
  /** Optional message bus for emitting retry observability events. */
  bus?: MessageBus;
  /** Optional run ID for correlating events. */
  runId?: string;
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions,
): Promise<T> {
  let lastError: unknown;
  const operation = options.operation ?? "unknown";

  for (let attempt = 0; attempt <= options.maxRetries; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      if (attempt < options.maxRetries) {
        const delay = options.backoffMs * Math.pow(options.multiplier, attempt);

        // Emit retry:attempt event if bus is available
        if (options.bus) {
          try {
            await options.bus.publish<RetryAttemptEvent>({
              type: "retry:attempt",
              meta: {
                id: crypto.randomUUID(),
                timestamp: new Date().toISOString(),
                runId: options.runId ?? "",
              },
              payload: {
                operation,
                attempt: attempt + 1,
                maxAttempts: options.maxRetries + 1,
                error: toErrorMessage(error),
              },
            });
          } catch {
            // Non-fatal: observability emission should never break retry logic
          }
        }

        await sleep(delay);
      }
    }
  }

  // Emit retry:exhausted event if bus is available
  if (options.bus) {
    try {
      await options.bus.publish<RetryExhaustedEvent>({
        type: "retry:exhausted",
        meta: {
          id: crypto.randomUUID(),
          timestamp: new Date().toISOString(),
          runId: options.runId ?? "",
        },
        payload: {
          operation,
          attempts: options.maxRetries + 1,
          finalError: toErrorMessage(lastError),
        },
      });
    } catch {
      // Non-fatal: observability emission should never break retry logic
    }
  }

  throw lastError;
}

function sleep(ms: number): Promise<void> {
  if (!Number.isFinite(ms) || ms <= 0) {
    return Promise.resolve();
  }

  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}
