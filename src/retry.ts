import { KuzushiError, classifyError, type ErrorCategory } from "./errors.js";

export interface RetryOptions {
  maxRetries: number;
  backoffMs: number;
  multiplier: number;
}

/** Categories that should never be retried. */
const NON_RETRYABLE: ReadonlySet<ErrorCategory> = new Set<ErrorCategory>([
  "auth",
  "validation",
  "budget",
  "fatal",
]);

/** Multiplier applied on top of the normal backoff for rate-limit errors. */
const RATE_LIMIT_BACKOFF_FACTOR = 3;

export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions,
): Promise<T> {
  let lastError: unknown;

  for (let attempt = 0; attempt <= options.maxRetries; attempt += 1) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;

      // Classify the error — works for both KuzushiError and plain errors.
      const category: ErrorCategory = error instanceof KuzushiError
        ? error.category
        : classifyError(error);

      // Non-retryable categories should fail immediately.
      if (NON_RETRYABLE.has(category)) {
        throw error;
      }

      if (attempt < options.maxRetries) {
        let delay = options.backoffMs * Math.pow(options.multiplier, attempt);

        // Rate-limit errors get extra breathing room.
        if (category === "rate_limit") {
          delay *= RATE_LIMIT_BACKOFF_FACTOR;
        }

        await sleep(delay);
      }
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
