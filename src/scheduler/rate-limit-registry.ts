import { EventEmitter } from "node:events";
import type {
  ProviderState,
  ProviderStats,
  QueueEntry,
  RateLimitRegistryEvents,
  ReleaseFunction,
} from "./types.js";

/** Default initial concurrency when no configuration is provided. */
const DEFAULT_MAX_CONCURRENCY = 5;

/** Queue timeout in milliseconds (5 minutes). */
const QUEUE_TIMEOUT_MS = 5 * 60 * 1000;

/** Number of consecutive successes required before recovery. */
const RECOVERY_THRESHOLD = 5;

/** Proactive throttle when remaining quota falls below this fraction. */
const PROACTIVE_THROTTLE_FRACTION = 0.1;

/**
 * Adaptive rate limit registry with per-provider state machines.
 *
 * Each model/provider gets its own concurrency pool, FIFO queue,
 * and adaptive state. The registry:
 *
 * - Halves concurrency immediately on rate-limit (429) hits
 * - Recovers concurrency by 50% after consecutive successes
 * - Proactively throttles when remaining quota headers indicate < 10%
 * - Times out queued requests after 5 minutes
 */
export class RateLimitRegistry extends EventEmitter {
  private readonly providers = new Map<string, ProviderState>();
  private readonly defaultMaxConcurrency: number;

  constructor(defaultMaxConcurrency?: number) {
    super();
    this.defaultMaxConcurrency = normalizePositiveInt(
      defaultMaxConcurrency ?? resolveDefaultConcurrency(),
      DEFAULT_MAX_CONCURRENCY,
    );
  }

  /**
   * Acquire a concurrency slot for `model`.
   *
   * If the provider is at capacity, the request is queued (FIFO)
   * with a 5-minute timeout. Returns a release function that MUST
   * be called when the request completes (via `release()`).
   */
  acquire(model: string): Promise<ReleaseFunction> {
    const state = this.getOrCreateState(model);

    if (state.currentConcurrency < state.maxConcurrency) {
      return Promise.resolve(this.startRequest(state, model));
    }

    // At capacity — queue the request.
    return new Promise<ReleaseFunction>((resolve, reject) => {
      const entry: QueueEntry = {
        resolve,
        reject,
        enqueuedAt: Date.now(),
        timer: setTimeout(() => {
          this.removeFromQueue(state, entry);
          reject(new Error(
            `Rate limit queue timeout: waited ${QUEUE_TIMEOUT_MS / 1000}s for concurrency slot on model "${model}"`,
          ));
        }, QUEUE_TIMEOUT_MS),
      };

      state.queue.push(entry);

      this.emit("request:queued", {
        model,
        queueDepth: state.queue.length,
      } satisfies RateLimitRegistryEvents["request:queued"]);
    });
  }

  /**
   * Release a concurrency slot for `model` and update adaptive state.
   *
   * @param model   The model/provider identifier.
   * @param success Whether the request succeeded (false on 429 / rate-limit errors).
   * @param headers Optional response headers for proactive throttling.
   */
  release(
    model: string,
    success: boolean,
    headers?: Record<string, string>,
  ): void {
    const state = this.providers.get(model);
    if (!state) return;

    state.currentConcurrency = Math.max(0, state.currentConcurrency - 1);

    if (!success) {
      this.handleRateLimitHit(state, model, headers);
    } else {
      state.consecutiveSuccesses += 1;

      // Parse rate-limit headers for proactive throttling.
      if (headers) {
        this.applyProactiveThrottle(state, model, headers);
      }

      // Asymmetric recovery: after RECOVERY_THRESHOLD consecutive successes,
      // increase concurrency by 50% (capped at original max).
      if (
        state.consecutiveSuccesses >= RECOVERY_THRESHOLD
        && state.maxConcurrency < state.originalMaxConcurrency
      ) {
        const oldConcurrency = state.maxConcurrency;
        state.maxConcurrency = Math.min(
          state.originalMaxConcurrency,
          Math.ceil(state.maxConcurrency * 1.5),
        );
        state.consecutiveSuccesses = 0;

        if (state.maxConcurrency !== oldConcurrency) {
          this.emit("concurrency:changed", {
            model,
            oldConcurrency,
            newConcurrency: state.maxConcurrency,
            reason: "recovery",
          } satisfies RateLimitRegistryEvents["concurrency:changed"]);
        }
      }
    }

    // Drain queue if there is capacity.
    this.drainQueue(state, model);
  }

  /**
   * Get a snapshot of the current stats for a provider.
   */
  getStats(model: string): ProviderStats {
    const state = this.providers.get(model);
    if (!state) {
      return {
        model,
        maxConcurrency: this.defaultMaxConcurrency,
        originalMaxConcurrency: this.defaultMaxConcurrency,
        currentConcurrency: 0,
        queueDepth: 0,
        consecutiveSuccesses: 0,
      };
    }

    return {
      model,
      maxConcurrency: state.maxConcurrency,
      originalMaxConcurrency: state.originalMaxConcurrency,
      currentConcurrency: state.currentConcurrency,
      queueDepth: state.queue.length,
      consecutiveSuccesses: state.consecutiveSuccesses,
    };
  }

  /**
   * Destroy the registry: reject all pending queue entries and clear state.
   */
  destroy(): void {
    for (const [, state] of this.providers) {
      for (const entry of state.queue) {
        clearTimeout(entry.timer);
        entry.reject(new Error("RateLimitRegistry destroyed"));
      }
      state.queue.length = 0;
    }
    this.providers.clear();
    this.removeAllListeners();
  }

  // ---------------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------------

  private getOrCreateState(model: string): ProviderState {
    let state = this.providers.get(model);
    if (!state) {
      state = {
        maxConcurrency: this.defaultMaxConcurrency,
        originalMaxConcurrency: this.defaultMaxConcurrency,
        currentConcurrency: 0,
        queue: [],
        consecutiveSuccesses: 0,
      };
      this.providers.set(model, state);
    }
    return state;
  }

  private startRequest(state: ProviderState, model: string): ReleaseFunction {
    state.currentConcurrency += 1;

    this.emit("request:started", {
      model,
      currentConcurrency: state.currentConcurrency,
      maxConcurrency: state.maxConcurrency,
    } satisfies RateLimitRegistryEvents["request:started"]);

    let released = false;
    return () => {
      if (!released) {
        released = true;
        // release() is called explicitly by the caller with success/headers,
        // so this is a fallback safety net — treat as success.
        this.release(model, true);
      }
    };
  }

  private handleRateLimitHit(
    state: ProviderState,
    model: string,
    headers?: Record<string, string>,
  ): void {
    const oldConcurrency = state.maxConcurrency;

    // Halve concurrency instantly (floor to at least 1).
    state.maxConcurrency = Math.max(1, Math.floor(state.maxConcurrency / 2));
    state.consecutiveSuccesses = 0;

    const retryAfterMs = parseRetryAfterMs(headers);

    this.emit("ratelimit:hit", {
      model,
      oldConcurrency,
      newConcurrency: state.maxConcurrency,
      retryAfterMs: retryAfterMs ?? undefined,
    } satisfies RateLimitRegistryEvents["ratelimit:hit"]);

    if (state.maxConcurrency !== oldConcurrency) {
      this.emit("concurrency:changed", {
        model,
        oldConcurrency,
        newConcurrency: state.maxConcurrency,
        reason: "ratelimit",
      } satisfies RateLimitRegistryEvents["concurrency:changed"]);
    }
  }

  private applyProactiveThrottle(
    state: ProviderState,
    model: string,
    headers: Record<string, string>,
  ): void {
    const remaining = parseHeaderNumber(headers, "x-ratelimit-remaining");
    const limit = parseHeaderNumber(headers, "x-ratelimit-limit");

    if (remaining == null || limit == null || limit <= 0) return;

    const fraction = remaining / limit;
    if (fraction >= PROACTIVE_THROTTLE_FRACTION) return;

    // Reduce concurrency proportionally to remaining quota.
    // E.g., 5% remaining -> scale to ~50% of original max.
    const scaleFactor = Math.max(0.2, fraction / PROACTIVE_THROTTLE_FRACTION);
    const targetConcurrency = Math.max(
      1,
      Math.floor(state.originalMaxConcurrency * scaleFactor),
    );

    if (targetConcurrency < state.maxConcurrency) {
      const oldConcurrency = state.maxConcurrency;
      state.maxConcurrency = targetConcurrency;

      this.emit("concurrency:changed", {
        model,
        oldConcurrency,
        newConcurrency: state.maxConcurrency,
        reason: "proactive-throttle",
      } satisfies RateLimitRegistryEvents["concurrency:changed"]);
    }
  }

  private drainQueue(state: ProviderState, model: string): void {
    while (
      state.queue.length > 0
      && state.currentConcurrency < state.maxConcurrency
    ) {
      const entry = state.queue.shift()!;
      clearTimeout(entry.timer);
      const release = this.startRequest(state, model);
      entry.resolve(release);
    }
  }

  private removeFromQueue(state: ProviderState, entry: QueueEntry): void {
    const idx = state.queue.indexOf(entry);
    if (idx !== -1) {
      state.queue.splice(idx, 1);
    }
  }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/**
 * Parse `Retry-After` header value to milliseconds.
 * Supports both seconds (integer) and HTTP-date formats.
 */
function parseRetryAfterMs(
  headers?: Record<string, string>,
): number | null {
  if (!headers) return null;

  const retryAfter = headers["retry-after"] ?? headers["Retry-After"];
  if (!retryAfter) return null;

  // Try as integer seconds first.
  const seconds = Number(retryAfter);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.ceil(seconds * 1000);
  }

  // Try as HTTP-date.
  const date = Date.parse(retryAfter);
  if (Number.isFinite(date)) {
    return Math.max(0, date - Date.now());
  }

  return null;
}

function parseHeaderNumber(
  headers: Record<string, string>,
  name: string,
): number | null {
  // Try lowercase first, then original case.
  const raw = headers[name] ?? headers[name.toLowerCase()];
  if (!raw) return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

function normalizePositiveInt(value: number, fallback: number): number {
  if (!Number.isFinite(value) || value < 1) return fallback;
  return Math.floor(value);
}

/**
 * Resolve the default concurrency from environment or fallback.
 */
function resolveDefaultConcurrency(): number {
  const envValue = process.env["KUZUSHI_MAX_CONCURRENCY"];
  if (envValue) {
    const n = Number(envValue);
    if (Number.isFinite(n) && n >= 1) {
      return Math.floor(n);
    }
  }
  return DEFAULT_MAX_CONCURRENCY;
}
