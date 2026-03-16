/** Release function returned by `acquire()`. Call to signal request completion. */
export type ReleaseFunction = () => void;

/** Per-provider concurrency and queue state. */
export interface ProviderState {
  /** Maximum concurrent requests allowed for this provider. */
  maxConcurrency: number;
  /** Original max concurrency before any adaptive adjustments. */
  originalMaxConcurrency: number;
  /** Number of currently in-flight requests. */
  currentConcurrency: number;
  /** FIFO queue of pending acquire requests. */
  queue: QueueEntry[];
  /** Count of consecutive successful releases (no rate-limit hit). */
  consecutiveSuccesses: number;
}

/** A single pending request waiting for a concurrency slot. */
export interface QueueEntry {
  resolve: (release: ReleaseFunction) => void;
  reject: (error: Error) => void;
  enqueuedAt: number;
  timer: ReturnType<typeof setTimeout>;
}

/** Stats snapshot for a provider returned by `getStats()`. */
export interface ProviderStats {
  model: string;
  maxConcurrency: number;
  originalMaxConcurrency: number;
  currentConcurrency: number;
  queueDepth: number;
  consecutiveSuccesses: number;
}

/** Events emitted by the RateLimitRegistry. */
export interface RateLimitRegistryEvents {
  "ratelimit:hit": {
    model: string;
    oldConcurrency: number;
    newConcurrency: number;
    retryAfterMs?: number;
  };
  "concurrency:changed": {
    model: string;
    oldConcurrency: number;
    newConcurrency: number;
    reason: "ratelimit" | "recovery" | "proactive-throttle";
  };
  "request:queued": {
    model: string;
    queueDepth: number;
  };
  "request:started": {
    model: string;
    currentConcurrency: number;
    maxConcurrency: number;
  };
}
