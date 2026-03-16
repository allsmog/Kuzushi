import { RateLimitRegistry } from "./rate-limit-registry.js";

export { RateLimitRegistry } from "./rate-limit-registry.js";
export type {
  ProviderState,
  ProviderStats,
  QueueEntry,
  RateLimitRegistryEvents,
  ReleaseFunction,
} from "./types.js";

/** Singleton rate-limit registry shared across the process. */
let singleton: RateLimitRegistry | undefined;

/**
 * Get (or lazily create) the global `RateLimitRegistry` singleton.
 *
 * The initial concurrency is resolved from:
 * 1. `KUZUSHI_MAX_CONCURRENCY` env var
 * 2. Fallback to internal default (5)
 *
 * To configure from `KuzushiConfig`, call `configureRateLimitRegistry()`
 * after loading config.
 */
export function getRateLimitRegistry(): RateLimitRegistry {
  if (!singleton) {
    singleton = new RateLimitRegistry();
  }
  return singleton;
}

/**
 * Replace the global singleton with a new instance configured with
 * the given default concurrency. Destroys any previous instance.
 *
 * Typically called once during startup after loading `KuzushiConfig`,
 * using `triageConcurrency` or `verifyConcurrency` as the default.
 */
export function configureRateLimitRegistry(
  defaultMaxConcurrency?: number,
): RateLimitRegistry {
  if (singleton) {
    singleton.destroy();
  }
  singleton = new RateLimitRegistry(defaultMaxConcurrency);
  return singleton;
}

/**
 * Destroy and remove the global singleton.
 * Useful for test cleanup.
 */
export function resetRateLimitRegistry(): void {
  if (singleton) {
    singleton.destroy();
    singleton = undefined;
  }
}
