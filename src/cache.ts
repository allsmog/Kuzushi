import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

/** Default TTL: 14 days in milliseconds. Override via KUZUSHI_CACHE_TTL env var. */
const DEFAULT_TTL_MS = 14 * 24 * 60 * 60 * 1000;

function resolveTtlMs(): number {
  const envVal = process.env["KUZUSHI_CACHE_TTL"];
  if (envVal != null) {
    const parsed = Number(envVal);
    if (Number.isFinite(parsed) && parsed > 0) {
      return parsed;
    }
  }
  return DEFAULT_TTL_MS;
}

interface CacheEntry<T = unknown> {
  result: T;
  timestamp: number;
}

/**
 * Inflight request deduplication and result caching for LLM calls.
 *
 * - Concurrent identical requests share the same in-flight promise.
 * - Completed results are cached in-memory with a configurable TTL.
 * - Cache keys incorporate git HEAD so results are automatically invalidated
 *   when the repository changes.
 */
export class InflightCache {
  /** In-flight promises keyed by cache key. Cleared when the promise settles. */
  private inflightRequests = new Map<string, Promise<unknown>>();

  /** Cached results keyed by cache key. Entries expire after TTL. */
  private diskCache = new Map<string, CacheEntry>();

  /** Whether caching is enabled. Toggled off by --no-cache or --fresh. */
  private _enabled = true;

  /** Resolved TTL in milliseconds. */
  readonly ttlMs: number;

  constructor() {
    this.ttlMs = resolveTtlMs();
  }

  /** Enable or disable the cache entirely. When disabled, getOrExecute always runs the executor. */
  set enabled(value: boolean) {
    this._enabled = value;
  }

  get enabled(): boolean {
    return this._enabled;
  }

  /**
   * Generate a deterministic cache key from the model, system prompt, user prompt,
   * and the current git HEAD (so cache is invalidated when code changes).
   */
  generateKey(model: string, systemPrompt: string, userPrompt: string, cwd?: string): string {
    const hash = createHash("sha256");
    hash.update(model);
    hash.update("\x00");
    hash.update(systemPrompt);
    hash.update("\x00");
    hash.update(userPrompt);

    const gitHead = resolveGitHead(cwd);
    if (gitHead) {
      hash.update("\x00");
      hash.update(gitHead);
    }

    return hash.digest("hex");
  }

  /**
   * Return a cached or in-flight result, or execute the callback and cache the outcome.
   *
   * - If an identical request is already in-flight, returns the same promise (deduplication).
   * - If a cached result exists and has not expired, returns it immediately.
   * - Otherwise, runs the executor, caches the result on success, and returns it.
   *
   * Errors from the executor are **not** cached. They do clear the in-flight entry
   * so that subsequent calls can retry.
   */
  async getOrExecute<T>(key: string, executor: () => Promise<T>): Promise<T> {
    if (!this._enabled) {
      return executor();
    }

    // Check in-flight deduplication first.
    const inflight = this.inflightRequests.get(key);
    if (inflight) {
      return inflight as Promise<T>;
    }

    // Check disk/memory cache.
    const cached = this.diskCache.get(key);
    if (cached && Date.now() - cached.timestamp < this.ttlMs) {
      return cached.result as T;
    }

    // Remove stale entry if present.
    if (cached) {
      this.diskCache.delete(key);
    }

    // Register the deferred promise BEFORE starting the executor to prevent
    // a race where a synchronously-resolving executor allows a concurrent
    // caller to miss the in-flight entry during microtask interleaving.
    let resolveDeferred!: (v: T) => void;
    let rejectDeferred!: (e: unknown) => void;
    const deferred = new Promise<T>((res, rej) => {
      resolveDeferred = res;
      rejectDeferred = rej;
    });
    this.inflightRequests.set(key, deferred);

    executor().then(
      (result) => {
        this.diskCache.set(key, { result, timestamp: Date.now() });
        this.inflightRequests.delete(key);
        resolveDeferred(result);
      },
      (error) => {
        this.inflightRequests.delete(key);
        rejectDeferred(error);
      },
    );

    return deferred;
  }

  /** Clear a specific cache entry, or all entries if no key is provided. */
  invalidate(key?: string): void {
    if (key) {
      this.diskCache.delete(key);
      this.inflightRequests.delete(key);
    } else {
      this.diskCache.clear();
      this.inflightRequests.clear();
    }
  }

  /** Number of cached results (excludes in-flight). */
  get size(): number {
    return this.diskCache.size;
  }

  /** Number of in-flight requests. */
  get inflightSize(): number {
    return this.inflightRequests.size;
  }
}

/** Cached git HEAD value per working directory (process-lifetime). */
const gitHeadCache = new Map<string, string | null>();

/** Resolve the current git HEAD SHA for a working directory. Returns null on failure. */
function resolveGitHead(cwd?: string): string | null {
  const key = cwd ?? "__default__";

  if (gitHeadCache.has(key)) {
    return gitHeadCache.get(key) ?? null;
  }

  try {
    const head = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: cwd ?? process.cwd(),
      encoding: "utf-8",
      timeout: 5_000,
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();

    gitHeadCache.set(key, head || null);
    return head || null;
  } catch {
    gitHeadCache.set(key, null);
    return null;
  }
}

/** Reset the cached git HEAD values (useful for testing or after git operations). */
export function resetGitHeadCache(): void {
  gitHeadCache.clear();
}

/** Singleton cache instance used across the application. */
export const inflightCache = new InflightCache();
