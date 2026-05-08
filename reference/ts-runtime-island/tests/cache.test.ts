import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { InflightCache, resetGitHeadCache } from "../src/cache.js";

describe("InflightCache", () => {
  let cache: InflightCache;

  beforeEach(() => {
    cache = new InflightCache();
    resetGitHeadCache();
  });

  afterEach(() => {
    cache.invalidate();
  });

  describe("generateKey", () => {
    it("produces a deterministic sha256 hex key", () => {
      const key1 = cache.generateKey("model-a", "system", "user");
      const key2 = cache.generateKey("model-a", "system", "user");
      expect(key1).toBe(key2);
      expect(key1).toMatch(/^[0-9a-f]{64}$/);
    });

    it("produces different keys for different models", () => {
      const key1 = cache.generateKey("model-a", "system", "user");
      const key2 = cache.generateKey("model-b", "system", "user");
      expect(key1).not.toBe(key2);
    });

    it("produces different keys for different system prompts", () => {
      const key1 = cache.generateKey("model-a", "system1", "user");
      const key2 = cache.generateKey("model-a", "system2", "user");
      expect(key1).not.toBe(key2);
    });

    it("produces different keys for different user prompts", () => {
      const key1 = cache.generateKey("model-a", "system", "user1");
      const key2 = cache.generateKey("model-a", "system", "user2");
      expect(key1).not.toBe(key2);
    });
  });

  describe("getOrExecute", () => {
    it("executes and caches a new request", async () => {
      let callCount = 0;
      const executor = async () => {
        callCount++;
        return "result-1";
      };

      const key = "test-key-1";
      const result1 = await cache.getOrExecute(key, executor);
      const result2 = await cache.getOrExecute(key, executor);

      expect(result1).toBe("result-1");
      expect(result2).toBe("result-1");
      expect(callCount).toBe(1);
      expect(cache.size).toBe(1);
    });

    it("deduplicates concurrent identical requests", async () => {
      let callCount = 0;
      let resolveExecutor!: (value: string) => void;
      const executor = () => {
        callCount++;
        return new Promise<string>((resolve) => {
          resolveExecutor = resolve;
        });
      };

      const key = "test-key-2";
      const promise1 = cache.getOrExecute(key, executor);
      const promise2 = cache.getOrExecute(key, executor);

      expect(cache.inflightSize).toBe(1);
      expect(callCount).toBe(1);

      resolveExecutor("dedup-result");
      const [result1, result2] = await Promise.all([promise1, promise2]);

      expect(result1).toBe("dedup-result");
      expect(result2).toBe("dedup-result");
      expect(callCount).toBe(1);
    });

    it("does not cache errors", async () => {
      let callCount = 0;
      const failingExecutor = async () => {
        callCount++;
        throw new Error("transient failure");
      };

      const key = "test-key-3";
      await expect(cache.getOrExecute(key, failingExecutor)).rejects.toThrow("transient failure");
      expect(callCount).toBe(1);
      expect(cache.size).toBe(0);
      expect(cache.inflightSize).toBe(0);

      // Should retry after failure.
      const successExecutor = async () => {
        callCount++;
        return "recovered";
      };
      const result = await cache.getOrExecute(key, successExecutor);
      expect(result).toBe("recovered");
      expect(callCount).toBe(2);
    });

    it("bypasses cache when disabled", async () => {
      cache.enabled = false;
      let callCount = 0;
      const executor = async () => {
        callCount++;
        return "fresh-result";
      };

      const key = "test-key-4";
      const result1 = await cache.getOrExecute(key, executor);
      const result2 = await cache.getOrExecute(key, executor);

      expect(result1).toBe("fresh-result");
      expect(result2).toBe("fresh-result");
      expect(callCount).toBe(2);
      expect(cache.size).toBe(0);
    });

    it("returns stale result before TTL and re-executes after TTL", async () => {
      // Create a cache with a very short TTL for testing.
      const shortCache = new InflightCache();
      // Override TTL via the private property for test purposes.
      Object.defineProperty(shortCache, "ttlMs", { value: 50, writable: false });

      let callCount = 0;
      const executor = async () => {
        callCount++;
        return `result-${callCount}`;
      };

      const key = "ttl-test";
      const result1 = await shortCache.getOrExecute(key, executor);
      expect(result1).toBe("result-1");
      expect(callCount).toBe(1);

      // Should still be cached.
      const result2 = await shortCache.getOrExecute(key, executor);
      expect(result2).toBe("result-1");
      expect(callCount).toBe(1);

      // Wait for TTL to expire.
      await new Promise((resolve) => setTimeout(resolve, 60));

      const result3 = await shortCache.getOrExecute(key, executor);
      expect(result3).toBe("result-2");
      expect(callCount).toBe(2);

      shortCache.invalidate();
    });
  });

  describe("invalidate", () => {
    it("clears a specific key", async () => {
      await cache.getOrExecute("key-a", async () => "a");
      await cache.getOrExecute("key-b", async () => "b");
      expect(cache.size).toBe(2);

      cache.invalidate("key-a");
      expect(cache.size).toBe(1);

      // key-a should re-execute, key-b should still be cached.
      let callCount = 0;
      const resultA = await cache.getOrExecute("key-a", async () => {
        callCount++;
        return "a2";
      });
      const resultB = await cache.getOrExecute("key-b", async () => {
        callCount++;
        return "b2";
      });

      expect(resultA).toBe("a2");
      expect(resultB).toBe("b");
      expect(callCount).toBe(1);
    });

    it("clears all entries when no key is provided", async () => {
      await cache.getOrExecute("key-1", async () => "1");
      await cache.getOrExecute("key-2", async () => "2");
      expect(cache.size).toBe(2);

      cache.invalidate();
      expect(cache.size).toBe(0);
      expect(cache.inflightSize).toBe(0);
    });
  });

  describe("enabled property", () => {
    it("defaults to true", () => {
      expect(cache.enabled).toBe(true);
    });

    it("can be toggled", () => {
      cache.enabled = false;
      expect(cache.enabled).toBe(false);
      cache.enabled = true;
      expect(cache.enabled).toBe(true);
    });
  });
});
