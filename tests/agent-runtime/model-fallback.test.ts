import { describe, it, expect, beforeEach, vi } from "vitest";
import { ModelFallbackManager } from "../../src/agent-runtime/model-fallback.js";

describe("ModelFallbackManager", () => {
  let manager: ModelFallbackManager;
  const onFallback = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();
    manager = new ModelFallbackManager(onFallback);
  });

  it("returns primary model when healthy", () => {
    const chain = ModelFallbackManager.buildChain("primary", ["fallback1"]);
    expect(manager.selectModel(chain)).toBe("primary");
    expect(onFallback).not.toHaveBeenCalled();
  });

  it("does not fallback on transient errors", () => {
    const chain = ModelFallbackManager.buildChain("primary", ["fallback1"]);
    manager.recordFailure("primary", "transient");
    manager.recordFailure("primary", "transient");
    manager.recordFailure("primary", "transient");
    expect(manager.selectModel(chain)).toBe("primary");
  });

  it("falls back after 3 consecutive auth failures", () => {
    const chain = ModelFallbackManager.buildChain("primary", ["fallback1"]);
    manager.recordFailure("primary", "auth");
    manager.recordFailure("primary", "auth");
    manager.recordFailure("primary", "auth");
    expect(manager.selectModel(chain)).toBe("fallback1");
    expect(onFallback).toHaveBeenCalledWith("primary", "fallback1");
  });

  it("falls back on budget errors", () => {
    const chain = ModelFallbackManager.buildChain("primary", ["fallback1"]);
    manager.recordFailure("primary", "budget");
    manager.recordFailure("primary", "budget");
    manager.recordFailure("primary", "budget");
    expect(manager.selectModel(chain)).toBe("fallback1");
  });

  it("recovers after cooldown expires", () => {
    const chain = ModelFallbackManager.buildChain("primary", ["fallback1"], 10); // 10ms cooldown
    manager.recordFailure("primary", "auth");
    manager.recordFailure("primary", "auth");
    manager.recordFailure("primary", "auth");
    expect(manager.selectModel(chain)).toBe("fallback1");

    return new Promise<void>((resolve) => {
      setTimeout(() => {
        expect(manager.selectModel(chain)).toBe("primary");
        resolve();
      }, 20);
    });
  });

  it("resets failure count on success", () => {
    const chain = ModelFallbackManager.buildChain("primary", ["fallback1"]);
    manager.recordFailure("primary", "auth");
    manager.recordFailure("primary", "auth");
    manager.recordSuccess("primary");
    manager.recordFailure("primary", "auth");
    // Only 1 failure after reset, should still use primary
    expect(manager.selectModel(chain)).toBe("primary");
  });

  it("falls through chain when all fallbacks are in cooldown", () => {
    const chain = ModelFallbackManager.buildChain("primary", ["fallback1", "fallback2"]);
    for (let i = 0; i < 3; i++) manager.recordFailure("primary", "auth");
    for (let i = 0; i < 3; i++) manager.recordFailure("fallback1", "auth");
    expect(manager.selectModel(chain)).toBe("fallback2");
  });

  it("returns primary as last resort when all models in cooldown", () => {
    const chain = ModelFallbackManager.buildChain("primary", ["fallback1"]);
    for (let i = 0; i < 3; i++) manager.recordFailure("primary", "auth");
    for (let i = 0; i < 3; i++) manager.recordFailure("fallback1", "auth");
    expect(manager.selectModel(chain)).toBe("primary");
  });

  it("buildChain uses defaults", () => {
    const chain = ModelFallbackManager.buildChain("model-a");
    expect(chain.primary).toBe("model-a");
    expect(chain.fallbacks).toEqual([]);
    expect(chain.cooldownMs).toBe(60_000);
  });
});
