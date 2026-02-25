import { afterEach, describe, expect, it, vi } from "vitest";
import { withRetry } from "../src/retry.js";

afterEach(() => {
  vi.useRealTimers();
});

describe("withRetry", () => {
  it("returns immediately on first success", async () => {
    const fn = vi.fn().mockResolvedValue("ok");

    const result = await withRetry(fn, {
      maxRetries: 2,
      backoffMs: 50,
      multiplier: 2,
    });

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries and succeeds on the second attempt", async () => {
    vi.useFakeTimers();
    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new Error("temporary"))
      .mockResolvedValueOnce("ok");

    const promise = withRetry(fn, {
      maxRetries: 2,
      backoffMs: 100,
      multiplier: 2,
    });

    expect(fn).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(100);

    const result = await promise;
    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("throws after max retries are exhausted", async () => {
    vi.useFakeTimers();
    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValue(new Error("permanent"));

    const promise = withRetry(fn, {
      maxRetries: 2,
      backoffMs: 100,
      multiplier: 2,
    });
    const expectation = expect(promise).rejects.toThrow("permanent");

    await vi.advanceTimersByTimeAsync(100);
    await vi.advanceTimersByTimeAsync(200);

    await expectation;
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("applies exponential backoff delays", async () => {
    vi.useFakeTimers();
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");

    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValue(new Error("boom"));

    const promise = withRetry(fn, {
      maxRetries: 3,
      backoffMs: 50,
      multiplier: 3,
    });
    const expectation = expect(promise).rejects.toThrow("boom");

    await vi.advanceTimersByTimeAsync(50);
    await vi.advanceTimersByTimeAsync(150);
    await vi.advanceTimersByTimeAsync(450);

    await expectation;

    const timeoutCalls = setTimeoutSpy.mock.calls.map((call) => Number(call[1]));
    expect(timeoutCalls.slice(0, 3)).toEqual([50, 150, 450]);
  });
});
