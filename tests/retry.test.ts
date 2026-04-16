import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthError, RateLimitError, TransientError } from "../src/errors.js";
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

  it("retries transient errors and succeeds on the second attempt", async () => {
    vi.useFakeTimers();
    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new TransientError("503 Service Temporarily Unavailable"))
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

  it("throws after max retries are exhausted for transient errors", async () => {
    vi.useFakeTimers();
    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValue(new TransientError("connection reset"));

    const promise = withRetry(fn, {
      maxRetries: 2,
      backoffMs: 100,
      multiplier: 2,
    });
    const expectation = expect(promise).rejects.toThrow("connection reset");

    await vi.advanceTimersByTimeAsync(100);
    await vi.advanceTimersByTimeAsync(200);

    await expectation;
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("applies exponential backoff delays", async () => {
    vi.useFakeTimers();
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");

    const fn = vi.fn<() => Promise<string>>().mockRejectedValue(new TransientError("ECONNRESET"));

    const promise = withRetry(fn, {
      maxRetries: 3,
      backoffMs: 50,
      multiplier: 3,
    });
    const expectation = expect(promise).rejects.toThrow("ECONNRESET");

    await vi.advanceTimersByTimeAsync(50);
    await vi.advanceTimersByTimeAsync(150);
    await vi.advanceTimersByTimeAsync(450);

    await expectation;

    const timeoutCalls = setTimeoutSpy.mock.calls.map((call) => Number(call[1]));
    expect(timeoutCalls.slice(0, 3)).toEqual([50, 150, 450]);
  });

  it("does not retry auth errors", async () => {
    const fn = vi.fn<() => Promise<string>>().mockRejectedValue(new AuthError("401 Unauthorized"));

    await expect(withRetry(fn, { maxRetries: 3, backoffMs: 50, multiplier: 2 })).rejects.toThrow(
      "401 Unauthorized",
    );

    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("does not retry unclassified errors (classified as fatal)", async () => {
    const fn = vi.fn<() => Promise<string>>().mockRejectedValue(new Error("some unknown error"));

    await expect(withRetry(fn, { maxRetries: 3, backoffMs: 50, multiplier: 2 })).rejects.toThrow(
      "some unknown error",
    );

    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("classifies plain errors with transient messages and retries them", async () => {
    vi.useFakeTimers();
    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new Error("502 Bad Gateway"))
      .mockResolvedValueOnce("recovered");

    const promise = withRetry(fn, {
      maxRetries: 2,
      backoffMs: 100,
      multiplier: 2,
    });

    await vi.advanceTimersByTimeAsync(100);

    const result = await promise;
    expect(result).toBe("recovered");
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("applies longer backoff for rate_limit errors", async () => {
    vi.useFakeTimers();
    const setTimeoutSpy = vi.spyOn(globalThis, "setTimeout");

    const fn = vi
      .fn<() => Promise<string>>()
      .mockRejectedValueOnce(new RateLimitError("429 Too Many Requests"))
      .mockRejectedValueOnce(new RateLimitError("429 Too Many Requests"))
      .mockResolvedValueOnce("ok");

    const promise = withRetry(fn, {
      maxRetries: 3,
      backoffMs: 100,
      multiplier: 2,
    });

    // Rate-limit backoff = base * multiplier^attempt * RATE_LIMIT_BACKOFF_FACTOR(3)
    // attempt 0: 100 * 1 * 3 = 300
    // attempt 1: 100 * 2 * 3 = 600
    await vi.advanceTimersByTimeAsync(300);
    await vi.advanceTimersByTimeAsync(600);

    const result = await promise;
    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(3);

    const timeoutCalls = setTimeoutSpy.mock.calls.map((call) => Number(call[1]));
    expect(timeoutCalls.slice(0, 2)).toEqual([300, 600]);
  });
});
