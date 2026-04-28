import { describe, expect, it } from "vitest";
import { mapConcurrent } from "../../src/agent-runtime/execution.js";

describe("mapConcurrent", () => {
  it("returns empty array for empty input without invoking the worker", async () => {
    let called = 0;
    const out = await mapConcurrent<number, number>([], 4, async (n) => {
      called += 1;
      return n;
    });
    expect(out).toEqual([]);
    expect(called).toBe(0);
  });

  it("preserves input order in the result array", async () => {
    const input = [10, 20, 30, 40, 50];
    const out = await mapConcurrent(input, 3, async (n, i) => {
      // Reverse-correlated delay so later items finish first if order
      // weren't preserved.
      await new Promise((r) => setTimeout(r, (input.length - i) * 5));
      return n * 2;
    });
    expect(out).toEqual([20, 40, 60, 80, 100]);
  });

  it("never exceeds the concurrency limit", async () => {
    let inFlight = 0;
    let peak = 0;
    const items = Array.from({ length: 12 }, (_, i) => i);
    const out = await mapConcurrent(items, 3, async (n) => {
      inFlight += 1;
      peak = Math.max(peak, inFlight);
      await new Promise((r) => setTimeout(r, 5));
      inFlight -= 1;
      return n;
    });
    expect(out).toEqual(items);
    expect(peak).toBeLessThanOrEqual(3);
    expect(peak).toBeGreaterThanOrEqual(2);
  });

  it("treats non-finite or sub-1 limits as 1", async () => {
    let inFlight = 0;
    let peak = 0;
    const items = [1, 2, 3, 4];
    for (const limit of [0, -3, Number.NaN, Number.POSITIVE_INFINITY]) {
      inFlight = 0;
      peak = 0;
      const out = await mapConcurrent(items, limit, async (n) => {
        inFlight += 1;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 2));
        inFlight -= 1;
        return n;
      });
      if (limit === Number.POSITIVE_INFINITY) {
        // POSITIVE_INFINITY is non-finite → coerced to 1.
        expect(peak).toBe(1);
      } else {
        expect(peak).toBe(1);
      }
      expect(out).toEqual(items);
    }
  });

  it("propagates worker rejections without dropping in-flight results", async () => {
    const items = [1, 2, 3];
    await expect(
      mapConcurrent(items, 2, async (n) => {
        if (n === 2) throw new Error("boom");
        return n;
      }),
    ).rejects.toThrow("boom");
  });

  it("caps runner count at items.length when limit > items", async () => {
    const items = [1, 2];
    let started = 0;
    const out = await mapConcurrent(items, 16, async (n) => {
      started += 1;
      return n + 1;
    });
    expect(out).toEqual([2, 3]);
    expect(started).toBe(2);
  });
});
