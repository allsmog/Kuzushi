import { describe, expect, it } from "vitest";
import { createManualUiClock } from "../../src/ui/clock.js";

describe("createManualUiClock", () => {
  it("advances intervals deterministically", () => {
    const clock = createManualUiClock(1_000);
    const seen: number[] = [];
    const dispose = clock.setInterval(() => {
      seen.push(clock.now());
    }, 1_000);

    clock.advanceBy(999);
    expect(seen).toEqual([]);

    clock.advanceBy(1);
    expect(seen).toEqual([2_000]);

    clock.advanceBy(2_000);
    expect(seen).toEqual([2_000, 3_000, 4_000]);

    dispose();
    clock.advanceBy(5_000);
    expect(seen).toEqual([2_000, 3_000, 4_000]);
  });
});
