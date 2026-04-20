import { describe, expect, it } from "vitest";
import { pickTip } from "../../src/ui/components/BannerSplash.js";

describe("BannerSplash.pickTip", () => {
  it("returns a non-empty string", () => {
    expect(pickTip(0)).toBeTruthy();
    expect(typeof pickTip(Date.now())).toBe("string");
  });

  it("returns the same tip for timestamps in the same minute", () => {
    // Pick a value aligned to a minute boundary so the +offset stays inside
    // the same bucket without edge-case straddling.
    const base = Math.floor(1_700_000_000_000 / 60_000) * 60_000;
    expect(pickTip(base)).toBe(pickTip(base + 1));
    expect(pickTip(base)).toBe(pickTip(base + 30_000));
    expect(pickTip(base)).toBe(pickTip(base + 59_999));
  });

  it("cycles deterministically across minutes", () => {
    const base = 0;
    const minute = 60_000;
    const observed = new Set<string>();
    // A run of 12 consecutive minutes should visit at least 8 distinct tips
    // (we have 10). Anything lower and the rotation is broken.
    for (let i = 0; i < 12; i++) observed.add(pickTip(base + i * minute));
    expect(observed.size).toBeGreaterThanOrEqual(8);
  });

  it("handles negative timestamps without crashing", () => {
    expect(() => pickTip(-1)).not.toThrow();
    expect(typeof pickTip(-60_001)).toBe("string");
  });
});
