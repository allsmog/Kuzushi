/**
 * Lock the severity sparkline behaviour: the catalog's `LAST RUN` column
 * relies on a fixed visible width of 5, the right glyph for each magnitude
 * bucket, and graceful fallback to an empty string when there's no data.
 */
import { describe, expect, it } from "vitest";
import { visibleWidth } from "../../src/ui/format.js";
import { severitySparkline } from "../../src/ui/sparkline.js";

// Mirror of `src/ui/format.ts:ANSI_RE`. We only need the strip side here.
// biome-ignore lint/suspicious/noControlCharactersInRegex: ESC/CSI bytes are intrinsic to ANSI escape detection
const ANSI_RE = /[][[()#;?]*(?:[0-9]{1,4}(?:;[0-9]{0,4})*)?[0-9A-ORZcf-nqry=><]/g;
const stripAnsi = (s: string): string => s.replace(ANSI_RE, "");

describe("severitySparkline", () => {
  it("returns empty string when counts are undefined", () => {
    expect(severitySparkline(undefined)).toBe("");
  });

  it("returns empty string when every bucket is zero", () => {
    expect(severitySparkline({ critical: 0, high: 0, medium: 0, low: 0, info: 0 })).toBe("");
  });

  it("renders a 5-glyph sparkline at fixed visible width", () => {
    const out = severitySparkline({ critical: 1, high: 8, medium: 32 });
    expect(visibleWidth(out)).toBe(5);
  });

  it("maps each severity to the expected magnitude glyph", () => {
    // critical=1 → ▁, high=8 → ▅, medium=32 → ▇, low=0 → ·, info=0 → ·
    // (32 falls into the 32–63 bracket per src/ui/sparkline.ts:bucket())
    const out = severitySparkline({ critical: 1, high: 8, medium: 32 });
    expect(stripAnsi(out)).toBe("▁▅▇··");
  });

  it("ceiling-clamps large counts to the █ glyph", () => {
    const out = severitySparkline({ high: 200 });
    // critical=0 → ·, high=200 → █, others zero → ·
    expect(stripAnsi(out)).toBe("·█···");
  });

  it("walks the full bucket ramp at boundary values", () => {
    // 1→▁, 2→▂, 4→▃, 7→▄, 15→▅ — boundaries the bucket() function flips at.
    const out = severitySparkline({ critical: 1, high: 2, medium: 4, low: 7, info: 15 });
    expect(stripAnsi(out)).toBe("▁▂▃▄▅");
  });

  it("ignores non-canonical severity keys", () => {
    // Only the five canonical keys make it into the output; foreign keys
    // are dropped silently so the column width stays predictable.
    const out = severitySparkline({ critical: 1, exotic: 99 });
    expect(stripAnsi(out)).toBe("▁····");
  });
});
