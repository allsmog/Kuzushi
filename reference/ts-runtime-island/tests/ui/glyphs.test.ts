/**
 * `BLACK_CIRCLE` must adapt to platform (cc-repo parity) and the rest of
 * the glyph constants must never silently drift — callsites all import
 * from this one module.
 */
import { describe, expect, it } from "vitest";
import { BLACK_CIRCLE, LOWER_HOOK, OUTCOME_GLYPH } from "../../src/ui/glyphs.js";

describe("glyphs", () => {
  it("exports a BLACK_CIRCLE for the current platform", () => {
    // On darwin: U+23FA (⏺). Elsewhere: U+25CF (●).
    const expected = process.platform === "darwin" ? "⏺" : "●";
    expect(BLACK_CIRCLE).toBe(expected);
  });

  it("BLACK_CIRCLE is exactly one visible character", () => {
    expect([...BLACK_CIRCLE].length).toBe(1);
  });

  it("exports the `⎿` LOWER_HOOK (U+23BF) unchanged", () => {
    expect(LOWER_HOOK).toBe("⎿");
    expect(LOWER_HOOK.codePointAt(0)).toBe(0x23bf);
  });

  it("exposes ok/fail/abort outcome glyphs", () => {
    expect(OUTCOME_GLYPH.ok).toBe("✓");
    expect(OUTCOME_GLYPH.fail).toBe("✗");
    expect(OUTCOME_GLYPH.abort).toBe("·");
  });
});
