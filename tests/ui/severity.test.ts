/**
 * Tests for the accessibility-aware severity palette.
 *
 * The goal of the palette is:
 *   1. Every tier has a `{color, glyph, label}` so color-blind and
 *      screen-reader users can still distinguish severity without hue.
 *   2. `NO_COLOR=1` suppresses `color` and the chalk wrapper.
 *   3. `KUZUSHI_HIGH_CONTRAST=1` forces `bright` + bold variants and
 *      strips dim/gray text (handled in tokens.ts, covered in a
 *      separate test below).
 *   4. `normalizeSeverity` accepts raw scanner tier strings and
 *      canonicalizes them.
 */

import chalk from "chalk";
import { describe, expect, it } from "vitest";
import {
  isHighContrast,
  isNoColor,
  normalizeSeverity,
  SEVERITY_ORDER,
  type Severity,
  severityChalk,
  severityRank,
  severityStyle,
  severityToken,
} from "../../src/ui/severity.js";

// Tests run under vitest where stdout isn't a TTY, so chalk auto-detects
// level=0 and emits no ANSI. Force color on so we can assert ANSI output.
chalk.level = Math.max(chalk.level, 1);

const ALL: Severity[] = ["critical", "high", "medium", "low", "info"];

describe("severityStyle — default palette", () => {
  it("returns a {color, bold, glyph, label, longLabel} for every tier", () => {
    for (const sev of ALL) {
      const s = severityStyle(sev, {});
      expect(typeof s.glyph).toBe("string");
      expect(s.glyph.length).toBeGreaterThan(0);
      expect(typeof s.label).toBe("string");
      expect(s.label.length).toBeGreaterThan(0);
      expect(typeof s.longLabel).toBe("string");
      expect(s.color).toBeDefined();
    }
  });

  it("uses distinct glyphs per tier so readers see shape differences", () => {
    const glyphs = new Set(ALL.map((sev) => severityStyle(sev, {}).glyph));
    expect(glyphs.size).toBe(ALL.length);
  });

  it("uses distinct labels per tier", () => {
    const labels = new Set(ALL.map((sev) => severityStyle(sev, {}).longLabel));
    expect(labels.size).toBe(ALL.length);
  });

  it("bolds only critical in the default palette (other tiers unbold)", () => {
    expect(severityStyle("critical", {}).bold).toBe(true);
    expect(severityStyle("high", {}).bold).toBe(false);
    expect(severityStyle("medium", {}).bold).toBe(false);
    expect(severityStyle("low", {}).bold).toBe(false);
    expect(severityStyle("info", {}).bold).toBe(false);
  });

  it("picks an Okabe-Ito friendly color — not default white — for every tier", () => {
    for (const sev of ALL) {
      const s = severityStyle(sev, {});
      expect(s.color).not.toBe("white");
      expect(s.color).not.toBe("gray");
    }
  });
});

describe("severityStyle — NO_COLOR", () => {
  it("drops color when NO_COLOR is set to any non-empty value", () => {
    for (const sev of ALL) {
      expect(severityStyle(sev, { NO_COLOR: "1" }).color).toBeUndefined();
      expect(severityStyle(sev, { NO_COLOR: "true" }).color).toBeUndefined();
      // arbitrary non-empty — spec-compliant
      expect(severityStyle(sev, { NO_COLOR: "yes" }).color).toBeUndefined();
    }
  });

  it("keeps glyph+label intact under NO_COLOR", () => {
    const s = severityStyle("high", { NO_COLOR: "1" });
    expect(s.glyph.length).toBeGreaterThan(0);
    expect(s.label).toBe("HIGH");
  });

  it("treats empty NO_COLOR as unset (per no-color.org)", () => {
    expect(severityStyle("high", { NO_COLOR: "" }).color).toBeDefined();
  });

  it("isNoColor reflects env", () => {
    expect(isNoColor({ NO_COLOR: "1" })).toBe(true);
    expect(isNoColor({ NO_COLOR: "" })).toBe(false);
    expect(isNoColor({})).toBe(false);
  });
});

describe("severityStyle — KUZUSHI_HIGH_CONTRAST", () => {
  it("forces bold for every tier", () => {
    for (const sev of ALL) {
      expect(severityStyle(sev, { KUZUSHI_HIGH_CONTRAST: "1" }).bold).toBe(true);
    }
  });

  it("upgrades to *Bright color variants", () => {
    // Spot-check: medium should move from `yellow` → `yellowBright`.
    expect(severityStyle("medium", {}).color).toBe("yellow");
    expect(severityStyle("medium", { KUZUSHI_HIGH_CONTRAST: "1" }).color).toBe("yellowBright");
    // info (blue → blueBright)
    expect(severityStyle("info", {}).color).toBe("blue");
    expect(severityStyle("info", { KUZUSHI_HIGH_CONTRAST: "1" }).color).toBe("blueBright");
  });

  it("accepts truthy strings (1/true/yes/on, case-insensitive)", () => {
    expect(isHighContrast({ KUZUSHI_HIGH_CONTRAST: "1" })).toBe(true);
    expect(isHighContrast({ KUZUSHI_HIGH_CONTRAST: "TRUE" })).toBe(true);
    expect(isHighContrast({ KUZUSHI_HIGH_CONTRAST: "Yes" })).toBe(true);
    expect(isHighContrast({ KUZUSHI_HIGH_CONTRAST: "on" })).toBe(true);
  });

  it("ignores empty/unset/false values", () => {
    expect(isHighContrast({})).toBe(false);
    expect(isHighContrast({ KUZUSHI_HIGH_CONTRAST: "" })).toBe(false);
    expect(isHighContrast({ KUZUSHI_HIGH_CONTRAST: "0" })).toBe(false);
    expect(isHighContrast({ KUZUSHI_HIGH_CONTRAST: "false" })).toBe(false);
  });
});

describe("severityStyle — NO_COLOR beats KUZUSHI_HIGH_CONTRAST", () => {
  it("drops color even when both are set (NO_COLOR wins)", () => {
    const s = severityStyle("critical", { NO_COLOR: "1", KUZUSHI_HIGH_CONTRAST: "1" });
    expect(s.color).toBeUndefined();
    // Bold is still on — that's fine, bold is a weight not a color.
    expect(s.bold).toBe(true);
  });
});

describe("severityToken / severityChalk", () => {
  it("severityToken pairs glyph + label", () => {
    for (const sev of ALL) {
      const tok = severityToken(sev, {});
      const s = severityStyle(sev, {});
      expect(tok).toContain(s.glyph);
      expect(tok).toContain(s.label);
    }
  });

  it("severityChalk returns identity under NO_COLOR", () => {
    const fn = severityChalk("critical", { NO_COLOR: "1" });
    expect(fn("CRIT")).toBe("CRIT");
  });

  it("severityChalk applies ANSI codes when color is on", () => {
    const fn = severityChalk("critical", {});
    const out = fn("CRIT");
    // The wrapped string should contain at least one ANSI escape
    // when color is enabled — without depending on a specific color code.
    // biome-ignore lint/suspicious/noControlCharactersInRegex: ESC is intentional
    expect(/\[[0-9;]+m/.test(out)).toBe(true);
    expect(out).toContain("CRIT");
  });
});

describe("normalizeSeverity", () => {
  it("maps scanner tiers", () => {
    expect(normalizeSeverity("CRITICAL")).toBe("critical");
    expect(normalizeSeverity("critical")).toBe("critical");
    expect(normalizeSeverity("crit")).toBe("critical");
    expect(normalizeSeverity("HIGH")).toBe("high");
    expect(normalizeSeverity("ERROR")).toBe("high");
    expect(normalizeSeverity("MEDIUM")).toBe("medium");
    expect(normalizeSeverity("WARNING")).toBe("medium");
    expect(normalizeSeverity("low")).toBe("low");
    expect(normalizeSeverity("INFO")).toBe("info");
  });

  it("returns info for unknown / empty inputs", () => {
    expect(normalizeSeverity("")).toBe("info");
    expect(normalizeSeverity(undefined)).toBe("info");
    expect(normalizeSeverity(null)).toBe("info");
    expect(normalizeSeverity("flerpbloop")).toBe("info");
  });
});

describe("SEVERITY_ORDER / severityRank", () => {
  it("critical outranks (is less than) all others", () => {
    for (const sev of ALL) {
      if (sev === "critical") continue;
      expect(severityRank("critical")).toBeLessThan(severityRank(sev));
    }
  });

  it("info is the lowest rank", () => {
    expect(severityRank("info")).toBe(ALL.length - 1);
  });

  it("SEVERITY_ORDER exposes all five tiers in descending severity", () => {
    expect(SEVERITY_ORDER).toEqual(["critical", "high", "medium", "low", "info"]);
  });
});
