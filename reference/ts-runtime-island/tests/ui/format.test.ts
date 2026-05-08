import { describe, expect, it } from "vitest";
import {
  type Align,
  formatContextAge,
  formatFindingsSummary,
  formatRelativeAgo,
  padCell,
  truncateEnd,
  truncateMiddle,
  visibleWidth,
  wrapToWidth,
} from "../../src/ui/format.js";

describe("visibleWidth", () => {
  it("counts plain characters", () => {
    expect(visibleWidth("hello")).toBe(5);
    expect(visibleWidth("")).toBe(0);
  });
  it("strips ANSI escape codes", () => {
    expect(visibleWidth("\u001b[31mred\u001b[0m")).toBe(3);
  });
});

describe("truncateEnd", () => {
  it("returns untouched when within width", () => {
    expect(truncateEnd("short", 10)).toBe("short");
  });
  it("truncates with ellipsis", () => {
    expect(truncateEnd("abcdefghij", 5)).toBe("abcd\u2026");
  });
  it("handles tiny widths", () => {
    expect(truncateEnd("abcdef", 1)).toBe("\u2026");
  });
});

describe("truncateMiddle", () => {
  it("returns untouched when within width", () => {
    expect(truncateMiddle("src/file.ts", 20)).toBe("src/file.ts");
  });
  it("preserves basename for path strings", () => {
    const out = truncateMiddle("src/ui/components/CopilotShell.tsx", 22);
    expect(out.endsWith("/CopilotShell.tsx")).toBe(true);
    expect(out).toContain("\u2026");
    expect(out.length).toBeLessThanOrEqual(22);
  });
  it("falls back to center-truncate for non-path strings", () => {
    const out = truncateMiddle("abcdefghijklmnop", 9);
    expect(out).toContain("\u2026");
    expect(out.length).toBe(9);
  });
  it("handles zero width gracefully", () => {
    expect(truncateMiddle("whatever", 0)).toBe("");
  });
});

describe("padCell", () => {
  const cases: ReadonlyArray<{ align: Align; input: string; width: number; expected: string }> = [
    { align: "left", input: "ab", width: 5, expected: "ab   " },
    { align: "right", input: "ab", width: 5, expected: "   ab" },
    { align: "center", input: "ab", width: 6, expected: "  ab  " },
  ];
  for (const { align, input, width, expected } of cases) {
    it(`pads ${align}`, () => {
      expect(padCell(input, width, align)).toBe(expected);
    });
  }
  it("returns string unchanged when already wider", () => {
    expect(padCell("toolong", 3)).toBe("toolong");
  });
  it("respects ANSI width when measuring", () => {
    const colored = "\u001b[31mab\u001b[0m";
    expect(padCell(colored, 5, "right")).toBe(`   ${colored}`);
  });
});

describe("formatRelativeAgo", () => {
  const now = 1_700_000_000_000;
  it("renders 'just now' within 5 seconds", () => {
    expect(formatRelativeAgo(now, now)).toBe("just now");
    expect(formatRelativeAgo(now - 4_999, now)).toBe("just now");
  });
  it("renders seconds between 5 and 59", () => {
    expect(formatRelativeAgo(now - 5_000, now)).toBe("5s ago");
    expect(formatRelativeAgo(now - 42_000, now)).toBe("42s ago");
    expect(formatRelativeAgo(now - 59_999, now)).toBe("59s ago");
  });
  it("renders minutes past 60s", () => {
    expect(formatRelativeAgo(now - 60_000, now)).toBe("1m ago");
    expect(formatRelativeAgo(now - 72_000, now)).toBe("1m 12s ago");
    expect(formatRelativeAgo(now - 3_599_000, now)).toBe("59m 59s ago");
  });
  it("renders hours past 60m", () => {
    expect(formatRelativeAgo(now - 3_600_000, now)).toBe("1h ago");
    expect(formatRelativeAgo(now - 4_200_000, now)).toBe("1h 10m ago");
  });
  it("clamps negative deltas to 'just now'", () => {
    expect(formatRelativeAgo(now + 5_000, now)).toBe("just now");
  });
});

describe("wrapToWidth", () => {
  it("returns empty array for empty string", () => {
    expect(wrapToWidth("", 10)).toEqual([]);
  });
  it("returns one line when text fits", () => {
    expect(wrapToWidth("hello world", 20)).toEqual(["hello world"]);
  });
  it("wraps on word boundaries", () => {
    expect(wrapToWidth("one two three four", 8)).toEqual(["one two", "three", "four"]);
  });
  it("keeps words longer than maxWidth on their own line", () => {
    expect(wrapToWidth("short supercalifragilistic tail", 10)).toEqual([
      "short",
      "supercalifragilistic",
      "tail",
    ]);
  });
  it("handles zero or negative maxWidth by returning the text as one line", () => {
    expect(wrapToWidth("hello world", 0)).toEqual(["hello world"]);
    expect(wrapToWidth("", 0)).toEqual([]);
  });
  it("collapses runs of whitespace", () => {
    expect(wrapToWidth("one   two    three", 40)).toEqual(["one two three"]);
  });
});

describe("formatContextAge", () => {
  it("renders missing without an age", () => {
    expect(formatContextAge("missing")).toBe("ctx: none");
  });
  it("renders building without an age", () => {
    expect(formatContextAge("building")).toBe("ctx: building…");
  });
  it("buckets seconds → s", () => {
    expect(formatContextAge("fresh", 12_000)).toBe("ctx: fresh 12s");
  });
  it("buckets minutes → m", () => {
    expect(formatContextAge("fresh", 4 * 60_000 + 12_000)).toBe("ctx: fresh 4m");
  });
  it("buckets hours → h", () => {
    expect(formatContextAge("stale", 2 * 3_600_000)).toBe("ctx: stale 2h");
  });
  it("buckets days → d once past 24h", () => {
    expect(formatContextAge("stale", 3 * 86_400_000)).toBe("ctx: stale 3d");
  });
  it("falls back to bare label when ageMs is missing for a known state", () => {
    expect(formatContextAge("fresh")).toBe("ctx: fresh");
  });
  it("treats negative ageMs as a missing age", () => {
    expect(formatContextAge("fresh", -1)).toBe("ctx: fresh");
  });
});

describe("formatFindingsSummary", () => {
  it("renders empty when total is zero", () => {
    expect(formatFindingsSummary({ total: 0 })).toBe("no findings");
  });
  it("uses the highest non-zero severity tier", () => {
    expect(
      formatFindingsSummary({
        total: 7,
        bySeverity: { high: 1, medium: 2, low: 4 },
      }),
    ).toBe("7 findings (1 high)");
  });
  it("prefers critical over high", () => {
    expect(
      formatFindingsSummary({
        total: 5,
        bySeverity: { critical: 1, high: 2, medium: 2 },
      }),
    ).toBe("5 findings (1 critical)");
  });
  it("falls back to plain count when bySeverity is empty", () => {
    expect(formatFindingsSummary({ total: 3 })).toBe("3 findings");
  });
  it("ignores zero-count tiers", () => {
    expect(
      formatFindingsSummary({
        total: 4,
        bySeverity: { critical: 0, high: 0, medium: 4 },
      }),
    ).toBe("4 findings (4 medium)");
  });
});
