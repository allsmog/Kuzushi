import { describe, expect, it } from "vitest";
import {
  type Align,
  formatRelativeAgo,
  padCell,
  truncateEnd,
  truncateMiddle,
  visibleWidth,
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
