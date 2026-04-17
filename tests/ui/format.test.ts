import { describe, expect, it } from "vitest";
import {
  type Align,
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
