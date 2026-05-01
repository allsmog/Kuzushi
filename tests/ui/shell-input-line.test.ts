import { describe, expect, it } from "vitest";
import { renderShellInputSegments } from "../../src/ui/shell-input-line.js";

function renderText(parts: ReturnType<typeof renderShellInputSegments>): string {
  return parts.prompt + parts.beforeCursor + parts.cursorText + parts.afterCursor;
}

describe("renderShellInputSegments", () => {
  it("keeps short focused-module input inline", () => {
    const parts = renderShellInputSegments({
      prompt: "kuzushi carlini-threat-hunt > ",
      input: "us",
      cursor: 2,
      columns: 80,
      cursorGlyph: "█",
    });

    expect(parts).toEqual({
      prompt: "kuzushi carlini-threat-hunt > ",
      beforeCursor: "us",
      cursorText: "█",
      afterCursor: "",
    });
  });

  it("horizontally scrolls long input instead of exceeding the terminal width", () => {
    const parts = renderShellInputSegments({
      prompt: "kuzushi carlini-threat-hunt > ",
      input: `run ${"x".repeat(80)}`,
      cursor: 84,
      columns: 32,
      cursorGlyph: "█",
    });

    const rendered = renderText(parts);
    expect(rendered).toHaveLength(32);
    expect(rendered.endsWith("█")).toBe(true);
    expect(parts.prompt).toBe("kuzushi carlini-threat-hunt > ");
  });

  it("fits very long module prompts while preserving an editor cell", () => {
    const parts = renderShellInputSegments({
      prompt: "kuzushi really-long-carlini-threat-hunting-module > ",
      input: "u",
      cursor: 1,
      columns: 20,
      cursorGlyph: "█",
    });

    const rendered = renderText(parts);
    expect(rendered).toHaveLength(20);
    expect(parts.prompt.endsWith("> ")).toBe(true);
    expect(rendered.endsWith("u█")).toBe(true);
  });

  it("keeps the active character under the cursor visible", () => {
    const parts = renderShellInputSegments({
      prompt: "kuzushi > ",
      input: "abcdef",
      cursor: 2,
      columns: 80,
      cursorGlyph: "█",
    });

    expect(parts.beforeCursor).toBe("ab");
    expect(parts.cursorText).toBe("c");
    expect(parts.afterCursor).toBe("def");
  });
});
