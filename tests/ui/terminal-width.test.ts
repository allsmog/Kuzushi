/**
 * Pure-helper tests for terminal-width classification. The live hook
 * (`useTerminalWidth`) is exercised indirectly via component snapshots
 * under `tests/ui/accessibility.test.tsx`.
 */
import { describe, expect, it } from "vitest";
import { classifyTerminalWidth } from "../../src/ui/hooks.js";

describe("classifyTerminalWidth", () => {
  it("classifies tiny (<60)", () => {
    expect(classifyTerminalWidth(40)).toBe("tiny");
    expect(classifyTerminalWidth(59)).toBe("tiny");
  });

  it("classifies narrow (60..79)", () => {
    expect(classifyTerminalWidth(60)).toBe("narrow");
    expect(classifyTerminalWidth(70)).toBe("narrow");
    expect(classifyTerminalWidth(79)).toBe("narrow");
  });

  it("classifies standard (80..119)", () => {
    expect(classifyTerminalWidth(80)).toBe("standard");
    expect(classifyTerminalWidth(100)).toBe("standard");
    expect(classifyTerminalWidth(119)).toBe("standard");
  });

  it("classifies wide (>=120)", () => {
    expect(classifyTerminalWidth(120)).toBe("wide");
    expect(classifyTerminalWidth(200)).toBe("wide");
  });
});
