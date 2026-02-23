import { describe, it, expect, vi } from "vitest";
import { DEFAULTS } from "../src/config.js";

// Mock the scanner resolver so it doesn't hit the filesystem/network
vi.mock("../src/scanner/resolve.js", () => ({
  resolveScanner: vi.fn().mockResolvedValue("/usr/bin/semgrep"),
}));

const { createDefaultDeps } = await import("../src/deps.js");

describe("createDefaultDeps", () => {
  it("returns an object with the expected methods", async () => {
    const deps = await createDefaultDeps(DEFAULTS);
    expect(typeof deps.runScanner).toBe("function");
    expect(typeof deps.triageFinding).toBe("function");
    expect(typeof deps.readFileContext).toBe("function");
  });

  it("readFileContext is the real implementation", async () => {
    const deps = await createDefaultDeps(DEFAULTS);
    const result = await deps.readFileContext("/nonexistent/file.ts", 1, 5);
    expect(result).toContain("Could not read file");
  });

  it("accepts a custom LLM client", async () => {
    const mockLLM = { complete: async () => "{}" };
    const deps = await createDefaultDeps(DEFAULTS, mockLLM);
    expect(typeof deps.triageFinding).toBe("function");
  });
});
