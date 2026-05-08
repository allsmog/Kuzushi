import * as path from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.js";

describe("config security", () => {
  it("loadConfig returns defaults for non-existent repo", () => {
    const config = loadConfig("/nonexistent/repo/path");
    expect(typeof config.model).toBe("string");
    expect(config.busBackend).toBe("in-process");
  });

  it("loadConfig returns valid config for current directory", () => {
    const config = loadConfig(path.resolve("."));
    expect(config).toBeDefined();
    expect(typeof config.model).toBe("string");
  });
});
