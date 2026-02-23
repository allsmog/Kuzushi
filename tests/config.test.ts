import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import path from "node:path";

// Redirect config to a temp dir so tests don't touch real ~/.kuzushi
const TMP_HOME = path.join(import.meta.dirname, ".tmp-config-test");
const TMP_CONFIG_DIR = path.join(TMP_HOME, ".kuzushi");
const TMP_CONFIG_PATH = path.join(TMP_CONFIG_DIR, "config.json");

// Mock os.homedir before importing config
vi.mock("node:os", () => ({
  default: { homedir: () => TMP_HOME },
  homedir: () => TMP_HOME,
}));

// Import after mock is set up
const { loadConfig, saveConfig, getConfigValue, setConfigValue, unsetConfigValue, configPath, DEFAULTS } =
  await import("../src/config.js");

beforeEach(() => {
  mkdirSync(TMP_CONFIG_DIR, { recursive: true });
});

afterEach(() => {
  rmSync(TMP_HOME, { recursive: true, force: true });
});

describe("loadConfig", () => {
  it("returns defaults when no config file exists", () => {
    rmSync(TMP_CONFIG_PATH, { force: true });
    const config = loadConfig();
    expect(config.model).toBe(DEFAULTS.model);
    expect(config.maxTokens).toBe(DEFAULTS.maxTokens);
    expect(config.severity).toEqual(DEFAULTS.severity);
  });

  it("merges config file over defaults", () => {
    writeFileSync(TMP_CONFIG_PATH, JSON.stringify({ model: "custom-model" }));
    const config = loadConfig();
    expect(config.model).toBe("custom-model");
    // Other fields should still have defaults
    expect(config.maxTokens).toBe(DEFAULTS.maxTokens);
  });

  it("ignores unknown keys in config file", () => {
    writeFileSync(TMP_CONFIG_PATH, JSON.stringify({ model: "x", bogusKey: true }));
    const config = loadConfig();
    expect(config.model).toBe("x");
    expect((config as Record<string, unknown>)["bogusKey"]).toBeUndefined();
  });

  it("returns defaults for malformed JSON", () => {
    writeFileSync(TMP_CONFIG_PATH, "not json {{{");
    const config = loadConfig();
    expect(config.model).toBe(DEFAULTS.model);
  });
});

describe("saveConfig", () => {
  it("writes config to disk", () => {
    const config = { ...DEFAULTS, model: "saved-model" };
    saveConfig(config);
    const raw = JSON.parse(readFileSync(TMP_CONFIG_PATH, "utf-8"));
    expect(raw.model).toBe("saved-model");
  });

  it("creates config dir if missing", () => {
    rmSync(TMP_CONFIG_DIR, { recursive: true, force: true });
    saveConfig(DEFAULTS);
    expect(existsSync(TMP_CONFIG_PATH)).toBe(true);
  });
});

describe("getConfigValue", () => {
  it("returns a specific value", () => {
    writeFileSync(TMP_CONFIG_PATH, JSON.stringify({ model: "get-test" }));
    expect(getConfigValue("model")).toBe("get-test");
  });

  it("returns undefined for unknown keys", () => {
    expect(getConfigValue("nonexistent")).toBeUndefined();
  });

  it("returns arrays correctly", () => {
    writeFileSync(TMP_CONFIG_PATH, JSON.stringify({ severity: ["ERROR"] }));
    expect(getConfigValue("severity")).toEqual(["ERROR"]);
  });
});

describe("setConfigValue", () => {
  it("sets a string value", () => {
    setConfigValue("model", "new-model");
    expect(getConfigValue("model")).toBe("new-model");
  });

  it("sets a number value", () => {
    setConfigValue("maxTokens", "2048");
    expect(getConfigValue("maxTokens")).toBe(2048);
  });

  it("sets an array from comma-separated string", () => {
    setConfigValue("severity", "ERROR,WARNING,INFO");
    expect(getConfigValue("severity")).toEqual(["ERROR", "WARNING", "INFO"]);
  });

  it("sets an array from JSON", () => {
    setConfigValue("severity", '["ERROR"]');
    expect(getConfigValue("severity")).toEqual(["ERROR"]);
  });

  it("throws on unknown key", () => {
    expect(() => setConfigValue("bogus", "val")).toThrow("Unknown config key");
  });

  it("throws on non-numeric value for number field", () => {
    expect(() => setConfigValue("maxTokens", "abc")).toThrow("must be a number");
  });
});

describe("unsetConfigValue", () => {
  it("resets a key to its default", () => {
    setConfigValue("model", "custom");
    expect(getConfigValue("model")).toBe("custom");
    unsetConfigValue("model");
    expect(getConfigValue("model")).toBe(DEFAULTS.model);
  });

  it("throws on unknown key", () => {
    expect(() => unsetConfigValue("bogus")).toThrow("Unknown config key");
  });
});

describe("configPath", () => {
  it("returns a path ending with config.json", () => {
    expect(configPath()).toMatch(/config\.json$/);
  });
});
