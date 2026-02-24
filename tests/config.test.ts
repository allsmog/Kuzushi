import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import path from "node:path";

const TMP_HOME = path.join(import.meta.dirname, ".tmp-config-test");
const TMP_CONFIG_DIR = path.join(TMP_HOME, ".kuzushi");
const TMP_CONFIG_PATH = path.join(TMP_CONFIG_DIR, "config.json");
const TMP_REPO = path.join(TMP_HOME, "repo");
const TMP_PROJECT_CONFIG_PATH = path.join(TMP_REPO, ".kuzushi", "config.json");

vi.mock("node:os", () => ({
  default: { homedir: () => TMP_HOME },
  homedir: () => TMP_HOME,
}));

const {
  loadConfig,
  saveConfig,
  getConfigValue,
  setConfigValue,
  unsetConfigValue,
  configPath,
  projectConfigPath,
  DEFAULTS,
} = await import("../src/config.js");

beforeEach(() => {
  mkdirSync(TMP_CONFIG_DIR, { recursive: true });
  mkdirSync(path.dirname(TMP_PROJECT_CONFIG_PATH), { recursive: true });
});

afterEach(() => {
  rmSync(TMP_HOME, { recursive: true, force: true });
});

describe("loadConfig", () => {
  it("returns defaults when no config files exist", () => {
    rmSync(TMP_CONFIG_PATH, { force: true });
    rmSync(TMP_PROJECT_CONFIG_PATH, { force: true });

    const config = loadConfig();
    expect(config.model).toBe(DEFAULTS.model);
    expect(config.busBackend).toBe(DEFAULTS.busBackend);
    expect(config.triageConcurrency).toBe(DEFAULTS.triageConcurrency);
    expect(config.scanMode).toBe(DEFAULTS.scanMode);
    expect(config.triageMaxTurns).toBe(DEFAULTS.triageMaxTurns);
    expect(config.triageModel).toBeUndefined();
    expect(config.scanners).toEqual(DEFAULTS.scanners);
  });

  it("merges global config over defaults", () => {
    writeFileSync(TMP_CONFIG_PATH, JSON.stringify({ model: "custom-model", triageModel: "triage-model" }));
    const config = loadConfig();
    expect(config.model).toBe("custom-model");
    expect(config.triageModel).toBe("triage-model");
  });

  it("applies project-level override when repoRoot is provided", () => {
    writeFileSync(TMP_CONFIG_PATH, JSON.stringify({ model: "global-model", scanners: ["semgrep"] }));
    writeFileSync(TMP_PROJECT_CONFIG_PATH, JSON.stringify({ model: "project-model", scanners: ["claude-adk"] }));

    const config = loadConfig(TMP_REPO);
    expect(config.model).toBe("project-model");
    expect(config.scanners).toEqual(["claude-adk"]);
  });

  it("returns defaults for malformed JSON", () => {
    writeFileSync(TMP_CONFIG_PATH, "not json {{{");
    const config = loadConfig();
    expect(config.model).toBe(DEFAULTS.model);
  });

  it("throws for invalid busBackend values from config files", () => {
    writeFileSync(TMP_CONFIG_PATH, JSON.stringify({ busBackend: "reddis" }));
    expect(() => loadConfig()).toThrow("Invalid busBackend");
  });
});

describe("saveConfig", () => {
  it("writes global config to disk", () => {
    const config = { ...DEFAULTS, model: "saved-model" };
    saveConfig(config);
    const raw = JSON.parse(readFileSync(TMP_CONFIG_PATH, "utf-8"));
    expect(raw.model).toBe("saved-model");
  });

  it("writes project config when repoRoot is provided", () => {
    const config = { ...DEFAULTS, model: "project-saved" };
    saveConfig(config, TMP_REPO);
    const raw = JSON.parse(readFileSync(TMP_PROJECT_CONFIG_PATH, "utf-8"));
    expect(raw.model).toBe("project-saved");
  });

  it("creates config dir if missing", () => {
    rmSync(TMP_CONFIG_DIR, { recursive: true, force: true });
    saveConfig(DEFAULTS);
    expect(existsSync(TMP_CONFIG_PATH)).toBe(true);
  });
});

describe("getConfigValue", () => {
  it("returns a specific top-level value", () => {
    writeFileSync(TMP_CONFIG_PATH, JSON.stringify({ model: "get-test" }));
    expect(getConfigValue("model")).toBe("get-test");
  });

  it("returns nested scannerConfig values", () => {
    writeFileSync(TMP_CONFIG_PATH, JSON.stringify({ scannerConfig: { semgrep: { binary: "opengrep" } } }));
    expect(getConfigValue("scannerConfig.semgrep.binary")).toBe("opengrep");
  });

  it("returns undefined for unknown keys", () => {
    expect(getConfigValue("nonexistent")).toBeUndefined();
  });
});

describe("setConfigValue", () => {
  it("sets a string value", () => {
    setConfigValue("model", "new-model");
    expect(getConfigValue("model")).toBe("new-model");
  });

  it("sets triageModel", () => {
    setConfigValue("triageModel", "claude-opus-4-20250514");
    expect(getConfigValue("triageModel")).toBe("claude-opus-4-20250514");
  });

  it("sets number values", () => {
    setConfigValue("triageConcurrency", "3");
    setConfigValue("triageMaxTurns", "15");
    expect(getConfigValue("triageConcurrency")).toBe(3);
    expect(getConfigValue("triageMaxTurns")).toBe(15);
  });

  it("sets scanMode", () => {
    setConfigValue("scanMode", "concurrent");
    expect(getConfigValue("scanMode")).toBe("concurrent");
  });

  it("sets busBackend", () => {
    setConfigValue("busBackend", "in-process");
    expect(getConfigValue("busBackend")).toBe("in-process");
  });

  it("sets agentRuntimeBackend", () => {
    setConfigValue("agentRuntimeBackend", "claude-sdk");
    expect(getConfigValue("agentRuntimeBackend")).toBe("claude-sdk");
  });

  it("sets scanners from comma-separated string", () => {
    setConfigValue("scanners", "semgrep,custom-scanner");
    expect(getConfigValue("scanners")).toEqual(["semgrep", "custom-scanner"]);
  });

  it("sets nested scannerConfig values", () => {
    setConfigValue("scannerConfig.semgrep.binary", "opengrep");
    expect(getConfigValue("scannerConfig.semgrep.binary")).toBe("opengrep");
  });

  it("throws on unknown top-level key", () => {
    expect(() => setConfigValue("bogus", "val")).toThrow("Unknown config key");
  });

  it("throws on invalid numeric values", () => {
    expect(() => setConfigValue("triageMaxTurns", "0")).toThrow("triageMaxTurns must be a positive number");
  });

  it("throws on invalid scanMode", () => {
    expect(() => setConfigValue("scanMode", "parallel")).toThrow("scanMode must be one of");
  });

  it("throws on invalid busBackend", () => {
    expect(() => setConfigValue("busBackend", "reddis")).toThrow("busBackend must be one of");
  });

  it("throws on invalid agentRuntimeBackend", () => {
    expect(() => setConfigValue("agentRuntimeBackend", "anthropic")).toThrow(
      "agentRuntimeBackend must be one of",
    );
  });
});

describe("unsetConfigValue", () => {
  it("resets a key to its default", () => {
    setConfigValue("model", "custom");
    expect(getConfigValue("model")).toBe("custom");
    unsetConfigValue("model");
    expect(getConfigValue("model")).toBe(DEFAULTS.model);
  });

  it("unsets optional triageModel", () => {
    setConfigValue("triageModel", "claude-opus-4-20250514");
    expect(getConfigValue("triageModel")).toBe("claude-opus-4-20250514");
    unsetConfigValue("triageModel");
    expect(getConfigValue("triageModel")).toBeUndefined();
  });

  it("removes nested key", () => {
    setConfigValue("scannerConfig.semgrep.binary", "opengrep");
    unsetConfigValue("scannerConfig.semgrep.binary");
    expect(getConfigValue("scannerConfig.semgrep.binary")).toBeUndefined();
  });

  it("throws on unknown key", () => {
    expect(() => unsetConfigValue("bogus")).toThrow("Unknown config key");
  });
});

describe("paths", () => {
  it("returns global config path", () => {
    expect(configPath()).toMatch(/config\.json$/);
  });

  it("returns project config path", () => {
    expect(projectConfigPath(TMP_REPO)).toBe(TMP_PROJECT_CONFIG_PATH);
  });
});
