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
    expect(config.verify).toBe(DEFAULTS.verify);
    expect(config.verifyMaxTurns).toBe(DEFAULTS.verifyMaxTurns);
    expect(config.verifyConcurrency).toBe(DEFAULTS.verifyConcurrency);
    expect(config.verifyVerdicts).toEqual(DEFAULTS.verifyVerdicts);
    expect(config.verifyMinConfidence).toBe(DEFAULTS.verifyMinConfidence);
    expect(config.enableContextGathering).toBe(DEFAULTS.enableContextGathering);
    expect(config.auditLog).toBe(DEFAULTS.auditLog);
    expect(config.sarifOutput).toBe(DEFAULTS.sarifOutput);
    expect(config.maxTriageRetries).toBe(DEFAULTS.maxTriageRetries);
    expect(config.maxVerifyRetries).toBe(DEFAULTS.maxVerifyRetries);
    expect(config.retryBackoffMs).toBe(DEFAULTS.retryBackoffMs);
    expect(config.retryBackoffMultiplier).toBe(DEFAULTS.retryBackoffMultiplier);
    expect(config.scanners).toEqual(DEFAULTS.scanners);
  });

  it("merges global config over defaults", () => {
    writeFileSync(TMP_CONFIG_PATH, JSON.stringify({
      model: "custom-model",
      triageModel: "triage-model",
      verify: true,
      verifyModel: "verify-model",
      verifyMaxTurns: 25,
      verifyConcurrency: 2,
      verifyVerdicts: ["tp", "needs_review"],
      verifyMinConfidence: 0.7,
      enableContextGathering: false,
      auditLog: true,
      reportOutput: "/tmp/report.md",
      sarifOutput: "/tmp/report.sarif",
      maxTriageRetries: 4,
      maxVerifyRetries: 5,
      retryBackoffMs: 2000,
      retryBackoffMultiplier: 3,
      scannerConfig: { semgrep: { verify: false } },
    }));
    const config = loadConfig();
    expect(config.model).toBe("custom-model");
    expect(config.triageModel).toBe("triage-model");
    expect(config.verify).toBe(true);
    expect(config.verifyModel).toBe("verify-model");
    expect(config.verifyMaxTurns).toBe(25);
    expect(config.verifyConcurrency).toBe(2);
    expect(config.verifyVerdicts).toEqual(["tp", "needs_review"]);
    expect(config.verifyMinConfidence).toBe(0.7);
    expect(config.enableContextGathering).toBe(false);
    expect(config.auditLog).toBe(true);
    expect(config.reportOutput).toBe("/tmp/report.md");
    expect(config.sarifOutput).toBe("/tmp/report.sarif");
    expect(config.maxTriageRetries).toBe(4);
    expect(config.maxVerifyRetries).toBe(5);
    expect(config.retryBackoffMs).toBe(2000);
    expect(config.retryBackoffMultiplier).toBe(3);
    expect(config.scannerConfig.semgrep?.verify).toBe(false);
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

  it("sets verify settings", () => {
    setConfigValue("verify", "true");
    setConfigValue("verifyModel", "claude-haiku-4-5-20251001");
    setConfigValue("verifyMaxTurns", "20");
    setConfigValue("verifyConcurrency", "3");
    setConfigValue("verifyVerdicts", "tp,needs_review");

    expect(getConfigValue("verify")).toBe(true);
    expect(getConfigValue("verifyModel")).toBe("claude-haiku-4-5-20251001");
    expect(getConfigValue("verifyMaxTurns")).toBe(20);
    expect(getConfigValue("verifyConcurrency")).toBe(3);
    expect(getConfigValue("verifyVerdicts")).toEqual(["tp", "needs_review"]);
  });

  it("sets confidence gate, context, audit, and retry settings", () => {
    setConfigValue("verifyMinConfidence", "0.6");
    setConfigValue("enableContextGathering", "false");
    setConfigValue("auditLog", "true");
    setConfigValue("reportOutput", "report.md");
    setConfigValue("sarifOutput", "report.sarif");
    setConfigValue("maxTriageRetries", "3");
    setConfigValue("maxVerifyRetries", "4");
    setConfigValue("retryBackoffMs", "1200");
    setConfigValue("retryBackoffMultiplier", "2.5");

    expect(getConfigValue("verifyMinConfidence")).toBe(0.6);
    expect(getConfigValue("enableContextGathering")).toBe(false);
    expect(getConfigValue("auditLog")).toBe(true);
    expect(getConfigValue("reportOutput")).toBe("report.md");
    expect(getConfigValue("sarifOutput")).toBe("report.sarif");
    expect(getConfigValue("maxTriageRetries")).toBe(3);
    expect(getConfigValue("maxVerifyRetries")).toBe(4);
    expect(getConfigValue("retryBackoffMs")).toBe(1200);
    expect(getConfigValue("retryBackoffMultiplier")).toBe(2.5);
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

  it("sets nested scanner verify flag values", () => {
    setConfigValue("scannerConfig.semgrep.verify", "false");
    expect(getConfigValue("scannerConfig.semgrep.verify")).toBe(false);
  });

  it("throws on unknown top-level key", () => {
    expect(() => setConfigValue("bogus", "val")).toThrow("Unknown config key");
  });

  it("throws on invalid numeric values", () => {
    expect(() => setConfigValue("triageMaxTurns", "0")).toThrow("triageMaxTurns must be a positive number");
  });

  it("throws on invalid verify values", () => {
    expect(() => setConfigValue("verify", "maybe")).toThrow("verify must be true or false");
    expect(() => setConfigValue("verifyMaxTurns", "0")).toThrow("verifyMaxTurns must be a positive number");
    expect(() => setConfigValue("verifyConcurrency", "0")).toThrow("verifyConcurrency must be a positive number");
    expect(() => setConfigValue("verifyVerdicts", "foo")).toThrow(
      "verifyVerdicts must contain only: tp, fp, needs_review",
    );
    expect(() => setConfigValue("verifyMinConfidence", "1.4")).toThrow(
      "verifyMinConfidence must be a number between 0 and 1",
    );
  });

  it("throws on invalid context/audit/retry values", () => {
    expect(() => setConfigValue("enableContextGathering", "maybe")).toThrow(
      "enableContextGathering must be true or false",
    );
    expect(() => setConfigValue("auditLog", "maybe")).toThrow(
      "auditLog must be true or false",
    );
    expect(() => setConfigValue("maxTriageRetries", "-1")).toThrow(
      "maxTriageRetries must be a non-negative number",
    );
    expect(() => setConfigValue("maxVerifyRetries", "-1")).toThrow(
      "maxVerifyRetries must be a non-negative number",
    );
    expect(() => setConfigValue("retryBackoffMs", "-1")).toThrow(
      "retryBackoffMs must be a non-negative number",
    );
    expect(() => setConfigValue("retryBackoffMultiplier", "0")).toThrow(
      "retryBackoffMultiplier must be a positive number",
    );
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

  it("unsets optional verifyModel", () => {
    setConfigValue("verifyModel", "claude-haiku-4-5-20251001");
    expect(getConfigValue("verifyModel")).toBe("claude-haiku-4-5-20251001");
    unsetConfigValue("verifyModel");
    expect(getConfigValue("verifyModel")).toBeUndefined();
  });

  it("resets verify keys to defaults", () => {
    setConfigValue("verify", "true");
    setConfigValue("verifyMaxTurns", "25");
    setConfigValue("verifyConcurrency", "4");
    setConfigValue("verifyVerdicts", "tp,fp");

    unsetConfigValue("verify");
    unsetConfigValue("verifyMaxTurns");
    unsetConfigValue("verifyConcurrency");
    unsetConfigValue("verifyVerdicts");

    expect(getConfigValue("verify")).toBe(DEFAULTS.verify);
    expect(getConfigValue("verifyMaxTurns")).toBe(DEFAULTS.verifyMaxTurns);
    expect(getConfigValue("verifyConcurrency")).toBe(DEFAULTS.verifyConcurrency);
    expect(getConfigValue("verifyVerdicts")).toEqual(DEFAULTS.verifyVerdicts);
  });

  it("resets context/audit/retry keys to defaults", () => {
    setConfigValue("verifyMinConfidence", "0.8");
    setConfigValue("enableContextGathering", "false");
    setConfigValue("auditLog", "true");
    setConfigValue("reportOutput", "report.md");
    setConfigValue("sarifOutput", "report.sarif");
    setConfigValue("maxTriageRetries", "9");
    setConfigValue("maxVerifyRetries", "8");
    setConfigValue("retryBackoffMs", "42");
    setConfigValue("retryBackoffMultiplier", "3");

    unsetConfigValue("verifyMinConfidence");
    unsetConfigValue("enableContextGathering");
    unsetConfigValue("auditLog");
    unsetConfigValue("reportOutput");
    unsetConfigValue("sarifOutput");
    unsetConfigValue("maxTriageRetries");
    unsetConfigValue("maxVerifyRetries");
    unsetConfigValue("retryBackoffMs");
    unsetConfigValue("retryBackoffMultiplier");

    expect(getConfigValue("verifyMinConfidence")).toBe(DEFAULTS.verifyMinConfidence);
    expect(getConfigValue("enableContextGathering")).toBe(DEFAULTS.enableContextGathering);
    expect(getConfigValue("auditLog")).toBe(DEFAULTS.auditLog);
    expect(getConfigValue("reportOutput")).toBe(DEFAULTS.reportOutput);
    expect(getConfigValue("sarifOutput")).toBe(DEFAULTS.sarifOutput);
    expect(getConfigValue("maxTriageRetries")).toBe(DEFAULTS.maxTriageRetries);
    expect(getConfigValue("maxVerifyRetries")).toBe(DEFAULTS.maxVerifyRetries);
    expect(getConfigValue("retryBackoffMs")).toBe(DEFAULTS.retryBackoffMs);
    expect(getConfigValue("retryBackoffMultiplier")).toBe(DEFAULTS.retryBackoffMultiplier);
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
