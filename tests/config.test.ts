import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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
const { hasConfigValidationErrors, validateKuzushiConfig } = await import(
  "../src/config/validation.js"
);

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
    expect(config.verify).toBe(DEFAULTS.verify);
    expect(config.verifyMaxTurns).toBe(DEFAULTS.verifyMaxTurns);
    expect(config.verifyConcurrency).toBe(DEFAULTS.verifyConcurrency);
    expect(config.verifyVerdicts).toEqual(DEFAULTS.verifyVerdicts);
    expect(config.verifyMinConfidence).toBe(DEFAULTS.verifyMinConfidence);
    expect(config.pocHarness).toBe(DEFAULTS.pocHarness);
    expect(config.pocHarnessMaxTurns).toBe(DEFAULTS.pocHarnessMaxTurns);
    expect(config.pocHarnessConcurrency).toBe(DEFAULTS.pocHarnessConcurrency);
    expect(config.enableContextGathering).toBe(DEFAULTS.enableContextGathering);
    expect(config.auditLog).toBe(DEFAULTS.auditLog);
    expect(config.sarifOutput).toBe(DEFAULTS.sarifOutput);
    expect(config.maxTriageRetries).toBe(DEFAULTS.maxTriageRetries);
    expect(config.maxVerifyRetries).toBe(DEFAULTS.maxVerifyRetries);
    expect(config.maxPocHarnessRetries).toBe(DEFAULTS.maxPocHarnessRetries);
    expect(config.retryBackoffMs).toBe(DEFAULTS.retryBackoffMs);
    expect(config.retryBackoffMultiplier).toBe(DEFAULTS.retryBackoffMultiplier);
    expect(config.ensembleModels).toEqual(DEFAULTS.ensembleModels);
    expect(config.pocRefinementMaxIterations).toBe(DEFAULTS.pocRefinementMaxIterations);
    expect(config.verifyRefinementMaxIterations).toBe(DEFAULTS.verifyRefinementMaxIterations);
    expect(config.agentRuntimeConfig).toBe(DEFAULTS.agentRuntimeConfig);
    expect(config.tasks).toEqual(DEFAULTS.tasks);
  });

  it("injects crypto-behavioral-test into explicit tasks when the feature is enabled", () => {
    writeFileSync(
      TMP_CONFIG_PATH,
      JSON.stringify({
        tasks: ["custom-task"],
        cryptoBehavioralTestEnabled: true,
      }),
    );

    const config = loadConfig();
    expect(config.cryptoBehavioralTestEnabled).toBe(true);
    expect(config.tasks).toEqual(["custom-task", "crypto-behavioral-test"]);
  });

  it("merges global config over defaults", () => {
    writeFileSync(
      TMP_CONFIG_PATH,
      JSON.stringify({
        model: "custom-model",
        verify: true,
        verifyMaxTurns: 25,
        verifyConcurrency: 2,
        verifyVerdicts: ["tp", "needs_review"],
        verifyMinConfidence: 0.7,
        pocHarness: true,
        pocHarnessMaxTurns: 30,
        pocHarnessConcurrency: 4,
        enableContextGathering: false,
        auditLog: true,
        reportOutput: "/tmp/report.md",
        sarifOutput: "/tmp/report.sarif",
        maxTriageRetries: 4,
        maxVerifyRetries: 5,
        maxPocHarnessRetries: 6,
        retryBackoffMs: 2000,
        retryBackoffMultiplier: 3,
        ensembleModels: ["anthropic:claude-haiku-4-5", "openai:gpt-4o"],
        pocRefinementMaxIterations: 4,
        pocReflectionInterval: 3,
        verifyRefinementMaxIterations: 5,
        verifyReflectionInterval: 4,
        agentRuntimeConfig: {
          apiKey: "sk-test",
          baseUrl: "https://api.example.com/",
        },
        taskConfig: {
          semgrep: { verify: false },
          triage: { model: "triage-model" },
          verify: { model: "verify-model" },
          "poc-harness": { model: "poc-model" },
        },
      }),
    );
    const config = loadConfig();
    expect(config.model).toBe("custom-model");
    expect(config.taskConfig.triage?.model).toBe("triage-model");
    expect(config.verify).toBe(true);
    expect(config.taskConfig.verify?.model).toBe("verify-model");
    expect(config.verifyMaxTurns).toBe(25);
    expect(config.verifyConcurrency).toBe(2);
    expect(config.verifyVerdicts).toEqual(["tp", "needs_review"]);
    expect(config.verifyMinConfidence).toBe(0.7);
    expect(config.pocHarness).toBe(true);
    expect(config.taskConfig["poc-harness"]?.model).toBe("poc-model");
    expect(config.pocHarnessMaxTurns).toBe(30);
    expect(config.pocHarnessConcurrency).toBe(4);
    expect(config.enableContextGathering).toBe(false);
    expect(config.auditLog).toBe(true);
    expect(config.reportOutput).toBe("/tmp/report.md");
    expect(config.sarifOutput).toBe("/tmp/report.sarif");
    expect(config.maxTriageRetries).toBe(4);
    expect(config.maxVerifyRetries).toBe(5);
    expect(config.maxPocHarnessRetries).toBe(6);
    expect(config.retryBackoffMs).toBe(2000);
    expect(config.retryBackoffMultiplier).toBe(3);
    expect(config.ensembleModels).toEqual(["anthropic:claude-haiku-4-5", "openai:gpt-4o"]);
    expect(config.pocRefinementMaxIterations).toBe(4);
    expect(config.pocReflectionInterval).toBe(3);
    expect(config.verifyRefinementMaxIterations).toBe(5);
    expect(config.verifyReflectionInterval).toBe(4);
    expect(config.agentRuntimeConfig).toEqual({
      apiKey: "sk-test",
      baseUrl: "https://api.example.com/",
    });
    expect(config.taskConfig.semgrep?.verify).toBe(false);
  });

  it("applies project-level override when repoRoot is provided", () => {
    writeFileSync(TMP_CONFIG_PATH, JSON.stringify({ model: "global-model", tasks: ["semgrep"] }));
    writeFileSync(
      TMP_PROJECT_CONFIG_PATH,
      JSON.stringify({ model: "project-model", tasks: ["agentic"] }),
    );

    const config = loadConfig(TMP_REPO);
    expect(config.model).toBe("project-model");
    expect(config.tasks).toEqual(["agentic"]);
  });

  it("merges agentRuntimeConfig shallowly across config layers", () => {
    writeFileSync(
      TMP_CONFIG_PATH,
      JSON.stringify({
        agentRuntimeConfig: {
          apiKey: "global-key",
        },
      }),
    );
    writeFileSync(
      TMP_PROJECT_CONFIG_PATH,
      JSON.stringify({
        agentRuntimeConfig: {
          baseUrl: "https://api.example.com/",
        },
      }),
    );

    const config = loadConfig(TMP_REPO, { trustProjectConfig: true });
    expect(config.agentRuntimeConfig).toEqual({
      apiKey: "global-key",
      baseUrl: "https://api.example.com/",
    });
  });

  it("strips unsafe repo-local config by default", () => {
    writeFileSync(
      TMP_CONFIG_PATH,
      JSON.stringify({
        agentRuntimeConfig: {
          apiKey: "global-key",
        },
      }),
    );
    writeFileSync(
      TMP_PROJECT_CONFIG_PATH,
      JSON.stringify({
        model: "project-model",
        agentRuntimeConfig: {
          baseUrl: "https://evil.example/",
        },
        taskConfig: {
          semgrep: {
            binary: "/tmp/evil-semgrep",
          },
          "code-graph": {
            maxEntryPoints: 5,
          },
        },
      }),
    );

    const config = loadConfig(TMP_REPO);
    expect(config.model).toBe("project-model");
    expect(config.agentRuntimeBackend).toBe(DEFAULTS.agentRuntimeBackend);
    expect(config.agentRuntimeConfig).toEqual({
      apiKey: "global-key",
    });
    expect(config.taskConfig.semgrep?.binary).toBeUndefined();
    expect(config.taskConfig["code-graph"]?.maxEntryPoints).toBe(5);
  });

  it("loads unsafe repo-local config when trustProjectConfig is enabled", () => {
    writeFileSync(
      TMP_PROJECT_CONFIG_PATH,
      JSON.stringify({
        agentRuntimeConfig: {
          baseUrl: "https://trusted.example/",
        },
      }),
    );

    const config = loadConfig(TMP_REPO, { trustProjectConfig: true });
    expect(config.agentRuntimeConfig).toEqual({
      baseUrl: "https://trusted.example/",
    });
  });

  it("rejects file references that escape the config directory", () => {
    const escapedDir = path.join(TMP_REPO, ".kuzushi-evil");
    mkdirSync(escapedDir, { recursive: true });
    writeFileSync(path.join(escapedDir, "escape.json"), JSON.stringify("escaped-model"));
    writeFileSync(
      TMP_PROJECT_CONFIG_PATH,
      JSON.stringify({
        model: "file://../.kuzushi-evil/escape.json",
      }),
    );

    const config = loadConfig(TMP_REPO, { trustProjectConfig: true });
    expect(config.model).toBe(DEFAULTS.model);
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

  it("returns nested taskConfig values", () => {
    writeFileSync(
      TMP_CONFIG_PATH,
      JSON.stringify({ taskConfig: { semgrep: { binary: "opengrep" } } }),
    );
    expect(getConfigValue("taskConfig.semgrep.binary")).toBe("opengrep");
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

  it("sets stage model overrides via taskConfig", () => {
    setConfigValue("taskConfig.triage.model", "claude-opus-4-20250514");
    expect(getConfigValue("taskConfig.triage.model")).toBe("claude-opus-4-20250514");
  });

  it("sets verify settings", () => {
    setConfigValue("verify", "true");
    setConfigValue("taskConfig.verify.model", "claude-haiku-4-5-20251001");
    setConfigValue("verifyMaxTurns", "20");
    setConfigValue("verifyConcurrency", "3");
    setConfigValue("verifyVerdicts", "tp,needs_review");

    expect(getConfigValue("verify")).toBe(true);
    expect(getConfigValue("taskConfig.verify.model")).toBe("claude-haiku-4-5-20251001");
    expect(getConfigValue("verifyMaxTurns")).toBe(20);
    expect(getConfigValue("verifyConcurrency")).toBe(3);
    expect(getConfigValue("verifyVerdicts")).toEqual(["tp", "needs_review"]);
  });

  it("sets poc harness settings", () => {
    setConfigValue("pocHarness", "true");
    setConfigValue("taskConfig.poc-harness.model", "claude-haiku-4-5-20251001");
    setConfigValue("pocHarnessMaxTurns", "28");
    setConfigValue("pocHarnessConcurrency", "2");

    expect(getConfigValue("pocHarness")).toBe(true);
    expect(getConfigValue("taskConfig.poc-harness.model")).toBe("claude-haiku-4-5-20251001");
    expect(getConfigValue("pocHarnessMaxTurns")).toBe(28);
    expect(getConfigValue("pocHarnessConcurrency")).toBe(2);
  });

  it("normalizes percentage-style verifyMinConfidence", () => {
    setConfigValue("verifyMinConfidence", "90");
    expect(getConfigValue("verifyMinConfidence")).toBe(0.9);
  });

  it("sets confidence gate, context, audit, and retry settings", () => {
    setConfigValue("verifyMinConfidence", "0.6");
    setConfigValue("enableContextGathering", "false");
    setConfigValue("auditLog", "true");
    setConfigValue("reportOutput", "report.md");
    setConfigValue("sarifOutput", "report.sarif");
    setConfigValue("maxTriageRetries", "3");
    setConfigValue("maxVerifyRetries", "4");
    setConfigValue("maxPocHarnessRetries", "5");
    setConfigValue("retryBackoffMs", "1200");
    setConfigValue("retryBackoffMultiplier", "2.5");

    expect(getConfigValue("verifyMinConfidence")).toBe(0.6);
    expect(getConfigValue("enableContextGathering")).toBe(false);
    expect(getConfigValue("auditLog")).toBe(true);
    expect(getConfigValue("reportOutput")).toBe("report.md");
    expect(getConfigValue("sarifOutput")).toBe("report.sarif");
    expect(getConfigValue("maxTriageRetries")).toBe(3);
    expect(getConfigValue("maxVerifyRetries")).toBe(4);
    expect(getConfigValue("maxPocHarnessRetries")).toBe(5);
    expect(getConfigValue("retryBackoffMs")).toBe(1200);
    expect(getConfigValue("retryBackoffMultiplier")).toBe(2.5);
  });

  it("sets ensemble and refinement settings", () => {
    setConfigValue("ensembleModels", "anthropic:claude-haiku-4-5,openai:gpt-4o");
    setConfigValue("pocRefinementMaxIterations", "4");
    setConfigValue("pocReflectionInterval", "3");
    setConfigValue("verifyRefinementMaxIterations", "5");
    setConfigValue("verifyReflectionInterval", "2");

    expect(getConfigValue("ensembleModels")).toEqual([
      "anthropic:claude-haiku-4-5",
      "openai:gpt-4o",
    ]);
    expect(getConfigValue("pocRefinementMaxIterations")).toBe(4);
    expect(getConfigValue("pocReflectionInterval")).toBe(3);
    expect(getConfigValue("verifyRefinementMaxIterations")).toBe(5);
    expect(getConfigValue("verifyReflectionInterval")).toBe(2);
  });

  it("sets number values", () => {
    setConfigValue("triageConcurrency", "3");
    expect(getConfigValue("triageConcurrency")).toBe(3);
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
    setConfigValue("agentRuntimeBackend", "pi-ai");
    expect(getConfigValue("agentRuntimeBackend")).toBe("pi-ai");
  });

  it("sets agentRuntimeConfig as an object", () => {
    setConfigValue(
      "agentRuntimeConfig",
      '{"apiKey":"sk-test","baseUrl":"https://api.example.com/"}',
    );
    expect(getConfigValue("agentRuntimeConfig")).toEqual({
      apiKey: "sk-test",
      baseUrl: "https://api.example.com/",
    });
  });

  it("sets nested agentRuntimeConfig values", () => {
    setConfigValue("agentRuntimeConfig.apiKey", "sk-inline");
    setConfigValue("agentRuntimeConfig.baseUrl", "https://proxy.example/");
    expect(getConfigValue("agentRuntimeConfig.apiKey")).toBe("sk-inline");
    expect(getConfigValue("agentRuntimeConfig.baseUrl")).toBe("https://proxy.example/");
  });

  it("sets tasks from comma-separated string", () => {
    setConfigValue("tasks", "semgrep,custom-scanner");
    expect(getConfigValue("tasks")).toEqual(["semgrep", "custom-scanner"]);
  });

  it("sets nested taskConfig values", () => {
    setConfigValue("taskConfig.semgrep.binary", "opengrep");
    expect(getConfigValue("taskConfig.semgrep.binary")).toBe("opengrep");
  });

  it("sets nested scanner verify flag values", () => {
    setConfigValue("taskConfig.semgrep.verify", "false");
    expect(getConfigValue("taskConfig.semgrep.verify")).toBe(false);
  });

  it("preserves repo-local layering when writing project config", () => {
    writeFileSync(
      TMP_CONFIG_PATH,
      JSON.stringify({
        model: "global-model",
        verify: true,
        verifyMaxTurns: 25,
      }),
    );

    setConfigValue("scanMode", "concurrent", TMP_REPO);

    expect(loadConfig(TMP_REPO)).toMatchObject({
      model: "global-model",
      verify: true,
      verifyMaxTurns: 25,
      scanMode: "concurrent",
    });
    expect(JSON.parse(readFileSync(TMP_PROJECT_CONFIG_PATH, "utf-8"))).toEqual({
      scanMode: "concurrent",
    });
  });

  it("throws on unknown top-level key", () => {
    expect(() => setConfigValue("bogus", "val")).toThrow("Unknown config key");
  });

  it("throws on invalid numeric values", () => {});

  it("throws on invalid verify values", () => {
    expect(() => setConfigValue("verify", "maybe")).toThrow("verify must be true or false");
    expect(() => setConfigValue("verifyMaxTurns", "0")).toThrow(
      "verifyMaxTurns must be a positive number",
    );
    expect(() => setConfigValue("verifyConcurrency", "0")).toThrow(
      "verifyConcurrency must be a positive number",
    );
    expect(() => setConfigValue("verifyVerdicts", "foo")).toThrow(
      "verifyVerdicts must contain only: tp, fp, needs_review",
    );
    expect(() => setConfigValue("verifyMinConfidence", "101")).toThrow(
      "verifyMinConfidence must be a number between 0 and 1 (or 0-100 as a percentage)",
    );
    expect(() => setConfigValue("pocHarness", "maybe")).toThrow("pocHarness must be true or false");
    expect(() => setConfigValue("pocHarnessMaxTurns", "0")).toThrow(
      "pocHarnessMaxTurns must be a positive number",
    );
    expect(() => setConfigValue("pocHarnessConcurrency", "0")).toThrow(
      "pocHarnessConcurrency must be a positive number",
    );
  });

  it("throws on invalid context/audit/retry values", () => {
    expect(() => setConfigValue("enableContextGathering", "maybe")).toThrow(
      "enableContextGathering must be true or false",
    );
    expect(() => setConfigValue("auditLog", "maybe")).toThrow("auditLog must be true or false");
    expect(() => setConfigValue("maxTriageRetries", "-1")).toThrow(
      "maxTriageRetries must be a non-negative number",
    );
    expect(() => setConfigValue("maxVerifyRetries", "-1")).toThrow(
      "maxVerifyRetries must be a non-negative number",
    );
    expect(() => setConfigValue("maxPocHarnessRetries", "-1")).toThrow(
      "maxPocHarnessRetries must be a non-negative number",
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

  it("throws on invalid agentRuntimeConfig", () => {
    expect(() => setConfigValue("agentRuntimeConfig", "not-object")).toThrow(
      "agentRuntimeConfig must be an object",
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

  it("unsets stage model via taskConfig", () => {
    setConfigValue("taskConfig.triage.model", "claude-opus-4-20250514");
    expect(getConfigValue("taskConfig.triage.model")).toBe("claude-opus-4-20250514");
    unsetConfigValue("taskConfig.triage.model");
    expect(getConfigValue("taskConfig.triage.model")).toBeUndefined();
  });

  it("unsets verify model via taskConfig", () => {
    setConfigValue("taskConfig.verify.model", "claude-haiku-4-5-20251001");
    expect(getConfigValue("taskConfig.verify.model")).toBe("claude-haiku-4-5-20251001");
    unsetConfigValue("taskConfig.verify.model");
    expect(getConfigValue("taskConfig.verify.model")).toBeUndefined();
  });

  it("unsets poc-harness model via taskConfig", () => {
    setConfigValue("taskConfig.poc-harness.model", "claude-haiku-4-5-20251001");
    expect(getConfigValue("taskConfig.poc-harness.model")).toBe("claude-haiku-4-5-20251001");
    unsetConfigValue("taskConfig.poc-harness.model");
    expect(getConfigValue("taskConfig.poc-harness.model")).toBeUndefined();
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

  it("resets poc harness keys to defaults", () => {
    setConfigValue("pocHarness", "true");
    setConfigValue("pocHarnessMaxTurns", "35");
    setConfigValue("pocHarnessConcurrency", "3");

    unsetConfigValue("pocHarness");
    unsetConfigValue("pocHarnessMaxTurns");
    unsetConfigValue("pocHarnessConcurrency");

    expect(getConfigValue("pocHarness")).toBe(DEFAULTS.pocHarness);
    expect(getConfigValue("pocHarnessMaxTurns")).toBe(DEFAULTS.pocHarnessMaxTurns);
    expect(getConfigValue("pocHarnessConcurrency")).toBe(DEFAULTS.pocHarnessConcurrency);
  });

  it("resets context/audit/retry keys to defaults", () => {
    setConfigValue("verifyMinConfidence", "0.8");
    setConfigValue("enableContextGathering", "false");
    setConfigValue("auditLog", "true");
    setConfigValue("reportOutput", "report.md");
    setConfigValue("sarifOutput", "report.sarif");
    setConfigValue("maxTriageRetries", "9");
    setConfigValue("maxVerifyRetries", "8");
    setConfigValue("maxPocHarnessRetries", "7");
    setConfigValue("retryBackoffMs", "42");
    setConfigValue("retryBackoffMultiplier", "3");

    unsetConfigValue("verifyMinConfidence");
    unsetConfigValue("enableContextGathering");
    unsetConfigValue("auditLog");
    unsetConfigValue("reportOutput");
    unsetConfigValue("sarifOutput");
    unsetConfigValue("maxTriageRetries");
    unsetConfigValue("maxVerifyRetries");
    unsetConfigValue("maxPocHarnessRetries");
    unsetConfigValue("retryBackoffMs");
    unsetConfigValue("retryBackoffMultiplier");

    expect(getConfigValue("verifyMinConfidence")).toBe(DEFAULTS.verifyMinConfidence);
    expect(getConfigValue("enableContextGathering")).toBe(DEFAULTS.enableContextGathering);
    expect(getConfigValue("auditLog")).toBe(DEFAULTS.auditLog);
    expect(getConfigValue("reportOutput")).toBe(DEFAULTS.reportOutput);
    expect(getConfigValue("sarifOutput")).toBe(DEFAULTS.sarifOutput);
    expect(getConfigValue("maxTriageRetries")).toBe(DEFAULTS.maxTriageRetries);
    expect(getConfigValue("maxVerifyRetries")).toBe(DEFAULTS.maxVerifyRetries);
    expect(getConfigValue("maxPocHarnessRetries")).toBe(DEFAULTS.maxPocHarnessRetries);
    expect(getConfigValue("retryBackoffMs")).toBe(DEFAULTS.retryBackoffMs);
    expect(getConfigValue("retryBackoffMultiplier")).toBe(DEFAULTS.retryBackoffMultiplier);
  });

  it("resets agentRuntimeConfig to default", () => {
    setConfigValue("agentRuntimeConfig.apiKey", "sk-inline");
    setConfigValue("agentRuntimeConfig.baseUrl", "https://proxy.example/");
    unsetConfigValue("agentRuntimeConfig");
    expect(getConfigValue("agentRuntimeConfig")).toBe(DEFAULTS.agentRuntimeConfig);
  });

  it("removes nested key", () => {
    setConfigValue("taskConfig.semgrep.binary", "opengrep");
    unsetConfigValue("taskConfig.semgrep.binary");
    expect(getConfigValue("taskConfig.semgrep.binary")).toBeUndefined();
  });

  it("restores inherited values when removing a project override", () => {
    writeFileSync(
      TMP_CONFIG_PATH,
      JSON.stringify({
        model: "global-model",
        verify: true,
      }),
    );
    writeFileSync(
      TMP_PROJECT_CONFIG_PATH,
      JSON.stringify({
        model: "project-model",
        scanMode: "concurrent",
      }),
    );

    unsetConfigValue("model", TMP_REPO);

    expect(loadConfig(TMP_REPO)).toMatchObject({
      model: "global-model",
      verify: true,
      scanMode: "concurrent",
    });
    expect(JSON.parse(readFileSync(TMP_PROJECT_CONFIG_PATH, "utf-8"))).toEqual({
      scanMode: "concurrent",
    });
  });

  it("throws on unknown key", () => {
    expect(() => unsetConfigValue("bogus")).toThrow("Unknown config key");
  });
});

describe("validateKuzushiConfig", () => {
  it("accepts the default configuration", () => {
    const issues = validateKuzushiConfig(DEFAULTS);
    expect(issues).toEqual([]);
    expect(hasConfigValidationErrors(issues)).toBe(false);
  });

  it("rejects unsupported bus backends", () => {
    const issues = validateKuzushiConfig({
      ...DEFAULTS,
      busBackend: "redis" as typeof DEFAULTS.busBackend,
    });

    expect(issues).toEqual([
      expect.objectContaining({
        severity: "error",
        path: "busBackend",
      }),
    ]);
    expect(hasConfigValidationErrors(issues)).toBe(true);
  });

  it("flags verification-dependent features when verify is disabled", () => {
    const issues = validateKuzushiConfig({
      ...DEFAULTS,
      verify: false,
      pocHarness: true,
      dynamicAnalysisEnabled: true,
      qualityGates: {
        failOnExploitable: true,
      },
    });

    expect(issues).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          severity: "error",
          path: "pocHarness",
        }),
        expect.objectContaining({
          severity: "error",
          path: "dynamicAnalysisEnabled",
        }),
        expect.objectContaining({
          severity: "warning",
          path: "qualityGates.failOnExploitable",
        }),
      ]),
    );
  });

  it("warns when external tasks are configured but disabled", () => {
    const issues = validateKuzushiConfig({
      ...DEFAULTS,
      enableExternalTasks: false,
      externalTasks: ["/tmp/ext-task"],
    });

    expect(issues).toEqual([
      expect.objectContaining({
        severity: "warning",
        path: "externalTasks",
      }),
    ]);
    expect(hasConfigValidationErrors(issues)).toBe(false);
  });
});

describe("prototype pollution prevention", () => {
  it("rejects __proto__ in dotted path for set", () => {
    expect(() => setConfigValue("__proto__.polluted", "true")).toThrow(
      "Invalid config key segment",
    );
  });

  it("rejects constructor in dotted path for set", () => {
    expect(() => setConfigValue("constructor.prototype.polluted", "true")).toThrow(
      "Invalid config key segment",
    );
  });

  it("rejects prototype in dotted path for set", () => {
    expect(() => setConfigValue("taskConfig.prototype.x", "true")).toThrow(
      "Invalid config key segment",
    );
  });

  it("rejects __proto__ in dotted path for unset", () => {
    expect(() => unsetConfigValue("__proto__.polluted")).toThrow("Invalid config key segment");
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
