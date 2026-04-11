import path from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULTS } from "../../src/config.js";
import { CliUsageError } from "../../src/cli/errors.js";
import { applyScanCommandConfigOverrides, type ScanCommandOptions } from "../../src/cli/scan-config.js";

function makeOptions(overrides: Partial<ScanCommandOptions> = {}): ScanCommandOptions {
  return {
    verify: false,
    cryptoBehavioralTest: false,
    pocHarness: false,
    context: true,
    moduleDiscovery: true,
    auditLog: false,
    enableExternalTasks: false,
    qualityGate: false,
    failOnTp: false,
    fresh: false,
    cache: true,
    ...overrides,
  };
}

describe("applyScanCommandConfigOverrides", () => {
  it("applies validated numeric and path overrides", () => {
    const config = structuredClone(DEFAULTS);

    applyScanCommandConfigOverrides(config, makeOptions({
      verify: true,
      verifyMaxTurns: 9,
      verifyConcurrency: 4,
      verifyMinConfidence: 0.7,
      output: "report.md",
      json: "report.json",
    }));

    expect(config.verify).toBe(true);
    expect(config.verifyMaxTurns).toBe(9);
    expect(config.verifyConcurrency).toBe(4);
    expect(config.verifyMinConfidence).toBe(0.7);
    expect(config.reportOutput).toBe(path.resolve("report.md"));
    expect(config.jsonOutput).toBe(path.resolve("report.json"));
  });

  it("merges enabled tasks and runtime overrides", () => {
    const config = structuredClone(DEFAULTS);

    applyScanCommandConfigOverrides(config, makeOptions({
      enabledTasks: "custom-a, custom-b",
      apiKey: "  sk-test  ",
      baseUrl: " https://proxy.example/ ",
      qualityGate: true,
    }));

    expect(config.enabledTasks).toEqual([...DEFAULTS.enabledTasks, "custom-a", "custom-b"]);
    expect(config.agentRuntimeConfig).toEqual({
      apiKey: "sk-test",
      baseUrl: "https://proxy.example/",
    });
    expect(config.qualityGates).toMatchObject({
      failOnHighSeverityTP: true,
      failOnExploitable: true,
    });
  });

  it("enables crypto behavioral testing and injects the task id", () => {
    const config = structuredClone(DEFAULTS);
    config.enabledTasks = ["custom-task"];

    applyScanCommandConfigOverrides(config, makeOptions({
      cryptoBehavioralTest: true,
    }));

    expect(config.cryptoBehavioralTestEnabled).toBe(true);
    expect(config.enabledTasks).toContain("custom-task");
    expect(config.enabledTasks).toContain("crypto-behavioral-test");
  });

  it("applies dynamic analysis and taint-diff overrides", () => {
    const config = structuredClone(DEFAULTS);

    applyScanCommandConfigOverrides(config, makeOptions({
      verify: true,
      dynamicAnalysis: true,
      dynamicMaxCandidates: 10,
      dynamicMinScore: 8,
      taintDiffBase: "main",
      taintDiffMode: "baseline",
    }));

    expect(config.verify).toBe(true);
    expect(config.dynamicAnalysisEnabled).toBe(true);
    expect(config.dynamicMaxCandidates).toBe(10);
    expect(config.dynamicMinScore).toBe(8);
    expect(config.taintDiffBase).toBe("main");
    expect(config.taintDiffMode).toBe("baseline");
  });

  it("rejects invalid unit interval values", () => {
    const config = structuredClone(DEFAULTS);

    expect(() => applyScanCommandConfigOverrides(config, makeOptions({
      verifyMinConfidence: 101,
    }))).toThrowError(new CliUsageError("--verify-min-confidence must be a number between 0 and 1 (or 0-100 as a percentage)."));
  });

  it("normalizes percentage-style verify-min-confidence (90 -> 0.9)", () => {
    const config = structuredClone(DEFAULTS);
    applyScanCommandConfigOverrides(config, makeOptions({
      verify: true,
      verifyMinConfidence: 90,
    }));
    expect(config.verifyMinConfidence).toBe(0.9);
  });

  it("accepts standard unit interval verify-min-confidence", () => {
    const config = structuredClone(DEFAULTS);
    applyScanCommandConfigOverrides(config, makeOptions({
      verify: true,
      verifyMinConfidence: 0.7,
    }));
    expect(config.verifyMinConfidence).toBe(0.7);
  });

  it("rejects poc harness without verification", () => {
    const config = structuredClone(DEFAULTS);

    expect(() => applyScanCommandConfigOverrides(config, makeOptions({
      pocHarness: true,
    }))).toThrowError(new CliUsageError("--poc-harness requires --verify."));
  });

  it("rejects invalid taint diff modes", () => {
    const config = structuredClone(DEFAULTS);

    expect(() => applyScanCommandConfigOverrides(config, makeOptions({
      taintDiffMode: "bogus",
    }))).toThrowError(new CliUsageError("--taint-diff-mode must be one of: delta, baseline."));
  });

  it("applies reference preset with deep-merged scannerConfig", () => {
    const config = structuredClone(DEFAULTS);
    const originalSemgrep = { ...config.scannerConfig.semgrep };

    applyScanCommandConfigOverrides(config, makeOptions({ preset: "reference" }));

    // Threat-hunt gets Orchid model from the preset
    expect(config.scannerConfig["threat-hunt"].model).toBe("anthropic:claude-orchid-preview");
    expect(config.scannerConfig["threat-hunt"].runsPerActor).toBe(3);

    // Other scanner configs survive the deep-merge (not wiped out)
    expect(config.scannerConfig.semgrep).toEqual(originalSemgrep);
    expect(config.scannerConfig["taint-analysis"]).toBeDefined();
    expect(config.scannerConfig["taint-analysis"].passes).toEqual([1, 2, 3]);

    // Top-level preset fields are applied
    expect(config.taskMode).toBe("compat");
    expect(config.verify).toBe(true);
    expect(config.pocHarness).toBe(true);
    // Scanners are NOT overridden — user's configured scanners are preserved
    expect(config.scanners).toEqual(DEFAULTS.scanners);
  });

  it("reference preset does not override global model or scanners", () => {
    const config = structuredClone(DEFAULTS);

    applyScanCommandConfigOverrides(config, makeOptions({
      preset: "reference",
      model: "anthropic:claude-opus-4-6",
    }));

    // CLI --model sets the global model; preset doesn't fight it
    expect(config.model).toBe("anthropic:claude-opus-4-6");
    // Scanners stay at user defaults
    expect(config.scanners).toEqual(DEFAULTS.scanners);
    // Threat-hunt gets Orchid from scannerConfig deep-merge
    expect(config.scannerConfig["threat-hunt"].model).toBe("anthropic:claude-orchid-preview");
  });

  it("applies fast preset as a true scanners-only mode", () => {
    const config = structuredClone(DEFAULTS);

    applyScanCommandConfigOverrides(config, makeOptions({ preset: "fast" }));

    expect(config.taskMode).toBe("scanners-only");
    expect(config.enabledTasks).toEqual([]);
    expect(config.enableDynamicTaskSelection).toBe(false);
    expect(config.enableContextGathering).toBe(false);
    expect(config.enableContextEnrichment).toBe(false);
  });

  it("applies standard preset as explicit task mode", () => {
    const config = structuredClone(DEFAULTS);

    applyScanCommandConfigOverrides(config, makeOptions({ preset: "standard" }));

    expect(config.taskMode).toBe("explicit");
    expect(config.enabledTasks).toEqual([
      "context-gatherer",
      "context-enricher",
      "secrets-crypto-detect",
      "code-config-detect",
      "taint-cwe-select",
      "taint-iris",
    ]);
    expect(config.enableDynamicTaskSelection).toBe(false);
  });

  it("applies deep preset as explicit standard coverage plus verification", () => {
    const config = structuredClone(DEFAULTS);

    applyScanCommandConfigOverrides(config, makeOptions({ preset: "deep" }));

    expect(config.taskMode).toBe("explicit");
    expect(config.enabledTasks).toEqual([
      "context-gatherer",
      "context-enricher",
      "secrets-crypto-detect",
      "code-config-detect",
      "taint-cwe-select",
      "taint-iris",
      "threat-model-randori",
      "threat-hunt",
    ]);
    expect(config.verify).toBe(true);
  });

  it("promotes scanners-only presets to explicit when CLI flags explicitly enable tasks", () => {
    const config = structuredClone(DEFAULTS);

    applyScanCommandConfigOverrides(config, makeOptions({
      preset: "fast",
      enabledTasks: "custom-detector",
    }));

    expect(config.taskMode).toBe("explicit");
    expect(config.enabledTasks).toEqual(["custom-detector"]);
  });

  it("rejects unknown preset names", () => {
    const config = structuredClone(DEFAULTS);

    expect(() => applyScanCommandConfigOverrides(config, makeOptions({
      preset: "bogus",
    }))).toThrowError(CliUsageError);
  });
});
