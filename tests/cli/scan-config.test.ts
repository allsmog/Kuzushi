import path from "node:path";
import { describe, expect, it } from "vitest";
import { DEFAULTS } from "../../src/config.js";
import { CliUsageError } from "../../src/cli/errors.js";
import { applyScanCommandConfigOverrides, type ScanCommandOptions } from "../../src/cli/scan-config.js";

function makeOptions(overrides: Partial<ScanCommandOptions> = {}): ScanCommandOptions {
  return {
    enableClassifier: false,
    verify: false,
    cryptoBehavioralTest: false,
    pocHarness: false,
    context: true,
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
      triageMaxTurns: 12,
      verify: true,
      verifyMaxTurns: 9,
      verifyConcurrency: 4,
      verifyMinConfidence: 0.7,
      output: "report.md",
      json: "report.json",
    }));

    expect(config.verify).toBe(true);
    expect(config.triageMaxTurns).toBe(12);
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

  it("rejects invalid unit interval values", () => {
    const config = structuredClone(DEFAULTS);

    expect(() => applyScanCommandConfigOverrides(config, makeOptions({
      classifierThreshold: 1.5,
    }))).toThrowError(new CliUsageError("--classifier-threshold must be a number between 0 and 1."));
  });

  it("rejects poc harness without verification", () => {
    const config = structuredClone(DEFAULTS);

    expect(() => applyScanCommandConfigOverrides(config, makeOptions({
      pocHarness: true,
    }))).toThrowError(new CliUsageError("--poc-harness requires --verify."));
  });
});
