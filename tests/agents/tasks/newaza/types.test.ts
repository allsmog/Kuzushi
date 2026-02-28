import { describe, expect, it } from "vitest";
import { resolveNewazaConfig } from "../../../../src/agents/tasks/newaza/types.js";
import type { KuzushiConfig } from "../../../../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageConcurrency: 1,
    scanMode: "sequential",
    enabledTasks: [],
    scanners: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    scannerConfig: {
      semgrep: {},
    },
  };
}

describe("resolveNewazaConfig", () => {
  it("returns defaults when scannerConfig.newaza is not configured", () => {
    const resolved = resolveNewazaConfig(makeConfig());

    expect(resolved.passes).toEqual([1, 2, 3, 4, 5, 6]);
    expect(resolved.labelingBatchSize).toBe(20);
    expect(resolved.labelingConfidenceThreshold).toBe(0.55);
    expect(resolved.workspaceDir).toBe("iris");
    expect(resolved.python3Binary).toBe("python3");
    expect(resolved.codeqlApiProfile).toBe("auto");
    expect(resolved.codeqlProbeTimeoutMs).toBe(20_000);
    expect(resolved.codeqlProfileFallbacks).toBe(true);
  });

  it("normalizes configured values and filters invalid pass ids", () => {
    const config = makeConfig();
    config.scannerConfig.newaza = {
      newazaPath: "./custom-newaza",
      dbPath: "/tmp/db",
      passes: [0, 1, 2, 6, 9],
      labelingModel: "anthropic:claude-sonnet-4-6",
      labelingBatchSize: 7,
      labelingConfidenceThreshold: 0.8,
      workspaceDir: "./iris-custom",
      codeqlBinary: "/usr/local/bin/codeql",
      python3Binary: "python3.12",
      threads: 4,
      ram: 8192,
      maxFindings: 50,
      codeqlApiProfile: "go-dataflow",
      codeqlProbeTimeoutMs: 35_000,
      codeqlProfileFallbacks: false,
    };

    const resolved = resolveNewazaConfig(config);

    expect(resolved.newazaPath).toBe("custom-newaza");
    expect(resolved.dbPath).toBe("/tmp/db");
    expect(resolved.passes).toEqual([1, 2, 6]);
    expect(resolved.labelingBatchSize).toBe(7);
    expect(resolved.labelingConfidenceThreshold).toBe(0.8);
    expect(resolved.workspaceDir).toBe("iris-custom");
    expect(resolved.codeqlBinary).toBe("/usr/local/bin/codeql");
    expect(resolved.python3Binary).toBe("python3.12");
    expect(resolved.threads).toBe(4);
    expect(resolved.ram).toBe(8192);
    expect(resolved.maxFindings).toBe(50);
    expect(resolved.codeqlApiProfile).toBe("go-dataflow");
    expect(resolved.codeqlProbeTimeoutMs).toBe(35_000);
    expect(resolved.codeqlProfileFallbacks).toBe(false);
  });
});
