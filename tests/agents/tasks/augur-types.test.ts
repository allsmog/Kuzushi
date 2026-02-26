import { describe, expect, it } from "vitest";
import { resolveAugurConfig } from "../../../src/agents/tasks/augur-types.js";
import type { KuzushiConfig } from "../../../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    model: "claude-sonnet-4-20250514",
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

describe("resolveAugurConfig", () => {
  it("returns defaults when scannerConfig.augur is not configured", () => {
    const resolved = resolveAugurConfig(makeConfig());

    expect(resolved.passes).toEqual([1, 2, 3, 4, 5, 6]);
    expect(resolved.labelingBatchSize).toBe(20);
    expect(resolved.labelingConfidenceThreshold).toBe(0.55);
    expect(resolved.autoApproveCheckpoint).toBe(false);
    expect(resolved.workspaceDir).toBe("iris");
    expect(resolved.python3Binary).toBe("python3");
  });

  it("normalizes configured values and filters invalid pass ids", () => {
    const config = makeConfig();
    config.scannerConfig.augur = {
      augurPath: "./custom-augur",
      dbPath: "/tmp/db",
      passes: [0, 1, 2, 6, 9],
      labelingModel: "claude-sonnet-4-20250514",
      labelingBatchSize: 7,
      labelingConfidenceThreshold: 0.8,
      autoApproveCheckpoint: true,
      workspaceDir: "./iris-custom",
      codeqlBinary: "/usr/local/bin/codeql",
      python3Binary: "python3.12",
      threads: 4,
      ram: 8192,
      maxFindings: 50,
    };

    const resolved = resolveAugurConfig(config);

    expect(resolved.augurPath).toBe("custom-augur");
    expect(resolved.dbPath).toBe("/tmp/db");
    expect(resolved.passes).toEqual([1, 2, 6]);
    expect(resolved.labelingBatchSize).toBe(7);
    expect(resolved.labelingConfidenceThreshold).toBe(0.8);
    expect(resolved.autoApproveCheckpoint).toBe(true);
    expect(resolved.workspaceDir).toBe("iris-custom");
    expect(resolved.codeqlBinary).toBe("/usr/local/bin/codeql");
    expect(resolved.python3Binary).toBe("python3.12");
    expect(resolved.threads).toBe(4);
    expect(resolved.ram).toBe(8192);
    expect(resolved.maxFindings).toBe(50);
  });
});
