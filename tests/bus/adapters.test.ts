import { describe, expect, it } from "vitest";
import { createBus } from "../../src/bus/adapters/index.js";
import type { KuzushiConfig } from "../../src/types.js";

function baseConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    scanners: ["semgrep"],
    severity: ["ERROR", "WARNING"],
    excludePatterns: ["node_modules"],
    scannerConfig: {
      semgrep: {},
    },
  };
}

describe("createBus", () => {
  it("creates in-process bus", () => {
    const bus = createBus(baseConfig());
    expect(bus).toBeTruthy();
  });

  it("throws for unsupported redis adapter placeholder", () => {
    const config = baseConfig();
    config.busBackend = "redis";
    expect(() => createBus(config)).toThrow("busBackend=redis is not available");
  });

  it("throws for unknown backend typo", () => {
    const config = {
      ...baseConfig(),
      busBackend: "reddis",
    } as KuzushiConfig;

    expect(() => createBus(config)).toThrow("Unknown bus backend");
  });
});
