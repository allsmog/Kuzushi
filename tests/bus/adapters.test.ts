import { describe, expect, it } from "vitest";
import { createBus } from "../../src/bus/adapters/index.js";
import type { KuzushiConfig } from "../../src/types.js";

function baseConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
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

  it("rejects unsupported distributed backends before runtime dispatch", () => {
    const config = baseConfig();
    config.busBackend = "redis" as KuzushiConfig["busBackend"];
    expect(() => createBus(config)).toThrow("Unknown bus backend");
  });

  it("throws for unknown backend typo", () => {
    const config = {
      ...baseConfig(),
      busBackend: "reddis",
    } as KuzushiConfig;

    expect(() => createBus(config)).toThrow("Unknown bus backend");
  });
});
