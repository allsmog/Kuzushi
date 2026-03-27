import { describe, expect, it } from "vitest";
import { shouldRegisterPocExecutorWorker } from "../../src/bus/index.js";
import type { KuzushiConfig } from "../../src/types.js";

function makeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    scanners: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    scannerConfig: { semgrep: {} },
    verify: false,
    verifyRefinementMaxIterations: 3,
    pocHarness: false,
    pocExecute: false,
    ...overrides,
  };
}

describe("shouldRegisterPocExecutorWorker", () => {
  it("does not require a PoC executor for plain scans with verification disabled", () => {
    expect(shouldRegisterPocExecutorWorker(makeConfig())).toBe(false);
  });

  it("requires a PoC executor for refined verification when verification is enabled", () => {
    expect(shouldRegisterPocExecutorWorker(makeConfig({
      verify: true,
      verifyRefinementMaxIterations: 2,
    }))).toBe(true);
  });

  it("requires a PoC executor when harness generation is enabled", () => {
    expect(shouldRegisterPocExecutorWorker(makeConfig({
      pocHarness: true,
    }))).toBe(true);
  });

  it("requires a PoC executor when direct PoC execution is enabled", () => {
    expect(shouldRegisterPocExecutorWorker(makeConfig({
      pocExecute: true,
    }))).toBe(true);
  });
});
