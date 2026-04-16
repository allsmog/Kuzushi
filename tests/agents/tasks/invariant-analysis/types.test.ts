import { describe, expect, it } from "vitest";
import {
  DEFAULT_INVARIANT_ANALYSIS_CONFIG,
  resolveInvariantAnalysisConfig,
} from "../../../../src/agents/tasks/invariant-analysis/types.js";
import type { KuzushiConfig } from "../../../../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: [],
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
  };
}

describe("DEFAULT_INVARIANT_ANALYSIS_CONFIG", () => {
  it("has expected defaults", () => {
    expect(DEFAULT_INVARIANT_ANALYSIS_CONFIG.maxInvariants).toBe(200);
    expect(DEFAULT_INVARIANT_ANALYSIS_CONFIG.securityOnly).toBe(true);
    expect(DEFAULT_INVARIANT_ANALYSIS_CONFIG.confidenceThreshold).toBe(0.4);
    expect(DEFAULT_INVARIANT_ANALYSIS_CONFIG.checkBatchSize).toBe(50);
  });
});

describe("resolveInvariantAnalysisConfig", () => {
  it("returns defaults when no config", () => {
    const resolved = resolveInvariantAnalysisConfig(makeConfig());
    expect(resolved.extractionModel).toBe("anthropic:claude-sonnet-4-6");
    expect(resolved.checkModel).toBe("anthropic:claude-sonnet-4-6");
    expect(resolved.maxInvariants).toBe(200);
    expect(resolved.securityOnly).toBe(true);
    expect(resolved.confidenceThreshold).toBe(0.4);
    expect(resolved.checkBatchSize).toBe(50);
  });

  it("reads overrides from taskConfig", () => {
    const config = makeConfig();
    config.taskConfig["invariant-analysis"] = {
      extractionModel: "openai:gpt-4",
      checkModel: "openai:gpt-4",
      maxInvariants: 100,
      securityOnly: false,
      confidenceThreshold: 0.8,
    };

    const resolved = resolveInvariantAnalysisConfig(config);
    expect(resolved.extractionModel).toBe("openai:gpt-4");
    expect(resolved.checkModel).toBe("openai:gpt-4");
    expect(resolved.maxInvariants).toBe(100);
    expect(resolved.securityOnly).toBe(false);
    expect(resolved.confidenceThreshold).toBe(0.8);
  });

  it("falls back to global model for extraction/check models", () => {
    const config = makeConfig();
    config.model = "google:gemini-pro";
    config.taskConfig["invariant-analysis"] = {};

    const resolved = resolveInvariantAnalysisConfig(config);
    expect(resolved.extractionModel).toBe("google:gemini-pro");
    expect(resolved.checkModel).toBe("google:gemini-pro");
  });

  it("clamps invalid confidenceThreshold", () => {
    const config = makeConfig();
    config.taskConfig["invariant-analysis"] = { confidenceThreshold: 2.0 };

    const resolved = resolveInvariantAnalysisConfig(config);
    expect(resolved.confidenceThreshold).toBe(0.4);
  });
});
