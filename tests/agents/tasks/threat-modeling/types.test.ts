import { describe, expect, it } from "vitest";
import {
  DEFAULT_THREAT_MODEL_CONFIG,
  resolveThreatModelConfig,
} from "../../../../src/agents/tasks/threat-modeling/config.js";
import type { KuzushiConfig } from "../../../../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {},
  };
}

describe("DEFAULT_THREAT_MODEL_CONFIG", () => {
  it("has expected defaults", () => {
    expect(DEFAULT_THREAT_MODEL_CONFIG.methodology).toBe("pasta");
    expect(DEFAULT_THREAT_MODEL_CONFIG.maxElements).toBe(50);
    expect(DEFAULT_THREAT_MODEL_CONFIG.maxThreats).toBe(20);
    expect(DEFAULT_THREAT_MODEL_CONFIG.emitFindings).toBe(true);
    expect(DEFAULT_THREAT_MODEL_CONFIG.findingThreshold).toBe("medium");
    expect(DEFAULT_THREAT_MODEL_CONFIG.randoriStages).toEqual(["s1", "s2", "s3", "s4"]);
  });
});

describe("resolveThreatModelConfig", () => {
  it("returns defaults when no config", () => {
    const resolved = resolveThreatModelConfig(makeConfig());
    expect(resolved.model).toBe("anthropic:claude-sonnet-4-6");
    expect(resolved.methodology).toBe("pasta");
    expect(resolved.maxElements).toBe(50);
    expect(resolved.maxThreats).toBe(20);
    expect(resolved.emitFindings).toBe(true);
  });

  it("reads overrides from taskConfig", () => {
    const config = makeConfig();
    config.taskConfig["threat-model"] = {
      model: "openai:gpt-4",
      methodology: "dread",
      maxElements: 25,
      maxThreats: 50,
      emitFindings: false,
      findingThreshold: "critical",
      randoriStages: ["s1", "s2", "s3", "s4", "s5"],
    };

    const resolved = resolveThreatModelConfig(config);
    expect(resolved.model).toBe("openai:gpt-4");
    expect(resolved.methodology).toBe("dread");
    expect(resolved.maxElements).toBe(25);
    expect(resolved.maxThreats).toBe(50);
    expect(resolved.emitFindings).toBe(false);
    expect(resolved.findingThreshold).toBe("critical");
    expect(resolved.randoriStages).toEqual(["s1", "s2", "s3", "s4", "s5"]);
  });

  it("falls back to global model", () => {
    const config = makeConfig();
    config.model = "google:gemini-pro";
    config.taskConfig["threat-model"] = {};

    const resolved = resolveThreatModelConfig(config);
    expect(resolved.model).toBe("google:gemini-pro");
  });

  it("accepts legacy strideModel key for backwards compat", () => {
    const config = makeConfig();
    config.taskConfig["threat-model"] = { strideModel: "openai:gpt-4" };

    const resolved = resolveThreatModelConfig(config);
    expect(resolved.model).toBe("openai:gpt-4");
  });

  it("accepts modelType as a methodology alias", () => {
    const config = makeConfig();
    config.taskConfig["threat-model"] = { modelType: "stride" };

    const resolved = resolveThreatModelConfig(config);
    expect(resolved.methodology).toBe("stride");
  });
});
