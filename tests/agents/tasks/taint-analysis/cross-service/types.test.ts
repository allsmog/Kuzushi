import { describe, expect, it } from "vitest";
import {
  resolveCrossServiceConfig,
  isTaintAnalysisLanguage,
} from "../../../../../src/agents/tasks/taint-analysis/cross-service/types.js";
import { resolveTaintAnalysisConfig } from "../../../../../src/agents/tasks/taint-analysis/types.js";
import type { KuzushiConfig } from "../../../../../src/types.js";

function makeConfig(overrides?: Record<string, unknown>): KuzushiConfig {
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
    taskConfig: {
      "taint-analysis": overrides ?? {},
    },
  };
}

describe("resolveTaintAnalysisConfig — crossService fields", () => {
  it("returns crossService defaults when not configured", () => {
    const resolved = resolveTaintAnalysisConfig(makeConfig());

    expect(resolved.crossService).toBe(false);
    expect(resolved.crossServiceBoundaryModel).toBeUndefined();
    expect(resolved.crossServiceStitchModel).toBeUndefined();
    expect(resolved.crossServiceMaxServices).toBe(20);
    expect(resolved.crossServiceConcurrency).toBe(3);
    expect(resolved.crossServiceContinueOnError).toBe(true);
    expect(resolved.crossServiceBoundaryThreshold).toBe(0.5);
    expect(resolved.crossServiceStitchThreshold).toBe(0.6);
    expect(resolved.crossServiceMaxPathDepth).toBe(5);
  });

  it("normalizes crossService: true from config", () => {
    const resolved = resolveTaintAnalysisConfig(makeConfig({ crossService: true }));
    expect(resolved.crossService).toBe(true);
  });

  it("normalizes crossService: 'true' (string) to true", () => {
    const resolved = resolveTaintAnalysisConfig(makeConfig({ crossService: "true" }));
    expect(resolved.crossService).toBe(true);
  });

  it("normalizes crossService: 'false' (string) to false", () => {
    const resolved = resolveTaintAnalysisConfig(makeConfig({ crossService: "false" }));
    expect(resolved.crossService).toBe(false);
  });

  it("applies custom cross-service config values", () => {
    const resolved = resolveTaintAnalysisConfig(makeConfig({
      crossService: true,
      crossServiceBoundaryModel: "openai:gpt-4o",
      crossServiceStitchModel: "anthropic:claude-sonnet-4-6",
      crossServiceMaxServices: 10,
      crossServiceConcurrency: 5,
      crossServiceContinueOnError: false,
      crossServiceBoundaryThreshold: 0.7,
      crossServiceStitchThreshold: 0.8,
      crossServiceMaxPathDepth: 3,
    }));

    expect(resolved.crossService).toBe(true);
    expect(resolved.crossServiceBoundaryModel).toBe("openai:gpt-4o");
    expect(resolved.crossServiceStitchModel).toBe("anthropic:claude-sonnet-4-6");
    expect(resolved.crossServiceMaxServices).toBe(10);
    expect(resolved.crossServiceConcurrency).toBe(5);
    expect(resolved.crossServiceContinueOnError).toBe(false);
    expect(resolved.crossServiceBoundaryThreshold).toBe(0.7);
    expect(resolved.crossServiceStitchThreshold).toBe(0.8);
    expect(resolved.crossServiceMaxPathDepth).toBe(3);
  });

  it("clamps crossServiceBoundaryThreshold to [0, 1]", () => {
    const resolved = resolveTaintAnalysisConfig(makeConfig({
      crossServiceBoundaryThreshold: 2.5,
    }));
    // Falls back to default since 2.5 is out of [0,1]
    expect(resolved.crossServiceBoundaryThreshold).toBe(0.5);
  });

  it("falls back to defaults for invalid numeric cross-service values", () => {
    const resolved = resolveTaintAnalysisConfig(makeConfig({
      crossServiceMaxServices: -1,
      crossServiceConcurrency: "abc",
    }));
    expect(resolved.crossServiceMaxServices).toBe(20);
    expect(resolved.crossServiceConcurrency).toBe(3);
  });
});

describe("resolveCrossServiceConfig", () => {
  it("derives CrossServiceConfig from TaintAnalysisTaskConfig", () => {
    const cfg = resolveTaintAnalysisConfig(makeConfig({
      crossService: true,
      crossServiceBoundaryModel: "openai:gpt-4o",
    }));
    const crossCfg = resolveCrossServiceConfig(cfg);

    expect(crossCfg.enabled).toBe(true);
    expect(crossCfg.boundaryModel).toBe("openai:gpt-4o");
    // stitchModel defaults to labelingModel
    expect(crossCfg.stitchModel).toBe(cfg.labelingModel);
    expect(crossCfg.maxServices).toBe(20);
    expect(crossCfg.concurrency).toBe(3);
    expect(crossCfg.continueOnError).toBe(true);
    expect(crossCfg.boundaryThreshold).toBe(0.5);
    expect(crossCfg.stitchThreshold).toBe(0.6);
    expect(crossCfg.maxPathDepth).toBe(5);
  });

  it("uses labelingModel as fallback for boundary and stitch models", () => {
    const cfg = resolveTaintAnalysisConfig(makeConfig({
      labelingModel: "anthropic:claude-sonnet-4-6",
    }));
    const crossCfg = resolveCrossServiceConfig(cfg);

    expect(crossCfg.boundaryModel).toBe("anthropic:claude-sonnet-4-6");
    expect(crossCfg.stitchModel).toBe("anthropic:claude-sonnet-4-6");
  });
});

describe("isTaintAnalysisLanguage", () => {
  it("returns true for supported languages", () => {
    expect(isTaintAnalysisLanguage("python")).toBe(true);
    expect(isTaintAnalysisLanguage("go")).toBe(true);
    expect(isTaintAnalysisLanguage("java")).toBe(true);
    expect(isTaintAnalysisLanguage("javascript")).toBe(true);
    expect(isTaintAnalysisLanguage("csharp")).toBe(true);
  });

  it("returns false for unsupported languages", () => {
    expect(isTaintAnalysisLanguage("rust")).toBe(false);
    expect(isTaintAnalysisLanguage("ruby")).toBe(false);
    expect(isTaintAnalysisLanguage("php")).toBe(false);
  });

  it("normalizes case before checking", () => {
    expect(isTaintAnalysisLanguage("Python")).toBe(true);
    expect(isTaintAnalysisLanguage("GO")).toBe(true);
    expect(isTaintAnalysisLanguage("JavaScript")).toBe(true);
    expect(isTaintAnalysisLanguage("JAVA")).toBe(true);
    expect(isTaintAnalysisLanguage("CSharp")).toBe(true);
  });
});
