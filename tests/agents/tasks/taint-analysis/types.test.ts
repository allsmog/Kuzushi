import { describe, expect, it } from "vitest";
import {
  DEFAULT_TAINT_ANALYSIS_TASK_CONFIG,
  resolveTaintAnalysisConfig,
  TAINT_ANALYSIS_PASSES,
} from "../../../../src/agents/tasks/taint-analysis/types.js";
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
    taskConfig: {
      semgrep: {},
    },
  };
}

describe("resolveTaintAnalysisConfig", () => {
  it('returns defaults when taskConfig["taint-analysis"] is not configured', () => {
    const resolved = resolveTaintAnalysisConfig(makeConfig());

    expect(resolved.passes).toEqual([
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    ]);
    expect(resolved.labelingBatchSize).toBe(20);
    expect(resolved.labelingConfidenceThreshold).toBe(0.55);
    expect(resolved.workspaceDir).toBe(".kuzushi/iris");
    expect(resolved.python3Binary).toBe("python3");
    expect(resolved.codeqlApiProfile).toBe("auto");
    expect(resolved.codeqlProbeTimeoutMs).toBe(20_000);
    expect(resolved.codeqlProfileFallbacks).toBe(true);
    expect(resolved.tiMode).toBe("live-required");
    expect(resolved.tiFailurePolicy).toBe("continue_without_ti");
    expect(resolved.tiTimeoutMs).toBe(15_000);
    expect(resolved.refinementEnabled).toBe(true);
    expect(resolved.refinementIterations).toBe(2);
    expect(resolved.refinementDeltaOnly).toBe(true);
    expect(resolved.groundingEnabled).toBe(true);
    expect(resolved.taintDiffBase).toBeUndefined();
  });

  it("normalizes configured values and filters invalid pass ids", () => {
    const config = makeConfig();
    config.taskConfig["taint-analysis"] = {
      taintAnalysisPath: "./custom-taint-analysis",
      dbPath: "/tmp/db",
      passes: [0, 1, 2, 6, 14, 20],
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
      tiMode: "live-required",
      tiFailurePolicy: "continue_without_ti",
      tiTimeoutMs: 10_000,
      refinementEnabled: true,
      refinementIterations: 2,
      refinementDeltaOnly: false,
      refinementModel: "anthropic:claude-sonnet-4-6",
    };

    const resolved = resolveTaintAnalysisConfig(config);

    expect(resolved.taintAnalysisPath).toBe("custom-taint-analysis");
    expect(resolved.dbPath).toBe("/tmp/db");
    expect(resolved.passes).toEqual([1, 2, 6, 14]);
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
    expect(resolved.tiMode).toBe("live-required");
    expect(resolved.tiFailurePolicy).toBe("continue_without_ti");
    expect(resolved.tiTimeoutMs).toBe(10_000);
    expect(resolved.refinementEnabled).toBe(true);
    expect(resolved.refinementIterations).toBe(2);
    expect(resolved.refinementDeltaOnly).toBe(false);
    expect(resolved.refinementModel).toBe("anthropic:claude-sonnet-4-6");
  });

  it("normalizePasses accepts pass ids 7 through 13", () => {
    const config = makeConfig();
    config.taskConfig["taint-analysis"] = {
      passes: [7, 8, 9, 10, 11, 12, 13],
    };

    const resolved = resolveTaintAnalysisConfig(config);
    expect(resolved.passes).toEqual([7, 8, 9, 10, 11, 12, 13]);
  });

  it("normalizePasses filters out ids above 19", () => {
    const config = makeConfig();
    config.taskConfig["taint-analysis"] = {
      passes: [1, 13, 19, 20, 99],
    };

    const resolved = resolveTaintAnalysisConfig(config);
    expect(resolved.passes).toEqual([1, 13, 19]);
  });

  it("prefers top-level grounding and diff settings when task overrides are absent", () => {
    const config = makeConfig();
    config.taintGroundingEnabled = false;
    config.taintDiffBase = "main";

    const resolved = resolveTaintAnalysisConfig(config);
    expect(resolved.groundingEnabled).toBe(false);
    expect(resolved.taintDiffBase).toBe("main");
  });
});

describe("TAINT_ANALYSIS_PASSES", () => {
  it("contains all 19 passes", () => {
    expect(TAINT_ANALYSIS_PASSES).toHaveLength(19);
    const ids = TAINT_ANALYSIS_PASSES.map((p) => p.passId);
    expect(ids).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
  });

  it("each pass has a unique passKey", () => {
    const keys = TAINT_ANALYSIS_PASSES.map((p) => p.passKey);
    expect(new Set(keys).size).toBe(19);
  });

  it("each pass has non-empty cwes", () => {
    for (const pass of TAINT_ANALYSIS_PASSES) {
      expect(pass.cwes.length).toBeGreaterThan(0);
    }
  });

  it("new passes have correct definitions", () => {
    const pass7 = TAINT_ANALYSIS_PASSES.find((p) => p.passId === 7);
    expect(pass7?.passKey).toBe("xss");
    expect(pass7?.cwes).toContain("079");

    const pass13 = TAINT_ANALYSIS_PASSES.find((p) => p.passId === 13);
    expect(pass13?.passKey).toBe("ssti");
    expect(pass13?.cwes).toContain("1336");
  });
});

describe("DEFAULT_TAINT_ANALYSIS_TASK_CONFIG", () => {
  it("includes all 19 pass ids in defaults", () => {
    expect(DEFAULT_TAINT_ANALYSIS_TASK_CONFIG.passes).toEqual([
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
    ]);
  });
});
