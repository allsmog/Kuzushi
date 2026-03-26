import { describe, expect, it } from "vitest";
import type { AgentRuntime } from "../../../src/agent-runtime/types.js";
import { quickClassifierTask } from "../../../src/agents/tasks/quick-classifier.js";
import { InProcessBus } from "../../../src/bus/adapters/in-process.js";
import type { Finding } from "../../../src/scanners/types.js";
import { getTaskOutputMeta } from "../../../src/task-output-meta.js";
import type { KuzushiConfig } from "../../../src/types.js";

function makeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    classifierThreshold: 0.5,
    triageConcurrency: 2,
    busBackend: "in-process",
    triageBatchSize: 15,
    scanMode: "sequential",
    scanners: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    scannerConfig: { semgrep: {} },
    ...overrides,
  };
}

function makeFinding(fp: string, ruleId: string): Finding {
  return {
    scanner: "semgrep",
    fingerprint: fp,
    ruleId,
    filePath: "src/app.ts",
    startLine: 10,
    severity: "ERROR",
    message: "possible vulnerability",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-79"],
    score: 80,
  };
}

describe("quick-classifier task", () => {
  it("filters out likely false positives and records cost", async () => {
    const runtime: AgentRuntime = {
      id: "test-runtime",
      async *query(request) {
        yield {
          type: "result",
          subtype: "success",
          result: request.prompt.includes("false.rule")
            ? "FALSE"
            : "REAL",
          totalCostUsd: 0.001,
        };
      },
    };

    const output = await quickClassifierTask.run(
      [
        makeFinding("fp-real", "real.rule"),
        makeFinding("fp-false", "false.rule"),
      ],
      {
        runId: "run-1",
        repoRoot: "/tmp/repo",
        repoName: "repo",
        config: makeConfig({ classifierModel: "anthropic:claude-haiku-4-5" }),
        runtime,
        bus: new InProcessBus(),
        upstreamOutputs: new Map(),
      },
    );

    expect(output.findings.map((finding) => finding.fingerprint)).toEqual(["fp-real"]);
    expect(output.decisions).toEqual([
      expect.objectContaining({ fingerprint: "fp-real", label: "LIKELY_REAL", model: "anthropic:claude-haiku-4-5" }),
      expect.objectContaining({ fingerprint: "fp-false", label: "LIKELY_FALSE_POSITIVE", model: "anthropic:claude-haiku-4-5" }),
    ]);
    expect(getTaskOutputMeta(output)?.costUsd).toBeCloseTo(0.002);
  });

  it("fails open when the classifier returns an invalid label", async () => {
    const runtime: AgentRuntime = {
      id: "test-runtime",
      async *query() {
        yield {
          type: "result",
          subtype: "success",
          result: "MAYBE",
          totalCostUsd: 0.001,
        };
      },
    };

    const output = await quickClassifierTask.run(
      [makeFinding("fp-1", "unknown.rule")],
      {
        runId: "run-2",
        repoRoot: "/tmp/repo",
        repoName: "repo",
        config: makeConfig(),
        runtime,
        bus: new InProcessBus(),
        upstreamOutputs: new Map(),
      },
    );

    expect(output.findings.map((finding) => finding.fingerprint)).toEqual(["fp-1"]);
    expect(output.decisions[0]).toEqual(
      expect.objectContaining({ label: "LIKELY_REAL", confidence: 1 }),
    );
  });
});
