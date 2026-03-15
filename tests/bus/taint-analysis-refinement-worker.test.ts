import { describe, expect, it } from "vitest";
import { __taintAnalysisRefinementInternals } from "../../src/bus/workers/taint-analysis-refinement-worker.js";
import type { TaintAnalysisLabelsDocument } from "../../src/agents/tasks/taint-analysis/types.js";

function makeLabels(): TaintAnalysisLabelsDocument {
  return {
    version: "1.0.0",
    metadata: {
      run_id: "run-refine",
      generated_at: new Date().toISOString(),
      language: "python",
      framework: "fastapi",
      model: "anthropic:claude-sonnet-4-6",
      project: "repo",
    },
    passes: [
      {
        pass_id: 1,
        focus: "Path Traversal",
        cwes: ["022"],
        entries: [
          {
            id: "src-a",
            role: "source",
            classification: "tp",
            confidence: 0.41,
            signature: {
              package: null,
              module: "api",
              type: null,
              callable: "Query",
              arg_index: null,
              flow_kind: "return",
            },
            location: { file: "a.py", line: 1 },
            rationale: "r1",
          },
          {
            id: "sink-a",
            role: "sink",
            classification: "tp",
            confidence: 0.91,
            signature: {
              package: null,
              module: "os",
              type: null,
              callable: "open",
              arg_index: 0,
              flow_kind: "argument",
            },
            location: { file: "b.py", line: 2 },
            rationale: "r2",
          },
        ],
      },
    ],
  };
}

describe("taint-analysis refinement internals", () => {
  it("downgrades role entries using deterministic false-positive signals", () => {
    const refined = __taintAnalysisRefinementInternals.applyDeterministicPatch(
      makeLabels(),
      new Map([[1, {
        sourceFalsePositive: true,
        sinkFalsePositive: false,
        sourceFpCount: 1,
        sinkFpCount: 0,
        hints: [],
      }]]),
      0.3,
    );

    const pass = refined.passes[0];
    const source = pass.entries.find((entry) => entry.id === "src-a");
    const sink = pass.entries.find((entry) => entry.id === "sink-a");
    expect(source?.classification).toBe("fp");
    expect((source?.confidence ?? 1) <= 0.3).toBe(true);
    expect(sink?.classification).toBe("tp");
  });

  it("proportional downgrade: 1 signal downgrades exactly 1 entry", () => {
    const labels = makeLabels();
    // Add extra source entries so there are multiple candidates
    labels.passes[0].entries.push(
      { ...labels.passes[0].entries[0], id: "src-b", confidence: 0.5 },
      { ...labels.passes[0].entries[0], id: "src-c", confidence: 0.6 },
    );

    const refined = __taintAnalysisRefinementInternals.applyDeterministicPatch(
      labels,
      new Map([[1, {
        sourceFalsePositive: true,
        sinkFalsePositive: false,
        sourceFpCount: 1,
        sinkFpCount: 0,
        hints: [],
      }]]),
      0.3,
    );

    const sources = refined.passes[0].entries.filter((e) => e.role === "source");
    const downgraded = sources.filter((e) => e.classification === "fp");
    expect(downgraded).toHaveLength(1);
  });

  it("proportional downgrade: 2 signals downgrade exactly 2 entries", () => {
    const labels = makeLabels();
    labels.passes[0].entries.push(
      { ...labels.passes[0].entries[0], id: "src-b", confidence: 0.5 },
      { ...labels.passes[0].entries[0], id: "src-c", confidence: 0.6 },
    );

    const refined = __taintAnalysisRefinementInternals.applyDeterministicPatch(
      labels,
      new Map([[1, {
        sourceFalsePositive: true,
        sinkFalsePositive: false,
        sourceFpCount: 2,
        sinkFpCount: 0,
        hints: [],
      }]]),
      0.3,
    );

    const sources = refined.passes[0].entries.filter((e) => e.role === "source");
    const downgraded = sources.filter((e) => e.classification === "fp");
    expect(downgraded).toHaveLength(2);
  });

  it("respects custom confidence cap", () => {
    const refined = __taintAnalysisRefinementInternals.applyDeterministicPatch(
      makeLabels(),
      new Map([[1, {
        sourceFalsePositive: true,
        sinkFalsePositive: false,
        sourceFpCount: 1,
        sinkFpCount: 0,
        hints: [],
      }]]),
      0.15,
    );

    const source = refined.passes[0].entries.find((e) => e.id === "src-a");
    expect((source?.confidence ?? 1) <= 0.15).toBe(true);
  });

  it("extracts pass id from taint-analysis rule ids", () => {
    expect(__taintAnalysisRefinementInternals.extractPassId("taint-analysis/pass2/js/path-traversal")).toBe(2);
    expect(__taintAnalysisRefinementInternals.extractPassId("semgrep/rule")).toBeUndefined();
  });

  it("rejects pass id 0 (below valid range)", () => {
    expect(__taintAnalysisRefinementInternals.extractPassId("taint-analysis/pass0/test")).toBeUndefined();
  });

  it("rejects pass id 20 (above valid range)", () => {
    expect(__taintAnalysisRefinementInternals.extractPassId("taint-analysis/pass20/test")).toBeUndefined();
  });

  it("accepts pass id 1 (lower bound)", () => {
    expect(__taintAnalysisRefinementInternals.extractPassId("taint-analysis/pass1/test")).toBe(1);
  });

  it("accepts pass id 19 (upper bound)", () => {
    expect(__taintAnalysisRefinementInternals.extractPassId("taint-analysis/pass19/test")).toBe(19);
  });
});
