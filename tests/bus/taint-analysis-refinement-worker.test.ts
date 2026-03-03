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
        hints: [],
      }]]),
    );

    const pass = refined.passes[0];
    const source = pass.entries.find((entry) => entry.id === "src-a");
    const sink = pass.entries.find((entry) => entry.id === "sink-a");
    expect(source?.classification).toBe("fp");
    expect((source?.confidence ?? 1) <= 0.3).toBe(true);
    expect(sink?.classification).toBe("tp");
  });

  it("extracts pass id from taint-analysis rule ids", () => {
    expect(__taintAnalysisRefinementInternals.extractPassId("taint-analysis/pass2/js/path-traversal")).toBe(2);
    expect(__taintAnalysisRefinementInternals.extractPassId("semgrep/rule")).toBeUndefined();
  });
});
