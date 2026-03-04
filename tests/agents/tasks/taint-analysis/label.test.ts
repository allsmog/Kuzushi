import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { __taintAnalysisLabelInternals } from "../../../../src/agents/tasks/taint-analysis/label.js";
import type { TaintAnalysisLabelsDocument } from "../../../../src/agents/tasks/taint-analysis/types.js";
import type { TiPriorDocument } from "../../../../src/agents/tasks/taint-analysis/ti-prior.js";

const TMP_DIR = path.join(import.meta.dirname, "..", "..", "..", ".tmp-taint-analysis-label");

beforeEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
  mkdirSync(TMP_DIR, { recursive: true });
});

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

describe("taint-analysis-label internals", () => {
  it("flags no-sources when preflight reports zero source rows", () => {
    const status = __taintAnalysisLabelInternals.resolveSourceAvailability(
      {
        extraction: { sourcesRowCount: 0 },
      } as unknown as Parameters<typeof __taintAnalysisLabelInternals.resolveSourceAvailability>[0],
      [
        {
          id: "sink-1",
          candidateKind: "sink_candidate",
          callable: "open",
          flowKind: "argument",
          receiverHint: null,
          moduleHint: "app.py",
          argIndex: 0,
          locationFile: "app.py",
          locationLine: 12,
        },
      ],
    );

    expect(status.noSourcesExtracted).toBe(true);
    expect(status.parsedSourceCount).toBe(0);
  });

  it("flags no-sources when parsed candidates contain no source markers", () => {
    const status = __taintAnalysisLabelInternals.resolveSourceAvailability(
      {
        extraction: { sourcesRowCount: 5 },
      } as unknown as Parameters<typeof __taintAnalysisLabelInternals.resolveSourceAvailability>[0],
      [
        {
          id: "sink-1",
          candidateKind: "sink_candidate",
          callable: "open",
          flowKind: "argument",
          receiverHint: null,
          moduleHint: "app.py",
          argIndex: 0,
          locationFile: "app.py",
          locationLine: 12,
        },
      ],
    );

    expect(status.noSourcesExtracted).toBe(true);
    expect(status.parsedSourceCount).toBe(0);
  });

  it("parses extraction CSV candidate rows", async () => {
    const csvPath = path.join(TMP_DIR, "sources.csv");
    writeFileSync(
      csvPath,
      [
        "col0,col1,col2,col3,col4,col5,col6,col7",
        "x,source_candidate,Query,flow_kind=return,receiver=req,module=backend/api.py,arg_index=-1,41",
        "x,source_candidate,Body,flow_kind=param,receiver=handler,module=backend/admin.py,arg_index=0,54",
      ].join("\n"),
      "utf-8",
    );

    const candidates = await __taintAnalysisLabelInternals.parseCsvCandidates(csvPath, "source_candidate");
    expect(candidates).toHaveLength(2);
    expect(candidates[0].candidateKind).toBe("source_candidate");
    expect(candidates[0].callable).toBe("Query");
    expect(candidates[0].flowKind).toBe("return");
    expect(candidates[0].argIndex).toBeNull();
    expect(candidates[0].locationLine).toBe(41);
    expect(candidates[1].argIndex).toBe(0);
  });

  it("builds label summary counts and top sinks/sources", () => {
    const labels: TaintAnalysisLabelsDocument = {
      version: "1.0.0",
      metadata: {
        run_id: "run-1",
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
              id: "e1",
              role: "source",
              classification: "candidate",
              confidence: 0.9,
              signature: {
                package: null,
                module: "fastapi",
                type: null,
                callable: "Query",
                arg_index: null,
                flow_kind: "return",
              },
              location: { file: "a.py", line: 1 },
              rationale: "r",
            },
            {
              id: "e2",
              role: "sink",
              classification: "candidate",
              confidence: 0.4,
              signature: {
                package: null,
                module: "builtins",
                type: null,
                callable: "open",
                arg_index: 0,
                flow_kind: "argument",
              },
              location: { file: "b.py", line: 2 },
              rationale: "r",
            },
          ],
        },
      ],
    };

    const summary = __taintAnalysisLabelInternals.summarizeLabels(labels, 0.55);
    expect(summary.labelCounts["pass1.source"]).toBe(1);
    expect(summary.labelCounts["pass1.sink"]).toBe(1);
    expect(summary.reviewSummary).toContain("low-confidence entries");
    expect(summary.reviewSummary).toContain("open(1)");
    expect(summary.reviewSummary).toContain("Query(1)");
  });

  it("validates minimal labels document contract", () => {
    const invalid: TaintAnalysisLabelsDocument = {
      version: "bad",
      metadata: {
        run_id: "",
        generated_at: new Date().toISOString(),
        language: "python",
        framework: null,
        model: "",
        project: "",
      },
      passes: [],
    };

    const error = __taintAnalysisLabelInternals.validateLabelsDocument(invalid);
    expect(error).toContain("version");
  });

  it("builds TAINT_MODEL with TI basis and confidence weighting", () => {
    const labels: TaintAnalysisLabelsDocument = {
      version: "1.0.0",
      metadata: {
        run_id: "run-2",
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
              id: "src-1",
              role: "source",
              classification: "tp",
              confidence: 0.5,
              signature: {
                package: null,
                module: "fastapi",
                type: null,
                callable: "Query",
                arg_index: null,
                flow_kind: "return",
              },
              location: { file: "api.py", line: 12 },
              rationale: "user input boundary",
            },
            {
              id: "sink-1",
              role: "sink",
              classification: "tp",
              confidence: 0.6,
              signature: {
                package: null,
                module: "os",
                type: null,
                callable: "open",
                arg_index: 0,
                flow_kind: "argument",
              },
              location: { file: "fs.py", line: 23 },
              rationale: "filesystem access",
            },
          ],
        },
      ],
    };

    const tiPrior: TiPriorDocument = {
      version: "1.0.0",
      generatedAt: new Date().toISOString(),
      mode: "live-required",
      degraded: false,
      errors: [],
      cwes: [
        {
          cwe: "CWE-22",
          focus: "Path Traversal",
          exploitationStory: "story",
          sourceArchetypes: ["HTTP params"],
          sinkArchetypes: ["file open"],
          sanitizers: ["realpath"],
          references: [
            {
              source: "cisa-kev",
              id: "CVE-2024-12345",
              url: "https://example.invalid/CVE-2024-12345",
              title: "example",
            },
          ],
          tiWeight: "HIGH",
          highPriority: ["download handlers"],
          commonFalsePositives: ["fixed base dir"],
          oftenExploitable: ["unsanitized join"],
        },
      ],
    };

    const taintModel = __taintAnalysisLabelInternals.buildTaintModelDocument(labels, tiPrior);
    const cwe22 = taintModel.cwes.find((entry) => entry.cwe === "CWE-22");

    expect(cwe22).toBeDefined();
    expect(cwe22?.sources[0]?.ti_basis).toContain("weight=HIGH");
    expect(cwe22?.sources[0]?.confidence).toBeCloseTo(0.6, 5);
    expect(cwe22?.sinks[0]?.sink_focus).toBe("argument[0]");
  });
});
