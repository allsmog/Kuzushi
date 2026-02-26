import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { __augurLabelInternals } from "../../../src/agents/tasks/augur-label.js";
import type { AugurLabelsDocument } from "../../../src/agents/tasks/augur-types.js";

const TMP_DIR = path.join(import.meta.dirname, "..", "..", ".tmp-augur-label");

beforeEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
  mkdirSync(TMP_DIR, { recursive: true });
});

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

describe("augur-label internals", () => {
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

    const candidates = await __augurLabelInternals.parseCsvCandidates(csvPath, "source_candidate");
    expect(candidates).toHaveLength(2);
    expect(candidates[0].candidateKind).toBe("source_candidate");
    expect(candidates[0].callable).toBe("Query");
    expect(candidates[0].flowKind).toBe("return");
    expect(candidates[0].argIndex).toBeNull();
    expect(candidates[0].locationLine).toBe(41);
    expect(candidates[1].argIndex).toBe(0);
  });

  it("builds label summary counts and top sinks/sources", () => {
    const labels: AugurLabelsDocument = {
      version: "1.0.0",
      metadata: {
        run_id: "run-1",
        generated_at: new Date().toISOString(),
        language: "python",
        framework: "fastapi",
        model: "claude-sonnet-4-20250514",
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

    const summary = __augurLabelInternals.summarizeLabels(labels, 0.55);
    expect(summary.labelCounts["pass1.source"]).toBe(1);
    expect(summary.labelCounts["pass1.sink"]).toBe(1);
    expect(summary.reviewSummary).toContain("low-confidence entries");
    expect(summary.reviewSummary).toContain("open(1)");
    expect(summary.reviewSummary).toContain("Query(1)");
  });

  it("validates minimal labels document contract", () => {
    const invalid: AugurLabelsDocument = {
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

    const error = __augurLabelInternals.validateLabelsDocument(invalid);
    expect(error).toContain("version");
  });
});
