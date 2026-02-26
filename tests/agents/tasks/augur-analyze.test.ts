import { describe, expect, it } from "vitest";
import { __augurAnalyzeInternals } from "../../../src/agents/tasks/augur-analyze.js";
import type { AugurLabelsDocument } from "../../../src/agents/tasks/augur-types.js";
import type { Finding } from "../../../src/scanners/types.js";

function makeLabels(): AugurLabelsDocument {
  return {
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
        cwes: ["022", "023"],
        entries: [
          {
            id: "p1-src",
            role: "source",
            classification: "candidate",
            confidence: 0.8,
            signature: {
              package: null,
              module: "fastapi",
              type: null,
              callable: "Query",
              arg_index: null,
              flow_kind: "return",
            },
            location: {
              file: "a.py",
              line: 1,
            },
            rationale: "r",
          },
          {
            id: "p1-sink",
            role: "sink",
            classification: "candidate",
            confidence: 0.9,
            signature: {
              package: null,
              module: "builtins",
              type: null,
              callable: "open",
              arg_index: 0,
              flow_kind: "argument",
            },
            location: {
              file: "b.py",
              line: 2,
            },
            rationale: "r",
          },
        ],
      },
    ],
  };
}

describe("augur-analyze internals", () => {
  it("renders deterministic libraries", () => {
    const libs = __augurAnalyzeInternals.renderAugurLibraries(makeLabels(), "python");
    expect(libs.sources).toContain("module MySources");
    expect(libs.sources).toContain("passKey = \"path_traversal\"");
    expect(libs.sources).toContain("Query");
    expect(libs.sinks).toContain("open");
    expect(libs.sanitizers).toContain("none()");
  });

  it("renders taint query from template substitutions", () => {
    const template = [
      "{{QUERY_NAME}}",
      "{{QUERY_ID}}",
      "{{CWE_PRIMARY}}",
      "{{SOURCE_MODULE}}",
      "{{PASS_KEY}}",
      "{{LANGUAGE_IMPORTS}}",
      "{{RESULT_MESSAGE}}",
    ].join("\n");

    const query = __augurAnalyzeInternals.renderTaintQuery(template, {
      passId: 1,
      passKey: "path_traversal",
      focus: "Path Traversal",
      cwes: ["022", "023"],
    }, "python");

    expect(query).toContain("Augur Pass 1 - Path Traversal");
    expect(query).toContain("py/augur/pass1-path-traversal");
    expect(query).toContain("022");
    expect(query).toContain("libraries.MySources");
    expect(query).toContain("path_traversal");
    expect(query).toContain("import python");
  });

  it("throws when taint query template leaves unresolved placeholders", () => {
    expect(() => __augurAnalyzeInternals.renderTaintQuery(
      "{{QUERY_NAME}}\n{{UNHANDLED_PLACEHOLDER}}",
      {
        passId: 1,
        passKey: "path_traversal",
        focus: "Path Traversal",
        cwes: ["022", "023"],
      },
      "python",
    )).toThrow("unresolved placeholders");
  });

  it("augments findings with Augur metadata", () => {
    const base: Finding = {
      scanner: "codeql",
      fingerprint: "fp",
      ruleId: "rule",
      filePath: "src/a.py",
      startLine: 10,
      severity: "ERROR",
      message: "m",
      evidence: "flow",
      scannerConfidence: "HIGH",
      subcategory: ["vuln"],
      likelihood: "HIGH",
      impact: "HIGH",
      cwe: ["CWE-000"],
      score: 1,
    };

    const augmented = __augurAnalyzeInternals.augmentFinding(base, {
      passId: 1,
      passKey: "path_traversal",
      focus: "Path Traversal",
      cwes: ["022", "023"],
    }, makeLabels());

    expect(augmented.scanner).toBe("augur-analyze");
    expect(augmented.ruleId).toContain("augur/pass1/");
    expect(augmented.message).toContain("[Augur Path Traversal]");
    expect(augmented.cwe).toEqual(["CWE-022", "CWE-023"]);
    expect(augmented.evidence).toContain("Augur pass 1");
  });
});
