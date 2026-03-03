import { describe, expect, it, vi } from "vitest";
import { __newazaAnalyzeInternals } from "../../../../src/agents/tasks/newaza/analyze.js";
import { profileById } from "../../../../src/agents/tasks/newaza/codeql-compat.js";
import type { NewazaLabelsDocument } from "../../../../src/agents/tasks/newaza/types.js";
import type { Finding } from "../../../../src/scanners/types.js";

function makeLabels(): NewazaLabelsDocument {
  return {
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

describe("newaza-analyze internals", () => {
  it("renders deterministic libraries", () => {
    const pythonProfile = profileById("python", "python-dataflow-new");
    expect(pythonProfile).not.toBeNull();
    if (!pythonProfile) {
      return;
    }

    const libs = __newazaAnalyzeInternals.renderNewazaLibraries(makeLabels(), pythonProfile);
    expect(libs.sources).toContain("module MySources");
    expect(libs.sources).toContain("passKey = \"path_traversal\"");
    expect(libs.sources).toContain("Query");
    expect(libs.sources).not.toContain("nodeHasCallable");
    expect(libs.sinks).toContain("open");
    expect(libs.sinks).not.toContain("nodeHasCallable");
    expect(libs.sanitizers).toContain("regexpMatch(\"a^\")");
    expect(libs.sanitizers).not.toContain("nodeHasCallable");
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

    const pythonProfile = profileById("python", "python-dataflow-new");
    expect(pythonProfile).not.toBeNull();
    if (!pythonProfile) {
      return;
    }

    const query = __newazaAnalyzeInternals.renderTaintQuery(template, {
      passId: 1,
      passKey: "path_traversal",
      focus: "Path Traversal",
      cwes: ["022", "023"],
    }, pythonProfile);

    expect(query).toContain("Newaza Pass 1 - Path Traversal");
    expect(query).toContain("py/newaza/pass1-path-traversal");
    expect(query).toContain("022");
    expect(query).toContain("MySources");
    expect(query).toContain("path_traversal");
    expect(query).toContain("import python");
    expect(query).not.toContain("$@");
  });

  it("renders Go taint query imports without legacy .new modules", () => {
    const template = "{{LANGUAGE_IMPORTS}}";
    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) {
      return;
    }

    const query = __newazaAnalyzeInternals.renderTaintQuery(template, {
      passId: 1,
      passKey: "path_traversal",
      focus: "Path Traversal",
      cwes: ["022"],
    }, goProfile);

    expect(query).toContain("import semmle.go.dataflow.DataFlow");
    expect(query).toContain("import semmle.go.dataflow.TaintTracking");
    expect(query).not.toContain("semmle.go.dataflow.new.");
  });

  it("escapes regex metacharacters in callable matchers for non-Go languages", () => {
    const labels = makeLabels();
    labels.passes[0].entries[0].signature.callable = "fmt.Sprintf";
    labels.metadata.language = "python";
    const pythonProfile = profileById("python", "python-dataflow-new");
    expect(pythonProfile).not.toBeNull();
    if (!pythonProfile) {
      return;
    }

    const libs = __newazaAnalyzeInternals.renderNewazaLibraries(labels, pythonProfile);

    expect(libs.sources).toContain("regexpMatch(\".*\\\\bfmt\\\\.Sprintf\\\\b.*\")");
  });

  it("Go sources use getTarget().getName() + getResult()", () => {
    const labels = makeLabels();
    labels.metadata.language = "go";
    labels.passes[0].entries[0].signature.callable = "Sprintf";
    labels.passes[0].entries[0].role = "source";
    labels.passes[0].entries[0].signature.flow_kind = "return";
    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) {
      return;
    }

    const libs = __newazaAnalyzeInternals.renderNewazaLibraries(labels, goProfile);

    expect(libs.sources).toContain("DataFlow::CallNode call");
    expect(libs.sources).toContain('call.getTarget().getName() = "Sprintf"');
    expect(libs.sources).toContain("call.getResult()");
    // The path_traversal pass clause uses Go-specific predicates, not regexpMatch
    const pathTraversalClause = libs.sources.split("passKey = \"path_traversal\"")[1]?.split("or\n")[0] ?? "";
    expect(pathTraversalClause).not.toContain("regexpMatch");
  });

  it("Go sinks use getTarget().getName() + getAnArgument()", () => {
    const labels = makeLabels();
    labels.metadata.language = "go";
    labels.passes[0].entries[1].signature.callable = "ExecContext";
    labels.passes[0].entries[1].role = "sink";
    labels.passes[0].entries[1].signature.arg_index = null;
    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) {
      return;
    }

    const libs = __newazaAnalyzeInternals.renderNewazaLibraries(labels, goProfile);

    expect(libs.sinks).toContain("DataFlow::CallNode call");
    expect(libs.sinks).toContain('call.getTarget().getName() = "ExecContext"');
    expect(libs.sinks).toContain("call.getAnArgument()");
    // The path_traversal pass clause uses Go-specific predicates, not regexpMatch
    const pathTraversalClause = libs.sinks.split("passKey = \"path_traversal\"")[1]?.split("or\n")[0] ?? "";
    expect(pathTraversalClause).not.toContain("regexpMatch");
  });

  it("Go sink with specific argIndex uses getArgument(N)", () => {
    const labels = makeLabels();
    labels.metadata.language = "go";
    labels.passes[0].entries[1].signature.callable = "ExecContext";
    labels.passes[0].entries[1].role = "sink";
    labels.passes[0].entries[1].signature.arg_index = 1;
    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) {
      return;
    }

    const libs = __newazaAnalyzeInternals.renderNewazaLibraries(labels, goProfile);

    expect(libs.sinks).toContain("call.getArgument(1)");
    expect(libs.sinks).not.toContain("getAnArgument");
  });

  it("Python still uses regexpMatch for callable matchers", () => {
    const pythonProfile = profileById("python", "python-dataflow-new");
    expect(pythonProfile).not.toBeNull();
    if (!pythonProfile) {
      return;
    }

    const libs = __newazaAnalyzeInternals.renderNewazaLibraries(makeLabels(), pythonProfile);

    expect(libs.sources).toContain("regexpMatch");
    expect(libs.sources).toContain("Query");
    expect(libs.sinks).toContain("regexpMatch");
    expect(libs.sinks).toContain("open");
    expect(libs.sources).not.toContain("DataFlow::CallNode");
  });

  it("throws when taint query template leaves unresolved placeholders", () => {
    const pythonProfile = profileById("python", "python-dataflow-new");
    expect(pythonProfile).not.toBeNull();
    if (!pythonProfile) {
      return;
    }

    expect(() => __newazaAnalyzeInternals.renderTaintQuery(
      "{{QUERY_NAME}}\n{{UNHANDLED_PLACEHOLDER}}",
      {
        passId: 1,
        passKey: "path_traversal",
        focus: "Path Traversal",
        cwes: ["022", "023"],
      },
      pythonProfile,
    )).toThrow("unresolved placeholders");
  });

  it("tries fallback profiles in order when compile gate fails", async () => {
    const selected = await __newazaAnalyzeInternals.selectProfileWithCompileGate({
      language: "go",
      initialProfileId: "go-dataflow",
      fallbackEnabled: true,
      tryProfile: async (profile: { id: string }) => {
        if (profile.id === "go-dataflow") {
          return {
            passQueries: [],
            error: "first failed",
          };
        }
        return {
          passQueries: [],
          error: null,
        };
      },
    });

    expect(selected.selected?.id).toBe("go-dataflow-new");
    expect(selected.attempts).toEqual([
      { id: "go-dataflow", ok: false, error: "first failed" },
      { id: "go-dataflow-new", ok: true },
    ]);
  });

  it("does not try fallback profiles when fallback is disabled", async () => {
    const tryProfile = vi.fn(async (profile: { id: string }) => {
      if (profile.id === "go-dataflow") {
        return {
          passQueries: [],
          error: "failed",
        };
      }
      return {
        passQueries: [],
        error: null,
      };
    });

    const selected = await __newazaAnalyzeInternals.selectProfileWithCompileGate({
      language: "go",
      initialProfileId: "go-dataflow",
      fallbackEnabled: false,
      tryProfile,
    });

    expect(tryProfile).toHaveBeenCalledTimes(1);
    expect(selected.selected).toBeNull();
    expect(selected.attempts).toEqual([
      { id: "go-dataflow", ok: false, error: "failed" },
    ]);
  });

  it("augments findings with Newaza metadata", () => {
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

    const augmented = __newazaAnalyzeInternals.augmentFinding(base, {
      passId: 1,
      passKey: "path_traversal",
      focus: "Path Traversal",
      cwes: ["022", "023"],
    }, makeLabels());

    expect(augmented.scanner).toBe("newaza-analyze");
    expect(augmented.ruleId).toContain("newaza/pass1/");
    expect(augmented.message).toContain("[Newaza Path Traversal]");
    expect(augmented.cwe).toEqual(["CWE-022", "CWE-023"]);
    expect(augmented.evidence).toContain("Newaza pass 1");
  });
});
