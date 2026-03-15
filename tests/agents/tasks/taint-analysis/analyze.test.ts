import { describe, expect, it, vi } from "vitest";
import { __taintAnalysisRunInternals } from "../../../../src/agents/tasks/taint-analysis/analyze.js";
import { profileById } from "../../../../src/agents/tasks/taint-analysis/codeql-compat.js";
import type { TaintAnalysisLabelsDocument } from "../../../../src/agents/tasks/taint-analysis/types.js";
import type { Finding } from "../../../../src/scanners/types.js";

function makeLabels(): TaintAnalysisLabelsDocument {
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

describe("taint-analysis-run internals", () => {
  it("renders deterministic libraries", () => {
    const pythonProfile = profileById("python", "python-dataflow-new");
    expect(pythonProfile).not.toBeNull();
    if (!pythonProfile) {
      return;
    }

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(makeLabels(), pythonProfile);
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

    const query = __taintAnalysisRunInternals.renderTaintQuery(template, {
      passId: 1,
      passKey: "path_traversal",
      focus: "Path Traversal",
      cwes: ["022", "023"],
    }, pythonProfile);

    expect(query).toContain("Taint Analysis Pass 1 - Path Traversal");
    expect(query).toContain("py/taint-analysis/pass1-path-traversal");
    expect(query).toContain("\n22\n");
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

    const query = __taintAnalysisRunInternals.renderTaintQuery(template, {
      passId: 1,
      passKey: "path_traversal",
      focus: "Path Traversal",
      cwes: ["022"],
    }, goProfile);

    expect(query).toContain("import semmle.go.dataflow.DataFlow");
    expect(query).toContain("import semmle.go.dataflow.TaintTracking");
    expect(query).not.toContain("semmle.go.dataflow.new.");
  });

  it("escapes callable names in structured predicates for non-Go languages", () => {
    const labels = makeLabels();
    labels.passes[0].entries[0].signature.callable = "fmt.Sprintf";
    labels.metadata.language = "python";
    const pythonProfile = profileById("python", "python-dataflow-new");
    expect(pythonProfile).not.toBeNull();
    if (!pythonProfile) {
      return;
    }

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, pythonProfile);

    expect(libs.sources).toContain("DataFlow::CallCfgNode call");
    expect(libs.sources).toContain('matches("%fmt.Sprintf%")');
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

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile);

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

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile);

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

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile);

    expect(libs.sinks).toContain("call.getArgument(1)");
    expect(libs.sinks).not.toContain("getAnArgument");
  });

  it("Python uses structured CallCfgNode predicates (not DataFlow::CallNode)", () => {
    const pythonProfile = profileById("python", "python-dataflow-new");
    expect(pythonProfile).not.toBeNull();
    if (!pythonProfile) {
      return;
    }

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(makeLabels(), pythonProfile);

    // Python must use CallCfgNode (top-level), NOT DataFlow::CallNode
    expect(libs.sources).toContain("DataFlow::CallCfgNode call");
    expect(libs.sources).not.toContain("DataFlow::CallNode call");
    expect(libs.sources).toContain('matches("%Query%")');
    expect(libs.sources).toContain("call");
    // The path_traversal pass clause uses structured predicates, not regexpMatch
    const srcClause = libs.sources.split('passKey = "path_traversal"')[1]?.split("or\n")[0] ?? "";
    expect(srcClause).not.toContain("regexpMatch");
    expect(libs.sinks).toContain("DataFlow::CallCfgNode call");
    expect(libs.sinks).not.toContain("DataFlow::CallNode call");
    expect(libs.sinks).toContain('matches("%open%")');
    expect(libs.sinks).toContain("call.getArg(0)");
    const sinkClause = libs.sinks.split('passKey = "path_traversal"')[1]?.split("or\n")[0] ?? "";
    expect(sinkClause).not.toContain("regexpMatch");
  });

  it("throws when taint query template leaves unresolved placeholders", () => {
    const pythonProfile = profileById("python", "python-dataflow-new");
    expect(pythonProfile).not.toBeNull();
    if (!pythonProfile) {
      return;
    }

    expect(() => __taintAnalysisRunInternals.renderTaintQuery(
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
    const selected = await __taintAnalysisRunInternals.selectProfileWithCompileGate({
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

    const selected = await __taintAnalysisRunInternals.selectProfileWithCompileGate({
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

  it("augments findings with Taint Analysis metadata", () => {
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

    const augmented = __taintAnalysisRunInternals.augmentFinding(base, {
      passId: 1,
      passKey: "path_traversal",
      focus: "Path Traversal",
      cwes: ["022", "023"],
    }, makeLabels());

    expect(augmented.scanner).toBe("taint-analysis-run");
    expect(augmented.ruleId).toContain("taint-analysis/pass1/");
    expect(augmented.message).toContain("[Taint Analysis Path Traversal]");
    expect(augmented.cwe).toEqual(["CWE-22", "CWE-23"]);
    expect(augmented.evidence).toContain("Taint Analysis pass 1");
  });

  it("Go source with argIndex + non-return flowKind uses getArgument(N)", () => {
    const labels = makeLabels();
    labels.metadata.language = "go";
    labels.passes[0].entries[0].signature.callable = "Unmarshal";
    labels.passes[0].entries[0].signature.module = "encoding/json";
    labels.passes[0].entries[0].role = "source";
    labels.passes[0].entries[0].signature.flow_kind = "argument";
    labels.passes[0].entries[0].signature.arg_index = 1;
    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) return;

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile);

    expect(libs.sources).toContain("call.getArgument(1)");
    expect(libs.sources).not.toContain("call.getResult()");
    expect(libs.sources).toContain('hasQualifiedName("encoding/json", "Unmarshal")');
  });

  it("preserves callable variants with distinct arg positions", () => {
    const labels = makeLabels();
    labels.metadata.language = "go";
    labels.passes[0].entries[1].signature.callable = "ExecContext";
    labels.passes[0].entries[1].signature.arg_index = 0;
    labels.passes[0].entries[1].signature.flow_kind = "argument";
    labels.passes[0].entries.push({
      ...labels.passes[0].entries[1],
      id: "p1-sink-variant",
      signature: {
        ...labels.passes[0].entries[1].signature,
        arg_index: 1,
      },
    });

    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) return;

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile);

    expect(libs.sinks).toContain('call.getTarget().getName() = "ExecContext"');
    expect(libs.sinks).toContain("call.getArgument(0)");
    expect(libs.sinks).toContain("call.getArgument(1)");
  });

  it("skips synthetic callable names in generated predicates", () => {
    const labels = makeLabels();
    labels.metadata.language = "go";
    labels.passes[0].entries[0].signature.callable = "<mq_handler>";
    labels.passes[0].entries[0].signature.flow_kind = "param";
    labels.passes[0].entries[0].signature.arg_index = 1;

    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) return;

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile);
    const pathTraversalClause = libs.sources.split("passKey = \"path_traversal\"")[1]?.split("or\n")[0] ?? "";

    expect(libs.sources).not.toContain("<mq_handler>");
    expect(pathTraversalClause).toContain("regexpMatch(\"a^\")");
  });

  it("Go param sources use parameter-node matching", () => {
    const labels = makeLabels();
    labels.metadata.language = "go";
    labels.passes[0].entries[0].signature.callable = "HandleRequest";
    labels.passes[0].entries[0].signature.flow_kind = "param";
    labels.passes[0].entries[0].signature.arg_index = 1;
    labels.passes[0].entries[0].signature.type = "AuthzService";

    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) return;

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile);
    const pathTraversalClause = libs.sources.split("passKey = \"path_traversal\"")[1]?.split("or\n")[0] ?? "";

    expect(pathTraversalClause).toContain("exists(Method m |");
    expect(pathTraversalClause).toContain('m.getName() = "HandleRequest"');
    expect(pathTraversalClause).toContain("node.asParameter() = m.getParameter(1)");
    expect(pathTraversalClause).not.toContain("call.getArgument(1)");
  });

  it("Go source with return flowKind uses getResult() even if argIndex set", () => {
    const labels = makeLabels();
    labels.metadata.language = "go";
    labels.passes[0].entries[0].signature.callable = "ReadFile";
    labels.passes[0].entries[0].role = "source";
    labels.passes[0].entries[0].signature.flow_kind = "return";
    labels.passes[0].entries[0].signature.arg_index = 0;
    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) return;

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile);

    expect(libs.sources).toContain("call.getResult()");
    expect(libs.sources).not.toContain("call.getArgument(0)");
  });

  it("variadic format sink (Sprintf) with argIndex=0 uses getAnArgument()", () => {
    const labels = makeLabels();
    labels.metadata.language = "go";
    labels.passes[0].entries[1].signature.callable = "Sprintf";
    labels.passes[0].entries[1].signature.module = "fmt";
    labels.passes[0].entries[1].role = "sink";
    labels.passes[0].entries[1].signature.arg_index = 0;
    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) return;

    const hints = __taintAnalysisRunInternals.defaultRenderingHints();
    hints.variadicFormatFuncs.add("Sprintf");
    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile, undefined, hints);

    expect(libs.sinks).toContain("call.getAnArgument()");
    expect(libs.sinks).not.toContain("call.getArgument(0)");
  });

  it("non-format sink with argIndex=0 uses getArgument(0)", () => {
    const labels = makeLabels();
    labels.metadata.language = "go";
    labels.passes[0].entries[1].signature.callable = "Write";
    labels.passes[0].entries[1].role = "sink";
    labels.passes[0].entries[1].signature.arg_index = 0;
    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) return;

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile);

    expect(libs.sinks).toContain("call.getArgument(0)");
    expect(libs.sinks).not.toContain("call.getAnArgument()");
  });

  it("Go SQL query-builder sinks Raw/From default to argument 0 when arg_index is unknown", () => {
    const labels = makeLabels();
    labels.metadata.language = "go";
    labels.passes[0].entries[1].role = "sink";
    labels.passes[0].entries[1].signature.callable = "queries.Raw";
    labels.passes[0].entries[1].signature.module = "github.com/volatiletech/sqlboiler/v4/queries";
    labels.passes[0].entries[1].signature.arg_index = null;
    labels.passes[0].entries[1].signature.flow_kind = "unknown";
    labels.passes[0].entries.push({
      ...labels.passes[0].entries[1],
      id: "p1-sink-from",
      signature: {
        ...labels.passes[0].entries[1].signature,
        callable: "qm.From",
        module: "github.com/volatiletech/sqlboiler/v4/queries/qm",
      },
    });

    const goProfile = profileById("go", "go-dataflow");
    expect(goProfile).not.toBeNull();
    if (!goProfile) return;

    const hints = __taintAnalysisRunInternals.defaultRenderingHints();
    hints.sqlQueryTextArg0Callables.add("Raw");
    hints.sqlQueryTextArg0Callables.add("From");
    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile, undefined, hints);

    expect(libs.sinks).toContain('hasQualifiedName("github.com/volatiletech/sqlboiler/v4/queries", "Raw")');
    expect(libs.sinks).toContain('hasQualifiedName("github.com/volatiletech/sqlboiler/v4/queries/qm", "From")');
    expect(libs.sinks).toContain("call.getArgument(0)");
  });

  it("Go sink matching keeps package-qualified callable checks for SQL executors", () => {
    const goProfile = profileById("go", "go-dataflow")!;
    const nameCheck = __taintAnalysisRunInternals.buildCallableNameCheck(
      "queries.Raw",
      "go",
      "github.com/volatiletech/sqlboiler/v4/queries",
      goProfile,
    );
    expect(nameCheck).toContain('hasQualifiedName("github.com/volatiletech/sqlboiler/v4/queries", "Raw")');
  });

  it("Java uses structured getCallee().getName() predicates", () => {
    const labels = makeLabels();
    labels.metadata.language = "java";
    labels.passes[0].entries[0].signature.callable = "getParameter";
    labels.passes[0].entries[0].role = "source";
    labels.passes[0].entries[0].signature.flow_kind = "return";
    labels.passes[0].entries[1].signature.callable = "executeQuery";
    labels.passes[0].entries[1].role = "sink";
    labels.passes[0].entries[1].signature.arg_index = 0;
    const javaProfile = profileById("java", "java-dataflow");
    expect(javaProfile).not.toBeNull();
    if (!javaProfile) return;

    const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, javaProfile);

    expect(libs.sources).toContain("DataFlow::CallNode call");
    expect(libs.sources).toContain('call.getCallee().getName() = "getParameter"');
    expect(libs.sources).toContain("call.getResult()");
    const javaSrcClause = libs.sources.split('passKey = "path_traversal"')[1]?.split("or\n")[0] ?? "";
    expect(javaSrcClause).not.toContain("regexpMatch");
    expect(libs.sinks).toContain('call.getCallee().getName() = "executeQuery"');
    expect(libs.sinks).toContain("call.getArgument(0)");
    const javaSinkClause = libs.sinks.split('passKey = "path_traversal"')[1]?.split("or\n")[0] ?? "";
    expect(javaSinkClause).not.toContain("regexpMatch");
  });

  it("Go qualified name matching for stdlib packages", () => {
    const goProfile = profileById("go", "go-dataflow")!;
    const nameCheck = __taintAnalysisRunInternals.buildCallableNameCheck(
      "Unmarshal", "go", "encoding/json", goProfile,
    );
    expect(nameCheck).toContain('hasQualifiedName("encoding/json", "Unmarshal")');

    const bareCheck = __taintAnalysisRunInternals.buildCallableNameCheck(
      "MyFunc", "go", null, goProfile,
    );
    expect(bareCheck).toContain('call.getTarget().getName() = "MyFunc"');
    expect(bareCheck).not.toContain("hasQualifiedName");
  });

  it("reports no usable sources when source labels are missing", () => {
    const labels = makeLabels();
    labels.passes[0].entries = labels.passes[0].entries.filter((entry) => entry.role !== "source");

    const hasSources = __taintAnalysisRunInternals.hasUsableRoleForPasses(
      labels,
      [{ passId: 1, passKey: "path_traversal", focus: "Path Traversal", cwes: ["022", "023"] }],
      "source",
    );

    expect(hasSources).toBe(false);
  });

  it("treats fp-only source labels as unusable for analysis", () => {
    const labels = makeLabels();
    const source = labels.passes[0].entries.find((entry) => entry.role === "source");
    if (!source) {
      throw new Error("test fixture missing source entry");
    }
    source.classification = "fp";

    const hasSources = __taintAnalysisRunInternals.hasUsableRoleForPasses(
      labels,
      [{ passId: 1, passKey: "path_traversal", focus: "Path Traversal", cwes: ["022", "023"] }],
      "source",
    );

    expect(hasSources).toBe(false);
  });

  describe("escapeQllString", () => {
    const { escapeQllString } = __taintAnalysisRunInternals;

    it("escapes backslash and double quote", () => {
      expect(escapeQllString('a\\b"c')).toBe('a\\\\b\\"c');
    });

    it("escapes newline characters", () => {
      expect(escapeQllString("line1\nline2")).toBe("line1\\nline2");
    });

    it("escapes carriage return", () => {
      expect(escapeQllString("line1\rline2")).toBe("line1\\rline2");
    });

    it("escapes tab characters", () => {
      expect(escapeQllString("col1\tcol2")).toBe("col1\\tcol2");
    });

    it("escapes null bytes", () => {
      expect(escapeQllString("before\0after")).toBe("before\\0after");
    });

    it("handles combined special characters", () => {
      expect(escapeQllString('a\n"b\t\0c\\')).toBe('a\\n\\"b\\t\\0c\\\\');
    });

    it("returns empty string unchanged", () => {
      expect(escapeQllString("")).toBe("");
    });

    it("does not double-escape literal backslash-n", () => {
      // A string containing a literal backslash followed by 'n' (2 chars)
      expect(escapeQllString("\\n")).toBe("\\\\n");
    });
  });

  describe("summary propagation", () => {
    function makeLabelsWithSummary(): TaintAnalysisLabelsDocument {
      const base = makeLabels();
      base.passes[0].entries.push({
        id: "p1-summary",
        role: "summary",
        classification: "candidate",
        confidence: 0.85,
        signature: {
          package: null,
          module: "builtins",
          type: null,
          callable: "json_decode",
          arg_index: null,
          flow_kind: "return",
        },
        location: { file: "a.py", line: 5 },
        rationale: "propagator",
      });
      return base;
    }

    it("renders implicit propagation steps when no labeled summary entries exist", () => {
      const pythonProfile = profileById("python", "python-dataflow-new")!;
      const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(makeLabels(), pythonProfile);
      expect(libs.summaries).toContain("module MySummaries");
      expect(libs.summaries).toContain("isAdditionalTaintStep");
      // Implicit steps include Python-specific data structure propagation
      expect(libs.summaries).toMatch(/json\.loads|"get"/);
    });

    it("renders populated predicates with summary entries", () => {
      const pythonProfile = profileById("python", "python-dataflow-new")!;
      const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(makeLabelsWithSummary(), pythonProfile);
      expect(libs.summaries).not.toContain("none()");
      expect(libs.summaries).toContain("module MySummaries");
      expect(libs.summaries).toContain("nodeFrom");
      expect(libs.summaries).toContain("nodeTo");
      expect(libs.summaries).toContain("json_decode");
      expect(libs.summaries).toContain("passKey = \"path_traversal\"");
    });

    it("excludes FP summaries", () => {
      const labels = makeLabelsWithSummary();
      const summaryEntry = labels.passes[0].entries.find((e) => e.role === "summary")!;
      summaryEntry.classification = "fp";

      const pythonProfile = profileById("python", "python-dataflow-new")!;
      const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, pythonProfile);
      // FP summary is excluded; only implicit propagation steps remain
      expect(libs.summaries).toContain("module MySummaries");
      expect(libs.summaries).toContain("isAdditionalTaintStep");
      expect(libs.summaries).not.toContain("json_decode");
    });

    it("renders per-language profiles correctly for Go", () => {
      const labels = makeLabelsWithSummary();
      labels.metadata.language = "go";
      labels.passes[0].entries.find((e) => e.role === "summary")!.signature.callable = "Unmarshal";
      const goProfile = profileById("go", "go-dataflow")!;
      const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, goProfile);
      expect(libs.summaries).toContain("DataFlow::CallNode call");
      expect(libs.summaries).toContain("Unmarshal");
      expect(libs.summaries).toContain("nodeFrom");
      expect(libs.summaries).toContain("nodeTo");
    });

    it("buildSummaryTaintStep binds nodeFrom and nodeTo for return flow", () => {
      const pythonProfile = profileById("python", "python-dataflow-new")!;
      const step = __taintAnalysisRunInternals.buildSummaryTaintStep(
        { callable: "json_decode", flowKind: "return", receiverHint: null, argIndex: null },
        pythonProfile,
      );
      expect(step).toContain("nodeFrom =");
      expect(step).toContain("nodeTo =");
      // return flow → nodeTo should use result expr
      expect(step).toContain("call");
    });

    it("buildSummaryTaintStep uses arg position for non-return flow", () => {
      const goProfile = profileById("go", "go-dataflow")!;
      const step = __taintAnalysisRunInternals.buildSummaryTaintStep(
        { callable: "Transform", flowKind: "argument", receiverHint: null, argIndex: 1 },
        goProfile,
      );
      expect(step).toContain("nodeTo = call.getArgument(1)");
      expect(step).toContain("nodeFrom = call.getAnArgument()");
    });

    it("uses impossible-match for empty passes alongside populated ones", () => {
      const pythonProfile = profileById("python", "python-dataflow-new")!;
      const labels = makeLabelsWithSummary();
      const libs = __taintAnalysisRunInternals.renderTaintAnalysisLibraries(labels, pythonProfile);
      // pass 1 has summary, other passes should use regexpMatch impossible
      expect(libs.summaries).toContain("regexpMatch(\"a^\")");
      expect(libs.summaries).toContain("json_decode");
    });
  });
});
