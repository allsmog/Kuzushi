import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { __taintAnalysisPreflightInternals } from "../../../../src/agents/tasks/taint-analysis/preflight.js";
import { DEFAULT_TAINT_ANALYSIS_TASK_CONFIG } from "../../../../src/agents/tasks/taint-analysis/types.js";

const TMP_ROOT = path.join(import.meta.dirname, "..", "..", "..", ".tmp-taint-analysis-preflight");

beforeEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
  mkdirSync(TMP_ROOT, { recursive: true });
});

afterEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

describe("taint-analysis-preflight internals", () => {
  it("resolves workspace path relative to repo root", () => {
    const workspace = __taintAnalysisPreflightInternals.resolveWorkspaceDir("/tmp/repo", "./iris");
    expect(workspace).toBe(path.resolve("/tmp/repo", "./iris"));
  });

  it("clamps workspace path to repo root when config escapes upward", () => {
    const repoRoot = path.join(TMP_ROOT, "repo");
    mkdirSync(repoRoot, { recursive: true });

    const workspace = __taintAnalysisPreflightInternals.resolveWorkspaceDir(repoRoot, "../outside-iris");
    expect(workspace).toBe(path.resolve(repoRoot, "./iris"));
  });

  it("uses extractionModel when configured", () => {
    const resolved = __taintAnalysisPreflightInternals.resolveExtractionModel({
      ...DEFAULT_TAINT_ANALYSIS_TASK_CONFIG,
      labelingModel: "label-model",
      extractionModel: "extract-model",
    });

    expect(resolved).toEqual({
      model: "extract-model",
      usedLabelingFallback: false,
    });
  });

  it("falls back to labelingModel when extractionModel is unset", () => {
    const resolved = __taintAnalysisPreflightInternals.resolveExtractionModel({
      ...DEFAULT_TAINT_ANALYSIS_TASK_CONFIG,
      labelingModel: "label-model",
      extractionModel: undefined,
    });

    expect(resolved).toEqual({
      model: "label-model",
      usedLabelingFallback: true,
    });
  });

  it("creates Taint Analysis workspace directory tree", async () => {
    const workspace = path.join(TMP_ROOT, "iris");
    await __taintAnalysisPreflightInternals.initializeWorkspace(workspace);

    const expectedSubdirs = [
      "exploration",
      "extraction",
      "labels",
      "libraries",
      "queries",
      "results",
      "report",
    ];

    for (const dir of expectedSubdirs) {
      expect(existsSync(path.join(workspace, dir))).toBe(true);
    }
  });

  it("uses context-gatherer output as a soft framework hint", async () => {
    const framework = await __taintAnalysisPreflightInternals.detectPrimaryFramework(
      TMP_ROOT,
      {
        frameworks: ["Express"],
      },
    );

    expect(framework).toBe("express");
  });

  it("detects framework heuristically when context output is absent", async () => {
    writeFileSync(path.join(TMP_ROOT, "package.json"), JSON.stringify({
      dependencies: {
        express: "^4.0.0",
      },
    }), "utf-8");

    const framework = await __taintAnalysisPreflightInternals.detectPrimaryFramework(TMP_ROOT, undefined);
    expect(framework).toBe("express");
  });

  it("resolves available reference files for language/framework", async () => {
    const taintAnalysisPath = path.join(TMP_ROOT, "taint-analysis");
    const refs = path.join(taintAnalysisPath, "references");
    mkdirSync(refs, { recursive: true });
    writeFileSync(path.join(refs, "patterns.md"), "patterns", "utf-8");
    writeFileSync(path.join(refs, "python.md"), "python", "utf-8");
    writeFileSync(path.join(refs, "fastapi.md"), "fastapi", "utf-8");

    const files = await __taintAnalysisPreflightInternals.resolveReferenceFiles(taintAnalysisPath, "python", "fastapi");
    expect(files).toEqual([
      path.join(refs, "patterns.md"),
      path.join(refs, "python.md"),
      path.join(refs, "fastapi.md"),
    ]);
  });

  it("renders generic extraction templates without leftover placeholders", async () => {
    const templatePath = path.join(TMP_ROOT, "source-template.ql.tmpl");
    writeFileSync(templatePath, [
      "{{QUERY_NAME}}",
      "{{QUERY_DESCRIPTION}}",
      "{{QUERY_ID}}",
      "{{LANGUAGE_IMPORTS}}",
      "{{HELPER_PREDICATES}}",
      "{{SOURCE_CLAUSES}}",
      "{{SELECT_NODE}}",
      "{{SELECT_CALLABLE}}",
      "{{SELECT_FLOW_KIND}}",
      "{{SELECT_RECEIVER}}",
      "{{SELECT_MODULE}}",
      "{{SELECT_ARG_INDEX}}",
      "{{SELECT_LINE}}",
    ].join("\n"), "utf-8");

    const rendered = await __taintAnalysisPreflightInternals.renderExtractionTemplate(templatePath, "python", "source");
    expect(rendered).not.toContain("{{");
    expect(rendered).toContain("Taint Analysis Source candidate extraction");
    expect(rendered).toContain("import python");
  });

  it("falls back when starter template contains unresolved language placeholders", async () => {
    const templatePath = path.join(TMP_ROOT, "starter.ql.tmpl");
    writeFileSync(templatePath, "{{SOURCE_HANDLER_PREDICATE}}", "utf-8");

    const rendered = await __taintAnalysisPreflightInternals.renderExtractionTemplate(templatePath, "python", "source");
    expect(rendered).toContain("@id taint-analysis/extraction/fallback-source");
  });

  it("falls back without agentCtx even when body placeholders present", async () => {
    const templatePath = path.join(TMP_ROOT, "go-source.ql.tmpl");
    writeFileSync(templatePath, [
      "import go",
      "{{SOURCE_HANDLER_PREDICATE}}",
      "from {{SOURCE_NODE_BINDINGS}}",
      "where {{SOURCE_WHERE}}",
      "select {{SOURCE_SELECT}}",
    ].join("\n"), "utf-8");

    // No agentCtx → should use deterministic fallback
    const rendered = await __taintAnalysisPreflightInternals.renderExtractionTemplate(
      templatePath,
      "go",
      "source",
    );
    expect(rendered).toContain("@id taint-analysis/extraction/fallback-source");
    expect(rendered).toContain("where 1 = 0");
  });

  it("gracefully falls back when agent throws", async () => {
    const templatePath = path.join(TMP_ROOT, "go-source-err.ql.tmpl");
    writeFileSync(templatePath, [
      "import go",
      "{{SOURCE_HANDLER_PREDICATE}}",
      "from DataFlow::Node n",
      "where true",
      "select n",
    ].join("\n"), "utf-8");

    // Agent will fail (no runtime configured) but should fall back gracefully
    const rendered = await __taintAnalysisPreflightInternals.renderExtractionTemplate(
      templatePath,
      "go",
      "source",
      {
        referenceFiles: [],
        taintAnalysisPath: TMP_ROOT,
        model: "nonexistent-model",
        repoRoot: TMP_ROOT,
        workspaceDir: path.join(TMP_ROOT, "iris"),
        codeqlBinary: "/usr/bin/false",
        dbPath: "/tmp/test.db",
        codeqlApiProfileId: "go-dataflow",
        dataFlowImport: "semmle.go.dataflow.DataFlow",
        taintTrackingImport: "semmle.go.dataflow.TaintTracking",
      },
    );

    // Should fall back to deterministic fallback
    expect(rendered).toContain("@id taint-analysis/extraction/fallback-source");
    expect(rendered).toContain("where 1 = 0");
  });

  it("writes manifest model fields aligned with effective extraction model", async () => {
    const workspaceDir = path.join(TMP_ROOT, "iris");
    mkdirSync(path.join(workspaceDir, "exploration"), { recursive: true });

    await __taintAnalysisPreflightInternals.writeManifestAndDetection(
      workspaceDir,
      "/tmp/db",
      "python",
      "fastapi",
      [],
      {
        ...DEFAULT_TAINT_ANALYSIS_TASK_CONFIG,
        labelingModel: "label-model",
        extractionModel: "extract-model",
      },
      "extract-model",
      "CodeQL CLI 2.20.7",
      "python-dataflow-new",
    );

    const manifestPath = path.join(workspaceDir, "exploration", "run_manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf-8")) as Record<string, unknown>;

    expect(manifest["model"]).toBe("extract-model");
    expect(manifest["extractionModel"]).toBe("extract-model");
    expect(manifest["labelingModel"]).toBe("label-model");
    expect(manifest["codeqlVersion"]).toBe("CodeQL CLI 2.20.7");
    expect(manifest["codeqlApiProfileId"]).toBe("python-dataflow-new");
  });

  it("writes codeql compatibility report with attempted profiles", async () => {
    const workspaceDir = path.join(TMP_ROOT, "iris");
    mkdirSync(path.join(workspaceDir, "exploration"), { recursive: true });

    await __taintAnalysisPreflightInternals.writeCodeqlCompatibility(
      workspaceDir,
      "go",
      "CodeQL CLI 2.20.7",
      {
        ...DEFAULT_TAINT_ANALYSIS_TASK_CONFIG,
        codeqlApiProfile: "auto",
        codeqlProfileFallbacks: true,
        codeqlProbeTimeoutMs: 20_000,
      },
      [
        { id: "go-dataflow", ok: false, error: "import missing" },
        { id: "go-dataflow-new", ok: true },
      ],
      "go-dataflow-new",
    );

    const compatPath = path.join(workspaceDir, "exploration", "codeql_compat.json");
    const compat = JSON.parse(readFileSync(compatPath, "utf-8")) as Record<string, unknown>;
    expect(compat["language"]).toBe("go");
    expect(compat["codeqlVersion"]).toBe("CodeQL CLI 2.20.7");
    expect(compat["selectedProfileId"]).toBe("go-dataflow-new");
    expect(compat["triedProfiles"]).toEqual([
      { id: "go-dataflow", ok: false, error: "import missing" },
      { id: "go-dataflow-new", ok: true },
    ]);
  });
});
