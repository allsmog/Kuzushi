import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { __augurPreflightInternals } from "../../../src/agents/tasks/augur-preflight.js";
import { DEFAULT_AUGUR_TASK_CONFIG } from "../../../src/agents/tasks/augur-types.js";

const TMP_ROOT = path.join(import.meta.dirname, "..", "..", ".tmp-augur-preflight");

beforeEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
  mkdirSync(TMP_ROOT, { recursive: true });
});

afterEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

describe("augur-preflight internals", () => {
  it("resolves workspace path relative to repo root", () => {
    const workspace = __augurPreflightInternals.resolveWorkspaceDir("/tmp/repo", "./iris");
    expect(workspace).toBe(path.resolve("/tmp/repo", "./iris"));
  });

  it("clamps workspace path to repo root when config escapes upward", () => {
    const repoRoot = path.join(TMP_ROOT, "repo");
    mkdirSync(repoRoot, { recursive: true });

    const workspace = __augurPreflightInternals.resolveWorkspaceDir(repoRoot, "../outside-iris");
    expect(workspace).toBe(path.resolve(repoRoot, "./iris"));
  });

  it("creates Augur workspace directory tree", async () => {
    const workspace = path.join(TMP_ROOT, "iris");
    await __augurPreflightInternals.initializeWorkspace(workspace);

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
    const framework = await __augurPreflightInternals.detectPrimaryFramework(
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

    const framework = await __augurPreflightInternals.detectPrimaryFramework(TMP_ROOT, undefined);
    expect(framework).toBe("express");
  });

  it("resolves available reference files for language/framework", async () => {
    const augurPath = path.join(TMP_ROOT, "augur");
    const refs = path.join(augurPath, "references");
    mkdirSync(refs, { recursive: true });
    writeFileSync(path.join(refs, "patterns.md"), "patterns", "utf-8");
    writeFileSync(path.join(refs, "python.md"), "python", "utf-8");
    writeFileSync(path.join(refs, "fastapi.md"), "fastapi", "utf-8");

    const files = await __augurPreflightInternals.resolveReferenceFiles(augurPath, "python", "fastapi");
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

    const rendered = await __augurPreflightInternals.renderExtractionTemplate(templatePath, "python", "source");
    expect(rendered).not.toContain("{{");
    expect(rendered).toContain("Augur Source candidate extraction");
    expect(rendered).toContain("import python");
  });

  it("falls back when starter template contains unresolved language placeholders", async () => {
    const templatePath = path.join(TMP_ROOT, "starter.ql.tmpl");
    writeFileSync(templatePath, "{{SOURCE_HANDLER_PREDICATE}}", "utf-8");

    const rendered = await __augurPreflightInternals.renderExtractionTemplate(templatePath, "python", "source");
    expect(rendered).toContain("@id augur/extraction/fallback-source");
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
    const rendered = await __augurPreflightInternals.renderExtractionTemplate(
      templatePath,
      "go",
      "source",
    );
    expect(rendered).toContain("@id augur/extraction/fallback-source");
    expect(rendered).toContain("where false");
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
    const rendered = await __augurPreflightInternals.renderExtractionTemplate(
      templatePath,
      "go",
      "source",
      {
        referenceFiles: [],
        augurPath: TMP_ROOT,
        model: "nonexistent-model",
        repoRoot: TMP_ROOT,
        workspaceDir: path.join(TMP_ROOT, "iris"),
        codeqlBinary: "/usr/bin/false",
        dbPath: "/tmp/test.db",
      },
    );

    // Should fall back to deterministic fallback
    expect(rendered).toContain("@id augur/extraction/fallback-source");
    expect(rendered).toContain("where false");
  });

  it("writes manifest model fields aligned with effective extraction model", async () => {
    const workspaceDir = path.join(TMP_ROOT, "iris");
    mkdirSync(path.join(workspaceDir, "exploration"), { recursive: true });

    await __augurPreflightInternals.writeManifestAndDetection(
      workspaceDir,
      "/tmp/db",
      "python",
      "fastapi",
      [],
      {
        ...DEFAULT_AUGUR_TASK_CONFIG,
        labelingModel: "label-model",
        extractionModel: "extract-model",
      },
      "extract-model",
    );

    const manifestPath = path.join(workspaceDir, "exploration", "run_manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf-8")) as Record<string, unknown>;

    expect(manifest["model"]).toBe("extract-model");
    expect(manifest["extractionModel"]).toBe("extract-model");
    expect(manifest["labelingModel"]).toBe("label-model");
  });
});
