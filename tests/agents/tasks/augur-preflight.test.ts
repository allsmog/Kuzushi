import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { __augurPreflightInternals } from "../../../src/agents/tasks/augur-preflight.js";

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
});
