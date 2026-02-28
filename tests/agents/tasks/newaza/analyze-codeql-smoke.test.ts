import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, it } from "vitest";
import { __newazaAnalyzeInternals } from "../../../../src/agents/tasks/newaza/analyze.js";
import { detectWorkingProfile } from "../../../../src/agents/tasks/newaza/codeql-compat.js";
import {
  DEFAULT_NEWAZA_TASK_CONFIG,
  NEWAZA_PASSES,
  type NewazaLabelsDocument,
} from "../../../../src/agents/tasks/newaza/types.js";

const tempDirs: string[] = [];

const runSmoke = process.env["KUZUSHI_CODEQL_SMOKE"] === "1";
const codeqlBinary = resolveCodeqlBinary();
const describeSmoke = runSmoke && codeqlBinary ? describe : describe.skip;

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describeSmoke("newaza-analyze CodeQL smoke", () => {
  it("compiles generated Go libraries and taint query", { timeout: 180_000 }, async () => {
    const codeql = codeqlBinary;
    if (!codeql) {
      return;
    }

    const tmpDir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-newaza-analyze-smoke-"));
    tempDirs.push(tmpDir);
    mkdirSync(path.join(tmpDir, "libraries"), { recursive: true });
    mkdirSync(path.join(tmpDir, "queries"), { recursive: true });

    writeFileSync(
      path.join(tmpDir, "qlpack.yml"),
      [
        "name: smoke/newaza-analyze",
        "version: 0.0.1",
        "dependencies:",
        "  codeql/go-all: \"*\"",
        "",
      ].join("\n"),
      "utf-8",
    );

    runCodeql(codeql, ["pack", "install"], tmpDir);
    const profileDetection = await detectWorkingProfile({
      language: "go",
      codeqlBinary: codeql,
      workspaceDir: tmpDir,
      codeqlApiProfile: "auto",
      codeqlProfileFallbacks: true,
      probeTimeoutMs: 20_000,
    });
    const selectedProfile = profileDetection.selected;

    const labels = makeLabels();
    const libs = __newazaAnalyzeInternals.renderNewazaLibraries(labels, selectedProfile);
    writeFileSync(path.join(tmpDir, "libraries", "MySources.qll"), libs.sources, "utf-8");
    writeFileSync(path.join(tmpDir, "libraries", "MySinks.qll"), libs.sinks, "utf-8");
    writeFileSync(path.join(tmpDir, "libraries", "MySanitizers.qll"), libs.sanitizers, "utf-8");
    writeFileSync(path.join(tmpDir, "libraries", "MySummaries.qll"), libs.summaries, "utf-8");

    const taintTemplatePath = path.join(DEFAULT_NEWAZA_TASK_CONFIG.newazaPath, "assets", "taint_query.ql.tmpl");
    const taintTemplate = readFileSync(taintTemplatePath, "utf-8");
    const pass1 = NEWAZA_PASSES.find((pass) => pass.passId === 1);
    if (!pass1) {
      throw new Error("missing Newaza pass definition for pass 1");
    }

    const queryText = __newazaAnalyzeInternals.renderTaintQuery(taintTemplate, pass1, selectedProfile);
    const queryPath = path.join(tmpDir, "queries", "Pass1_PathTraversal.ql");
    writeFileSync(queryPath, queryText, "utf-8");

    runCodeql(codeql, ["query", "compile", queryPath, "--search-path", tmpDir], tmpDir);
  });
});

function runCodeql(codeql: string, args: string[], cwd: string): void {
  const result = spawnSync(codeql, args, {
    cwd,
    encoding: "utf-8",
    maxBuffer: 32 * 1024 * 1024,
  });

  if (result.status === 0) {
    return;
  }

  throw new Error(
    [
      `CodeQL command failed: ${codeql} ${args.join(" ")}`,
      result.stderr?.trim() || result.stdout?.trim() || result.error?.message || "unknown error",
    ].join("\n"),
  );
}

function resolveCodeqlBinary(): string | null {
  const candidates = [
    process.env["CODEQL_BINARY"]?.trim(),
    "codeql",
    "/opt/homebrew/bin/codeql",
  ].filter((candidate): candidate is string => Boolean(candidate));

  for (const candidate of candidates) {
    const probe = spawnSync(candidate, ["version"], {
      encoding: "utf-8",
      stdio: "ignore",
    });
    if (probe.status === 0) {
      return candidate;
    }
  }

  return null;
}

function makeLabels(): NewazaLabelsDocument {
  return {
    version: "1.0.0",
    metadata: {
      run_id: "run-1",
      generated_at: new Date().toISOString(),
      language: "go",
      framework: "gin",
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
            id: "src-1",
            role: "source",
            classification: "candidate",
            confidence: 0.9,
            signature: {
              package: null,
              module: "cmd/server.go",
              type: null,
              callable: "flag.String",
              arg_index: null,
              flow_kind: "return",
            },
            location: {
              file: "cmd/server.go",
              line: 10,
            },
            rationale: "source",
          },
          {
            id: "sink-1",
            role: "sink",
            classification: "candidate",
            confidence: 0.9,
            signature: {
              package: null,
              module: "internal/db/query.go",
              type: null,
              callable: "fmt.Sprintf",
              arg_index: 0,
              flow_kind: "argument",
            },
            location: {
              file: "internal/db/query.go",
              line: 25,
            },
            rationale: "sink",
          },
        ],
      },
    ],
  };
}
