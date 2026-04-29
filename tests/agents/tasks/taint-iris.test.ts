import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import type { AgentQueryRequest, AgentRuntime } from "../../../src/agent-runtime/types.js";
import { __taintIrisInternals, taintIrisTask } from "../../../src/agents/tasks/taint-iris/iris.js";
import type { PipelineContext } from "../../../src/agents/types.js";
import type { KuzushiConfig, ScanOpts } from "../../../src/types.js";

function cwe(id: string) {
  return { id, name: `${id} name`, reason: `${id} reason` };
}

function makeRuntime(capture: (request: AgentQueryRequest) => void): AgentRuntime {
  return {
    id: "test",
    async *query(request) {
      capture(request);
      yield {
        type: "result",
        subtype: "success",
        result: '{"findings":[]}',
        structuredOutput: { findings: [] },
        totalCostUsd: 0.02,
      };
    },
  };
}

function makeConfig(taskConfig: KuzushiConfig["taskConfig"]): KuzushiConfig {
  return {
    model: "test-model",
    taskConfig,
    tasks: [],
  } as unknown as KuzushiConfig;
}

function makeContext(
  runtime: AgentRuntime,
  taskConfig: KuzushiConfig["taskConfig"],
  signal?: AbortSignal,
): PipelineContext {
  const repoRoot = mkdtempSync(path.join(tmpdir(), "kuzushi-iris-context-"));
  return {
    runId: "run-1",
    repoRoot,
    repoName: "repo",
    config: makeConfig(taskConfig),
    runtime,
    bus: {} as PipelineContext["bus"],
    upstreamOutputs: new Map([
      ["context-gatherer", { languages: ["TypeScript"], frameworks: ["Express"] }],
      ["taint-cwe-select", { cwes: [cwe("CWE-89"), cwe("CWE-78"), cwe("CWE-22")] }],
    ]),
    ...(signal ? { signal } : {}),
  };
}

describe("taint-iris task", () => {
  it("threads TAINT_IRIS_PROMPT into the agent prompt", async () => {
    let captured: AgentQueryRequest | undefined;
    const runtime = makeRuntime((request) => {
      captured = request;
    });

    await taintIrisTask.run(
      {
        target: ".",
        TAINT_IRIS_PROMPT: "Operator override: focus on sql sinks only.",
      } as unknown as ScanOpts,
      makeContext(runtime, { "taint-iris": { codeqlMode: "off" } }),
    );

    expect(captured?.prompt).toContain("## Operator Prompt Override");
    expect(captured?.prompt).toContain("Operator override: focus on sql sinks only.");
    expect(captured?.prompt).toContain("CWE-89");
  });

  it("caps selected CWEs while keeping one agent session", async () => {
    let captured: AgentQueryRequest | undefined;
    const runtime = makeRuntime((request) => {
      captured = request;
    });

    await taintIrisTask.run(
      { target: ".", maxCwes: 2 } as unknown as ScanOpts,
      makeContext(runtime, { "taint-iris": { codeqlMode: "off" } }),
    );

    expect(captured?.prompt).toContain("Analyzing first 2 of 3 selected CWE classes.");
    expect(captured?.prompt).toContain("CWE-89");
    expect(captured?.prompt).toContain("CWE-78");
    expect(captured?.prompt).not.toContain("CWE-22");
  });

  it("forwards abort and budget controls to the runtime query", async () => {
    let captured: AgentQueryRequest | undefined;
    const runtime = makeRuntime((request) => {
      captured = request;
    });
    const controller = new AbortController();

    await taintIrisTask.run(
      { target: "." },
      makeContext(
        runtime,
        { "taint-iris": { codeqlMode: "off", maxBudgetUsd: 0.5 } },
        controller.signal,
      ),
    );

    expect(captured?.options.maxBudgetUsd).toBe(0.5);
    expect(captured?.options.abortController).toBeDefined();
    expect(captured?.options.abortController?.signal.aborted).toBe(false);

    controller.abort();
    expect(captured?.options.abortController?.signal.aborted).toBe(true);
  });

  it("guards legacy IRIS tools to scan root, workspace, and exact CodeQL commands", () => {
    const root = mkdtempSync(path.join(tmpdir(), "kuzushi-iris-"));
    try {
      const scanRoot = path.join(root, "lab");
      const workspaceDir = path.join(root, ".kuzushi", "runs", "run-1", "taint-iris");
      const codeqlDbPath = path.join(root, ".kuzushi", "codeql-db");
      mkdirSync(scanRoot, { recursive: true });
      mkdirSync(workspaceDir, { recursive: true });
      mkdirSync(codeqlDbPath, { recursive: true });
      const denied: string[] = [];
      const guard = __taintIrisInternals.createIrisToolGuard({
        scanRoot,
        workspaceDir,
        codeqlDbPath,
        denied,
      });

      expect(guard("Read", { path: path.join(scanRoot, "app.py") }).behavior).toBe("allow");
      expect(guard("Write", { file_path: path.join(workspaceDir, "query.ql") }).behavior).toBe(
        "allow",
      );
      expect(
        guard("Bash", {
          command: `codeql query compile ${path.join(workspaceDir, "query.ql")} --search-path ${workspaceDir}`,
        }).behavior,
      ).toBe("allow");
      expect(
        guard("Bash", {
          command: `codeql database analyze ${codeqlDbPath} ${path.join(workspaceDir, "query.ql")} --format=sarif-latest --output=${path.join(workspaceDir, "results.sarif")}`,
        }).behavior,
      ).toBe("allow");

      expect(guard("Read", { path: "/etc/passwd" }).behavior).toBe("deny");
      expect(guard("Write", { file_path: path.join(scanRoot, "query.ql") }).behavior).toBe("deny");
      expect(guard("Bash", { command: "find / -type f -name '*.py'" }).behavior).toBe("deny");
      expect(
        guard("Bash", {
          command: `codeql query compile ${path.join(workspaceDir, "query.ql")} --search-path ${workspaceDir} && rm -rf /`,
        }).behavior,
      ).toBe("deny");
      expect(denied.length).toBeGreaterThanOrEqual(4);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("resolves a parent git-root CodeQL DB for a subdirectory scan", () => {
    const root = mkdtempSync(path.join(tmpdir(), "kuzushi-iris-db-"));
    try {
      const lab = path.join(root, "lab");
      const db = path.join(root, ".kuzushi", "codeql-db");
      mkdirSync(lab, { recursive: true });
      mkdirSync(db, { recursive: true });
      const resolved = __taintIrisInternals.resolveCodeqlDbPath({
        ...makeContext(
          makeRuntime(() => undefined),
          {},
        ),
        repoRoot: lab,
        scanPath: lab,
        gitRoot: root,
      });

      expect(resolved).toBe(db);
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});
