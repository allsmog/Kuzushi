import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { AgentRuntime } from "../../../src/agent-runtime/types.js";
import {
  __codeGraphBuildInternals,
  codeGraphBuildTask,
} from "../../../src/agents/tasks/code-graph/build.js";
import type { TaskContext } from "../../../src/agents/types.js";

vi.mock("../../../src/analysis-support/index.js", () => ({
  getCodeIntelligenceProvider: vi.fn(),
}));

import { getCodeIntelligenceProvider } from "../../../src/analysis-support/index.js";

const mockedGetProvider = vi.mocked(getCodeIntelligenceProvider);
const { classifyStaticNodeFromContent } = __codeGraphBuildInternals;

function makeRuntime(): AgentRuntime {
  const query = vi.fn().mockImplementation(async function* () {
    yield {
      type: "result",
      subtype: "success",
      result: "{}",
      structuredOutput: {
        hops: [
          {
            filePath: "main.go",
            startLine: 2,
            symbol: "listen",
            nodeKind: "external-call",
            edgeKind: "calls",
            confidence: 0.92,
          },
        ],
      },
      totalCostUsd: 0.01,
    };
  });

  return {
    id: "mock-runtime",
    query,
  };
}

function makeContext(repoRoot: string, runtime: AgentRuntime): TaskContext {
  return {
    runId: "run-1",
    repoRoot,
    repoName: "repo",
    config: {
      model: "anthropic:claude-sonnet-4-6",
      codeGraphEnabled: true,
      busBackend: "in-process",
      triageBatchSize: 5,
      triageConcurrency: 1,
      scanMode: "sequential",
      tasks: [],
      tasks: ["semgrep"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: {
        "code-graph": {},
      },
    } as any,
    runtime,
    bus: { publish: vi.fn(), subscribe: vi.fn(), close: vi.fn() } as any,
    upstreamOutputs: new Map([
      [
        "context-gatherer",
        {
          repoContext: {
            languages: ["Go"],
            frameworks: [],
            authPatterns: [],
            sanitizationLibs: [],
            ormOrDb: [],
            entryPoints: ["main.go"],
          },
          fileIndex: {
            tree: [{ path: "main.go" }],
            totalFiles: 1,
            truncated: false,
            patternMatches: {},
          },
        },
      ],
      ["context-enricher", {}],
      [
        "app-model-build",
        {
          version: "1",
          routes: [],
          outboundClients: [],
          dataStores: [],
          backgroundJobs: [],
          serviceBoundaries: [],
          relevantFiles: [],
          notes: [],
        },
      ],
    ]),
  };
}

let tempDir: string | undefined;

afterEach(async () => {
  vi.restoreAllMocks();
  if (tempDir) {
    await rm(tempDir, { recursive: true, force: true });
    tempDir = undefined;
  }
});

describe("code-graph-build task", () => {
  it("classifies Go static nodes with entry, middleware, data, and external-call heuristics", () => {
    expect(
      classifyStaticNodeFromContent("func handle(w http.ResponseWriter, r *http.Request) {}", []),
    ).toMatchObject({ nodeKind: "entry-http" });

    expect(classifyStaticNodeFromContent("func main() {}\nflag.Parse()", [])).toMatchObject({
      nodeKind: "entry-cli",
    });

    expect(classifyStaticNodeFromContent("r.Use(authz)\nvar mw gin.HandlerFunc", [])).toMatchObject(
      { nodeKind: "middleware" },
    );

    expect(
      classifyStaticNodeFromContent('rows, _ := db.Query("SELECT 1")\nvar conn *gorm.DB', []),
    ).toMatchObject({ nodeKind: "data-access" });

    expect(
      classifyStaticNodeFromContent(
        'cmd := exec.Command("sh")\nos.Exit(1)\nnet.Dial("tcp", addr)',
        [],
      ),
    ).toMatchObject({ nodeKind: "external-call" });
  });

  it("falls back to main() and still traces when the app model has no routes", async () => {
    tempDir = await mkdtemp(path.join(tmpdir(), "kuzushi-code-graph-"));
    await writeFile(
      path.join(tempDir, "main.go"),
      [
        "package main",
        "",
        'import "net"',
        "",
        "func main() {",
        '  _, _ = net.Listen("tcp", ":9000")',
        "}",
        "",
      ].join("\n"),
      "utf-8",
    );

    const runtime = makeRuntime();
    mockedGetProvider.mockResolvedValue({
      getImportGraph: vi.fn().mockResolvedValue([]),
    } as any);

    const output = await codeGraphBuildTask.run({} as any, makeContext(tempDir, runtime));

    expect(runtime.query).toHaveBeenCalledTimes(2);
    expect(output.stats.entryPoints).toBe(2);
    expect(output.stats.tracedEntryPoints).toBe(2);
    expect(output.paths).toHaveLength(2);
    expect(output.nodes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          filePath: "main.go",
          symbol: "main",
          nodeKind: "entry-cli",
        }),
      ]),
    );
  });
});
