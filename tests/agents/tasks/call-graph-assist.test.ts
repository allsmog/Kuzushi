import { describe, it, expect, vi, afterEach } from "vitest";
import type { Finding } from "../../../src/scanners/types.js";
import type { TaskContext } from "../../../src/agents/types.js";
import { callGraphAssistTask } from "../../../src/agents/tasks/call-graph-assist.js";

// Mock the code intelligence provider
vi.mock("../../../src/analysis-support/code-intelligence.js", () => ({
  getCodeIntelligenceProvider: vi.fn(),
}));

import { getCodeIntelligenceProvider } from "../../../src/analysis-support/code-intelligence.js";
const mockedGetProvider = vi.mocked(getCodeIntelligenceProvider);

function makeFinding(fp: string, score: number, extras?: Partial<Finding>): Finding {
  return {
    taskId: "agentic",
    fingerprint: fp,
    ruleId: "ssrf-detect",
    filePath: "src/routes/api.ts",
    startLine: 42,
    severity: "ERROR",
    message: "SSRF via user-controlled URL",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-918"],
    score,
    ...extras,
  };
}

function makeContext(): TaskContext {
  return {
    runId: "test-run",
    repoRoot: "/tmp/repo",
    repoName: "repo",
    config: {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 1,
      scanMode: "sequential",
      tasks: [],
      tasks: ["semgrep"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: {},
    },
    bus: { publish: vi.fn(), subscribe: vi.fn(), close: vi.fn() } as any,
    upstreamOutputs: new Map(),
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("callGraphAssistTask", () => {
  it("has correct task metadata", () => {
    expect(callGraphAssistTask.id).toBe("call-graph-assist");
    expect(callGraphAssistTask.outputKind).toBe("findings");
  });

  it("enriches high-score findings with call-chain evidence from taintPath", async () => {
    const mockProvider = {
      getCallers: vi.fn().mockResolvedValue(["handleRequest", "router.post"]),
    };
    mockedGetProvider.mockResolvedValue(mockProvider as any);

    const finding = makeFinding("fp-high", 85, {
      taintPath: [
        { filePath: "src/routes/api.ts", line: 42, message: "user input" },
        { filePath: "src/services/fetcher.ts", line: 15, message: "passed to fetch(url)" },
      ],
    });

    const result = await callGraphAssistTask.run([finding], makeContext());
    expect(result).toHaveLength(1);
    expect(result[0].evidence).toContain("Call chain:");
    expect(result[0].evidence).toContain("handleRequest");
    expect(result[0].evidence).toContain("router.post");
  });

  it("skips findings below score threshold", async () => {
    const mockProvider = {
      getCallers: vi.fn(),
    };
    mockedGetProvider.mockResolvedValue(mockProvider as any);

    const lowScore = makeFinding("fp-low", 3);
    const result = await callGraphAssistTask.run([lowScore], makeContext());
    expect(result).toHaveLength(1);
    expect(result[0].evidence).toBeUndefined();
    expect(mockProvider.getCallers).not.toHaveBeenCalled();
  });

  it("passes through findings when code intelligence fails to initialize", async () => {
    mockedGetProvider.mockRejectedValue(new Error("no LSP available"));

    const finding = makeFinding("fp-nolsp", 90);
    const result = await callGraphAssistTask.run([finding], makeContext());
    expect(result).toHaveLength(1);
    expect(result[0].fingerprint).toBe("fp-nolsp");
  });

  it("returns input unchanged when empty", async () => {
    const result = await callGraphAssistTask.run([], makeContext());
    expect(result).toEqual([]);
  });

  it("appends to existing evidence without overwriting", async () => {
    const mockProvider = {
      getCallers: vi.fn().mockResolvedValue(["caller1"]),
    };
    mockedGetProvider.mockResolvedValue(mockProvider as any);

    const finding = makeFinding("fp-existing", 90, {
      evidence: "Existing evidence here",
      taintPath: [
        { filePath: "a.ts", line: 1, message: "calls doStuff()" },
      ],
    });

    const result = await callGraphAssistTask.run([finding], makeContext());
    expect(result[0].evidence).toContain("Existing evidence here");
    expect(result[0].evidence).toContain("Call chain:");
  });
});
