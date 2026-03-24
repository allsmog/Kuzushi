import { describe, it, expect, vi, beforeEach } from "vitest";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import type { Finding } from "../../src/scanners/types.js";

// Mock the agent runtime execution
vi.mock("../../src/agent-runtime/execution.js", () => ({
  runStructuredAgentQuery: vi.fn(),
  DEFAULT_READ_ONLY_TOOLS: ["Read", "Glob", "Grep", "GetCallers", "GetCallees", "GetFunctionBody"],
}));

// Mock fs
vi.mock("node:fs", async () => {
  const actual = await vi.importActual<typeof import("node:fs")>("node:fs");
  return {
    ...actual,
    readFileSync: vi.fn().mockReturnValue("line1\nline2\nline3\nline4\nline5\n"),
  };
});

import { rescoreFindings, type LlmRescoreResult } from "../../src/scanners/llm-rescore.js";
import { runStructuredAgentQuery } from "../../src/agent-runtime/execution.js";

const mockRunQuery = vi.mocked(runStructuredAgentQuery);
const runtime = { id: "test-runtime", query: vi.fn() } as unknown as AgentRuntime;

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    scanner: "test",
    fingerprint: "fp-" + Math.random().toString(36).slice(2, 8),
    ruleId: "test/rule",
    filePath: "src/app.ts",
    startLine: 3,
    severity: "WARNING",
    message: "Test finding",
    evidence: null,
    scannerConfidence: "MEDIUM",
    subcategory: ["vuln"],
    likelihood: "MEDIUM",
    impact: "MEDIUM",
    cwe: [],
    score: 4,
    ...overrides,
  };
}

describe("rescoreFindings", () => {
  beforeEach(() => {
    mockRunQuery.mockReset();
  });

  it("returns empty array for no findings", async () => {
    const results = await rescoreFindings([], { repoRoot: "/repo", runtime });
    expect(results).toEqual([]);
  });

  it("keeps findings scoring at or above threshold", async () => {
    mockRunQuery.mockResolvedValue({
      resultText: "",
      structuredOutput: { score: 7, reason: "Likely true positive" },
      executionError: null,
      costUsd: 0.001,
    });

    const findings = [makeFinding({ fingerprint: "fp-1" })];
    const results = await rescoreFindings(findings, {
      repoRoot: "/repo",
      threshold: 4,
      runtime,
    });

    expect(results).toHaveLength(1);
    expect(results[0].keep).toBe(true);
    expect(results[0].score).toBe(7);
  });

  it("excludes findings scoring below threshold", async () => {
    mockRunQuery.mockResolvedValue({
      resultText: "",
      structuredOutput: { score: 2, reason: "Clearly a false positive" },
      executionError: null,
      costUsd: 0.001,
    });

    const findings = [makeFinding({ fingerprint: "fp-1" })];
    const results = await rescoreFindings(findings, {
      repoRoot: "/repo",
      threshold: 4,
      runtime,
    });

    expect(results).toHaveLength(1);
    expect(results[0].keep).toBe(false);
    expect(results[0].score).toBe(2);
  });

  it("keeps findings on execution error", async () => {
    mockRunQuery.mockResolvedValue({
      resultText: "",
      structuredOutput: null,
      executionError: "timeout",
      costUsd: 0,
    });

    const findings = [makeFinding({ fingerprint: "fp-1" })];
    const results = await rescoreFindings(findings, {
      repoRoot: "/repo",
      threshold: 4,
      runtime,
    });

    expect(results).toHaveLength(1);
    expect(results[0].keep).toBe(true);
  });

  it("processes multiple findings", async () => {
    let callCount = 0;
    mockRunQuery.mockImplementation(async () => {
      callCount++;
      return {
        resultText: "",
        structuredOutput: { score: callCount <= 1 ? 8 : 2, reason: "test" },
        executionError: null,
        costUsd: 0.001,
      };
    });

    const findings = [
      makeFinding({ fingerprint: "fp-keep" }),
      makeFinding({ fingerprint: "fp-drop" }),
    ];

    const results = await rescoreFindings(findings, {
      repoRoot: "/repo",
      threshold: 4,
      runtime,
    });

    expect(results).toHaveLength(2);
    const kept = results.filter((r) => r.keep);
    const dropped = results.filter((r) => !r.keep);
    expect(kept.length + dropped.length).toBe(2);
  });
});
