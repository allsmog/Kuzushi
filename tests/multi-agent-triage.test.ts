import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "../src/scanners/types.js";
import type { TriageResult } from "../src/types.js";

const { runStructuredAgentQueryMock } = vi.hoisted(() => ({
  runStructuredAgentQueryMock: vi.fn(),
}));

const { triageFindingWithAgentMock } = vi.hoisted(() => ({
  triageFindingWithAgentMock: vi.fn(),
}));

vi.mock("../src/agent-runtime/execution.js", async (importOriginal) => {
  const original = await importOriginal() as Record<string, unknown>;
  return {
    ...original,
    runStructuredAgentQuery: runStructuredAgentQueryMock,
  };
});

vi.mock("../src/triage.js", async (importOriginal) => {
  const original = await importOriginal() as Record<string, unknown>;
  return {
    ...original,
    triageFindingWithAgent: triageFindingWithAgentMock,
  };
});

// Import after mocks
const { triageFindingMultiAgent } = await import("../src/multi-agent-triage.js");

function makeFinding(): Finding {
  return {
    taskId: "semgrep",
    fingerprint: "fp-1",
    ruleId: "express.sqli.tainted",
    filePath: "src/routes/users.ts",
    startLine: 42,
    severity: "ERROR",
    message: "SQL injection via string concatenation",
    scannerConfidence: "HIGH",
    subcategory: ["sqli"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 80,
    evidence: "const query = `SELECT * FROM users WHERE id = ${req.params.id}`",
  };
}

function makeSpecialistResult(overrides: Partial<{
  role: string;
  findings: string;
  is_false_positive: boolean;
  evidence: string;
  confidence: number;
}> = {}) {
  return {
    resultText: "",
    structuredOutput: {
      role: overrides.role ?? "source-tracer",
      findings: overrides.findings ?? "found user input flow",
      is_false_positive: overrides.is_false_positive ?? false,
      evidence: overrides.evidence ?? "req.params.id flows directly to SQL query",
      confidence: overrides.confidence ?? 0.8,
    },
    executionError: null,
    costUsd: 0.005,
  };
}

function makeManagerResult(verdict: string = "tp", confidence: number = 0.85): {
  resultText: string;
  structuredOutput: Record<string, unknown>;
  executionError: null;
  costUsd: number;
} {
  return {
    resultText: "",
    structuredOutput: {
      fingerprint: "fp-1",
      verdict,
      confidence,
      rationale: "All specialists confirm exploitable SQL injection",
      verification_steps: ["Test with SQLi payload"],
      fix_patch: null,
    },
    executionError: null,
    costUsd: 0.01,
  };
}

const mockTriageConfigProvider = {
  has: () => false,
  get: () => { throw new Error("not found"); },
};

afterEach(() => {
  runStructuredAgentQueryMock.mockReset();
  triageFindingWithAgentMock.mockReset();
});

describe("triageFindingMultiAgent", () => {
  it("dispatches 4 specialists + 1 manager and returns TriageResult", async () => {
    // First 4 calls are specialists, 5th is manager
    runStructuredAgentQueryMock
      .mockResolvedValueOnce(makeSpecialistResult({ role: "source-tracer" }))
      .mockResolvedValueOnce(makeSpecialistResult({ role: "sink-analyzer" }))
      .mockResolvedValueOnce(makeSpecialistResult({ role: "sanitization-checker", is_false_positive: false }))
      .mockResolvedValueOnce(makeSpecialistResult({ role: "config-reviewer" }))
      .mockResolvedValueOnce(makeManagerResult("tp", 0.85));

    const result = await triageFindingMultiAgent(
      mockTriageConfigProvider,
      makeFinding(),
      "/tmp/repo",
      "test-repo",
      "anthropic:claude-sonnet-4-6",
      "anthropic:claude-sonnet-4-6",
      null,
      null,
    );

    expect(result.result.verdict).toBe("tp");
    expect(result.result.confidence).toBe(0.85);
    // 4 specialist costs + 1 manager cost
    expect(result.costUsd).toBe(0.005 * 4 + 0.01);
    expect(runStructuredAgentQueryMock).toHaveBeenCalledTimes(5);
  });

  it("falls back to single-agent when all specialists fail", async () => {
    // All 4 specialists fail
    runStructuredAgentQueryMock
      .mockResolvedValueOnce({ resultText: "", structuredOutput: null, executionError: "rate limit", costUsd: 0.001 })
      .mockResolvedValueOnce({ resultText: "", structuredOutput: null, executionError: "rate limit", costUsd: 0.001 })
      .mockResolvedValueOnce({ resultText: "", structuredOutput: null, executionError: "rate limit", costUsd: 0.001 })
      .mockResolvedValueOnce({ resultText: "", structuredOutput: null, executionError: "rate limit", costUsd: 0.001 });

    triageFindingWithAgentMock.mockResolvedValue({
      result: {
        fingerprint: "fp-1",
        verdict: "needs_review",
        confidence: 0.5,
        rationale: "fallback",
        verificationSteps: ["check"],
        fixPatch: null,
      },
      costUsd: 0.02,
    });

    const result = await triageFindingMultiAgent(
      mockTriageConfigProvider,
      makeFinding(),
      "/tmp/repo",
      "test-repo",
      "anthropic:claude-sonnet-4-6",
      "anthropic:claude-sonnet-4-6",
      null,
      null,
    );

    expect(result.result.verdict).toBe("needs_review");
    expect(triageFindingWithAgentMock).toHaveBeenCalledTimes(1);
    // Specialist costs + fallback cost
    expect(result.costUsd).toBe(0.001 * 4 + 0.02);
  });

  it("continues with partial specialist results when some fail", async () => {
    // 2 specialists succeed, 2 fail
    runStructuredAgentQueryMock
      .mockResolvedValueOnce(makeSpecialistResult({ role: "source-tracer" }))
      .mockResolvedValueOnce({ resultText: "", structuredOutput: null, executionError: "timeout", costUsd: 0.001 })
      .mockResolvedValueOnce(makeSpecialistResult({ role: "sanitization-checker" }))
      .mockResolvedValueOnce({ resultText: "", structuredOutput: null, executionError: "timeout", costUsd: 0.001 })
      .mockResolvedValueOnce(makeManagerResult("tp", 0.7));

    const result = await triageFindingMultiAgent(
      mockTriageConfigProvider,
      makeFinding(),
      "/tmp/repo",
      "test-repo",
      "anthropic:claude-sonnet-4-6",
      "anthropic:claude-sonnet-4-6",
      null,
      null,
    );

    expect(result.result.verdict).toBe("tp");
    expect(result.result.confidence).toBe(0.7);
    // 5 calls total (4 specialists + 1 manager)
    expect(runStructuredAgentQueryMock).toHaveBeenCalledTimes(5);
  });

  it("produces same TriageResult shape as single-agent", async () => {
    runStructuredAgentQueryMock
      .mockResolvedValueOnce(makeSpecialistResult())
      .mockResolvedValueOnce(makeSpecialistResult())
      .mockResolvedValueOnce(makeSpecialistResult())
      .mockResolvedValueOnce(makeSpecialistResult())
      .mockResolvedValueOnce(makeManagerResult());

    const result = await triageFindingMultiAgent(
      mockTriageConfigProvider,
      makeFinding(),
      "/tmp/repo",
      "test-repo",
      "anthropic:claude-sonnet-4-6",
      "anthropic:claude-sonnet-4-6",
      null,
      null,
    );

    // Verify TriageResult shape
    expect(result.result).toHaveProperty("fingerprint");
    expect(result.result).toHaveProperty("verdict");
    expect(result.result).toHaveProperty("confidence");
    expect(result.result).toHaveProperty("rationale");
    expect(result.result).toHaveProperty("verificationSteps");
    expect(result.result).toHaveProperty("fixPatch");
    expect(typeof result.costUsd).toBe("number");
  });

  it("throws TriageExecutionError when manager fails", async () => {
    runStructuredAgentQueryMock
      .mockResolvedValueOnce(makeSpecialistResult())
      .mockResolvedValueOnce(makeSpecialistResult())
      .mockResolvedValueOnce(makeSpecialistResult())
      .mockResolvedValueOnce(makeSpecialistResult())
      .mockResolvedValueOnce({
        resultText: "",
        structuredOutput: null,
        executionError: "manager crashed",
        costUsd: 0.01,
      });

    await expect(
      triageFindingMultiAgent(
        mockTriageConfigProvider,
        makeFinding(),
        "/tmp/repo",
        "test-repo",
        "anthropic:claude-sonnet-4-6",
        "anthropic:claude-sonnet-4-6",
        null,
        null,
      ),
    ).rejects.toThrow("multi-agent manager failed");
  });

  it("handles specialist exceptions gracefully", async () => {
    runStructuredAgentQueryMock
      .mockRejectedValueOnce(new Error("network error"))
      .mockResolvedValueOnce(makeSpecialistResult())
      .mockResolvedValueOnce(makeSpecialistResult())
      .mockResolvedValueOnce(makeSpecialistResult())
      .mockResolvedValueOnce(makeManagerResult());

    const result = await triageFindingMultiAgent(
      mockTriageConfigProvider,
      makeFinding(),
      "/tmp/repo",
      "test-repo",
      "anthropic:claude-sonnet-4-6",
      "anthropic:claude-sonnet-4-6",
      null,
      null,
    );

    expect(result.result.verdict).toBe("tp");
  });
});
