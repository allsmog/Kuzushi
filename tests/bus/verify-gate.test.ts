import { describe, expect, it, vi } from "vitest";
import {
  gateVerificationCandidates,
  type VerifyGateCandidate,
} from "../../src/bus/orchestrator/verify-gate.js";
import type { Finding } from "../../src/scanners/types.js";
import type { TriageResult } from "../../src/types.js";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    fingerprint: "fp-001",
    scanner: "semgrep",
    ruleId: "javascript.lang.security.audit.xss.no-xss",
    filePath: "src/app.ts",
    startLine: 42,
    endLine: 42,
    severity: "ERROR",
    message: "Potential XSS vulnerability",
    evidence: "user input passed to innerHTML",
    cwe: ["CWE-79"],
    score: 7,
    ...overrides,
  } as Finding;
}

function makeTriageResult(overrides: Partial<TriageResult> = {}): TriageResult {
  return {
    verdict: "tp",
    confidence: 0.85,
    rationale: "User input flows directly to innerHTML without sanitization.",
    verificationSteps: ["Check input sanitization", "Test with XSS payload"],
    fixPatch: null,
    ...overrides,
  } as TriageResult;
}

function makeCandidate(
  findingOverrides?: Partial<Finding>,
  triageOverrides?: Partial<TriageResult>,
): VerifyGateCandidate {
  return {
    finding: makeFinding(findingOverrides),
    triageResult: makeTriageResult(triageOverrides),
  };
}

describe("gateVerificationCandidates", () => {
  it("returns empty array for empty input", async () => {
    const runtime = {} as AgentRuntime;
    const results = await gateVerificationCandidates([], {
      runtime,
      repoRoot: "/tmp",
    });
    expect(results).toEqual([]);
  });

  it("defaults to verify when batch API is unavailable", async () => {
    const runtime = {
      id: "test",
      createSession: vi.fn(),
    } as unknown as AgentRuntime;

    const results = await gateVerificationCandidates(
      [makeCandidate()],
      { runtime, repoRoot: "/tmp" },
    );

    expect(results).toHaveLength(1);
    expect(results[0].decision).toBe("verify");
    expect(results[0].fingerprint).toBe("fp-001");
  });

  it("parses structured batch output into decisions", async () => {
    const runtime = {
      id: "test",
      queryBatch: vi.fn().mockResolvedValue(
        new Map([
          ["gate-batch0", {
            resultText: "",
            structuredOutput: {
              decisions: [
                { fingerprint: "fp-001", decision: "auto_accept", reason: "Clear XSS" },
                { fingerprint: "fp-002", decision: "skip", reason: "Informational only" },
                { fingerprint: "fp-003", decision: "verify", reason: "Needs investigation" },
              ],
            },
            executionError: null,
            costUsd: 0.001,
          }],
        ]),
      ),
    } as unknown as AgentRuntime;

    const results = await gateVerificationCandidates(
      [
        makeCandidate({ fingerprint: "fp-001" }),
        makeCandidate({ fingerprint: "fp-002" }),
        makeCandidate({ fingerprint: "fp-003" }),
      ],
      { runtime, repoRoot: "/tmp" },
    );

    expect(results).toHaveLength(3);
    expect(results[0]).toEqual({
      fingerprint: "fp-001",
      decision: "auto_accept",
      reason: "Clear XSS",
    });
    expect(results[1]).toEqual({
      fingerprint: "fp-002",
      decision: "skip",
      reason: "Informational only",
    });
    expect(results[2]).toEqual({
      fingerprint: "fp-003",
      decision: "verify",
      reason: "Needs investigation",
    });
  });

  it("defaults missing findings to verify", async () => {
    const runtime = {
      id: "test",
      queryBatch: vi.fn().mockResolvedValue(
        new Map([
          ["gate-batch0", {
            resultText: "",
            structuredOutput: {
              decisions: [
                { fingerprint: "fp-001", decision: "skip", reason: "Low quality" },
                // fp-002 missing from response
              ],
            },
            executionError: null,
            costUsd: 0.001,
          }],
        ]),
      ),
    } as unknown as AgentRuntime;

    const results = await gateVerificationCandidates(
      [
        makeCandidate({ fingerprint: "fp-001" }),
        makeCandidate({ fingerprint: "fp-002" }),
      ],
      { runtime, repoRoot: "/tmp" },
    );

    expect(results[0].decision).toBe("skip");
    expect(results[1].decision).toBe("verify");
    expect(results[1].reason).toContain("defaulting to verify");
  });

  it("defaults to verify on batch error", async () => {
    const runtime = {
      id: "test",
      queryBatch: vi.fn().mockResolvedValue(
        new Map([
          ["gate-batch0", {
            resultText: "",
            structuredOutput: undefined,
            executionError: "API error",
            costUsd: 0,
          }],
        ]),
      ),
    } as unknown as AgentRuntime;

    const results = await gateVerificationCandidates(
      [makeCandidate({ fingerprint: "fp-001" })],
      { runtime, repoRoot: "/tmp" },
    );

    expect(results).toHaveLength(1);
    expect(results[0].decision).toBe("verify");
    expect(results[0].reason).toContain("API error");
  });

  it("sanitizes invalid decision values to verify", async () => {
    const runtime = {
      id: "test",
      queryBatch: vi.fn().mockResolvedValue(
        new Map([
          ["gate-batch0", {
            resultText: "",
            structuredOutput: {
              decisions: [
                { fingerprint: "fp-001", decision: "invalid_value", reason: "Bad" },
              ],
            },
            executionError: null,
            costUsd: 0.001,
          }],
        ]),
      ),
    } as unknown as AgentRuntime;

    const results = await gateVerificationCandidates(
      [makeCandidate({ fingerprint: "fp-001" })],
      { runtime, repoRoot: "/tmp" },
    );

    expect(results[0].decision).toBe("verify");
  });
});
