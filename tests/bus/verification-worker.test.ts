import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "../../src/scanners/types.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerVerificationWorker } from "../../src/bus/workers/verification-worker.js";
import type {
  VerificationAgentActivityEvent,
  VerificationErrorEvent,
  VerificationResultEvent,
} from "../../src/bus/events.js";
import type { KuzushiConfig, TriageResult, VerificationResult } from "../../src/types.js";

const {
  verifyFindingWithAgentMock,
  verifyFindingsBatchMock,
  generatePocHarnessMock,
  createPocExecutorMock,
  executorExecuteMock,
  VerificationExecutionErrorMock,
} = vi.hoisted(() => {
  class VerificationExecutionErrorMock extends Error {
    readonly costUsd: number;

    constructor(message: string, costUsd = 0) {
      super(message);
      this.name = "VerificationExecutionError";
      this.costUsd = costUsd;
    }
  }

  return {
    verifyFindingWithAgentMock: vi.fn(),
    generatePocHarnessMock: vi.fn(),
    createPocExecutorMock: vi.fn(),
    executorExecuteMock: vi.fn(),
    VerificationExecutionErrorMock,
    verifyFindingsBatchMock: vi.fn(),
  };
});

vi.mock("../../src/verify.js", () => ({
  verifyFindingWithAgent: verifyFindingWithAgentMock,
  verifyFindingsBatch: verifyFindingsBatchMock,
  VerificationExecutionError: VerificationExecutionErrorMock,
}));

vi.mock("../../src/poc-harness.js", () => ({
  generatePocHarness: generatePocHarnessMock,
}));

vi.mock("../../src/poc-executor/index.js", () => ({
  createPocExecutor: createPocExecutorMock,
}));

function makeFinding(): Finding {
  return {
    scanner: "semgrep",
    fingerprint: "fp-verify-1",
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: 7,
    severity: "ERROR",
    message: "possible vulnerability",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-79"],
    score: 61,
  };
}

function makeTriageResult(): TriageResult {
  return {
    fingerprint: "fp-verify-1",
    verdict: "tp",
    confidence: 0.91,
    rationale: "confirmed by triage",
    verificationSteps: ["trace source", "check sink"],
    fixPatch: null,
  };
}

function makeVerificationResult(): VerificationResult {
  return {
    fingerprint: "fp-verify-1",
    exploitable: true,
    pocPayload: "<script>alert(1)</script>",
    pocDescription: "Inject into unsanitized output.",
    attackVector: "query param",
    preconditions: ["Endpoint is reachable"],
    confidence: 0.88,
  };
}

function makeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    maxVerifyRetries: 0,
    verifyRefinementMaxIterations: 1,
    retryBackoffMs: 0,
    retryBackoffMultiplier: 2,
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    scanners: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    scannerConfig: { semgrep: {} },
    ...overrides,
  };
}

afterEach(() => {
  verifyFindingWithAgentMock.mockReset();
  verifyFindingsBatchMock.mockReset();
  generatePocHarnessMock.mockReset();
  createPocExecutorMock.mockReset();
  executorExecuteMock.mockReset();
});

describe("verification-worker", () => {
  it("publishes verification:result on success", async () => {
    const bus = new InProcessBus();
    const config = makeConfig({
      verifyModel: "claude-haiku-4-5-20251001",
      verifyMaxTurns: 17,
    });

    verifyFindingWithAgentMock.mockResolvedValue({
      result: makeVerificationResult(),
      costUsd: 0.0065,
    });

    registerVerificationWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const finding = makeFinding();
    const triageResult = makeTriageResult();
    const resultPromise = bus.waitFor<VerificationResultEvent>(
      "verification:result",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("verification:finding-queued", runId, {
        context,
        finding,
        triageResult,
        index: 1,
        total: 1,
      }),
    );

    const event = await resultPromise;
    expect(event.payload.result.exploitable).toBe(true);
    expect(event.payload.costUsd).toBe(0.0065);
    expect(event.payload.result.verifyCostUsd).toBe(0.0065);
    expect(verifyFindingWithAgentMock).toHaveBeenCalledWith(
      finding,
      triageResult,
      "/tmp/repo",
      "repo",
      "claude-haiku-4-5-20251001",
      undefined,
      expect.objectContaining({
        activityCallback: expect.any(Function),
      }),
      expect.any(String),
    );

    await bus.close();
  });

  it("publishes verification:error with cost when VerificationExecutionError is thrown", async () => {
    const bus = new InProcessBus();
    const config = makeConfig();

    verifyFindingWithAgentMock.mockRejectedValue(
      new VerificationExecutionErrorMock("verification failed", 0.013),
    );

    registerVerificationWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const errorPromise = bus.waitFor<VerificationErrorEvent>(
      "verification:error",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("verification:finding-queued", runId, {
        context,
        finding: makeFinding(),
        triageResult: makeTriageResult(),
        index: 1,
        total: 1,
      }),
    );

    const event = await errorPromise;
    expect(event.payload.error).toContain("verification failed");
    expect(event.payload.costUsd).toBe(0.013);

    await bus.close();
  });

  it("forwards activity callback updates as verification:agent-activity events", async () => {
    const bus = new InProcessBus();
    const config = makeConfig();

    verifyFindingWithAgentMock.mockImplementation(async (...args: any[]) => {
      const runtimeOptions = args[6];
      await runtimeOptions?.activityCallback?.({
        kind: "tool-start",
        toolName: "Read",
        toolInput: { file_path: "src/app.ts" },
      });

      return {
        result: makeVerificationResult(),
        costUsd: 0.004,
      };
    });

    registerVerificationWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const activityPromise = bus.waitFor<VerificationAgentActivityEvent>(
      "verification:agent-activity",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("verification:finding-queued", runId, {
        context,
        finding: makeFinding(),
        triageResult: makeTriageResult(),
        index: 1,
        total: 1,
      }),
    );

    const activityEvent = await activityPromise;
    expect(activityEvent.payload.kind).toBe("tool-start");
    expect(activityEvent.payload.toolName).toBe("Read");
    expect(activityEvent.payload.fingerprint).toBe("fp-verify-1");

    await bus.close();
  });

  it("retries verification failures and emits verification:result after retry success", async () => {
    const bus = new InProcessBus();
    const config = makeConfig({
      maxVerifyRetries: 2,
      retryBackoffMs: 0,
    });

    verifyFindingWithAgentMock
      .mockRejectedValueOnce(new Error("rate limited"))
      .mockResolvedValueOnce({
        result: makeVerificationResult(),
        costUsd: 0.008,
      });

    registerVerificationWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const resultPromise = bus.waitFor<VerificationResultEvent>(
      "verification:result",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("verification:finding-queued", runId, {
        context,
        finding: makeFinding(),
        triageResult: makeTriageResult(),
        index: 1,
        total: 1,
      }),
    );

    const resultEvent = await resultPromise;
    expect(resultEvent.payload.result.exploitable).toBe(true);
    expect(resultEvent.payload.attempts).toBe(2);
    expect(verifyFindingWithAgentMock).toHaveBeenCalledTimes(2);

    await bus.close();
  });

  it("refines inconclusive verification with probe execution feedback", async () => {
    const bus = new InProcessBus();
    const config = makeConfig({
      verifyRefinementMaxIterations: 3,
      verifyReflectionInterval: 2,
      pocHarnessMaxTurns: 9,
    });

    verifyFindingWithAgentMock
      .mockResolvedValueOnce({
        result: {
          ...makeVerificationResult(),
          confidence: 0.6,
          proofVerdict: undefined,
        },
        costUsd: 0.01,
      })
      .mockResolvedValueOnce({
        result: {
          ...makeVerificationResult(),
          confidence: 0.95,
          proofVerdict: "exploited",
        },
        costUsd: 0.03,
      });

    generatePocHarnessMock.mockResolvedValue({
      result: {
        fingerprint: "fp-verify-1",
        scriptPath: "/tmp/repo/.kuzushi/poc/probe.ts",
        language: "typescript",
        scriptContent: "console.log('FAIL');",
        parsed: true,
        parseError: null,
        skipped: false,
        skipReason: null,
      },
      costUsd: 0.02,
    });

    executorExecuteMock.mockResolvedValue({
      exitCode: 1,
      stdout: "FAIL",
      stderr: "bad payload",
      timedOut: false,
      durationMs: 12,
      verdict: "FAIL",
    });
    createPocExecutorMock.mockResolvedValue({
      available: async () => true,
      execute: executorExecuteMock,
    });

    registerVerificationWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const resultPromise = bus.waitFor<VerificationResultEvent>(
      "verification:result",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("verification:finding-queued", runId, {
        context,
        finding: makeFinding(),
        triageResult: makeTriageResult(),
        index: 1,
        total: 1,
      }),
    );

    const resultEvent = await resultPromise;
    expect(resultEvent.payload.result.proofVerdict).toBe("exploited");
    expect(resultEvent.payload.costUsd).toBeCloseTo(0.06);
    expect(verifyFindingWithAgentMock).toHaveBeenCalledTimes(2);
    expect(generatePocHarnessMock).toHaveBeenCalledTimes(1);
    expect(executorExecuteMock).toHaveBeenCalledTimes(1);
    expect(verifyFindingWithAgentMock.mock.calls[1]?.[6]).toEqual(
      expect.objectContaining({
        history: expect.arrayContaining([
          expect.objectContaining({ role: "assistant" }),
          expect.objectContaining({
            role: "user",
            content: expect.stringContaining("Exit code: 1"),
          }),
        ]),
      }),
    );

    await bus.close();
  });

  it("requeues batch-missing findings for individual verification instead of synthesizing not-exploitable", async () => {
    const bus = new InProcessBus();
    const config = makeConfig();

    verifyFindingsBatchMock.mockResolvedValue({
      results: new Map([
        ["fp-verify-1", makeVerificationResult()],
      ]),
      costUsd: 0.02,
      missingFingerprints: ["fp-verify-2"],
      incomplete: true,
      recoveredByRetry: [],
    });
    verifyFindingWithAgentMock.mockResolvedValue({
      result: {
        ...makeVerificationResult(),
        fingerprint: "fp-verify-2",
      },
      costUsd: 0.01,
    });

    registerVerificationWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const retriedResultPromise = bus.waitFor<VerificationResultEvent>(
      "verification:result",
      (event) => event.meta.runId === runId && event.payload.finding.fingerprint === "fp-verify-2",
    );

    await bus.publish(
      createEvent("verification:batch-queued", runId, {
        context,
        items: [
          { finding: makeFinding(), triageResult: makeTriageResult(), index: 1, total: 2 },
          {
            finding: { ...makeFinding(), fingerprint: "fp-verify-2" },
            triageResult: { ...makeTriageResult(), fingerprint: "fp-verify-2" },
            index: 2,
            total: 2,
          },
        ],
        index: 1,
        total: 2,
      } as any),
    );

    const retriedResult = await retriedResultPromise;
    expect(retriedResult.payload.finding.fingerprint).toBe("fp-verify-2");
    expect(retriedResult.payload.result.exploitable).toBe(true);
    expect(verifyFindingsBatchMock).toHaveBeenCalledTimes(1);
    expect(verifyFindingWithAgentMock).toHaveBeenCalledTimes(1);

    await bus.close();
  });
});
