import { afterEach, describe, expect, it, vi } from "vitest";
import type { Finding } from "../../src/scanners/types.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerPocHarnessWorker } from "../../src/bus/workers/poc-harness-worker.js";
import type {
  PocHarnessAgentActivityEvent,
  PocHarnessErrorEvent,
  PocHarnessResultEvent,
} from "../../src/bus/events.js";
import type { KuzushiConfig, PocHarnessResult, TriageResult, VerificationResult } from "../../src/types.js";

const { generatePocHarnessMock, PocHarnessExecutionErrorMock } = vi.hoisted(() => {
  class PocHarnessExecutionErrorMock extends Error {
    readonly costUsd: number;

    constructor(message: string, costUsd = 0) {
      super(message);
      this.name = "PocHarnessExecutionError";
      this.costUsd = costUsd;
    }
  }

  return {
    generatePocHarnessMock: vi.fn(),
    PocHarnessExecutionErrorMock,
  };
});

vi.mock("../../src/poc-harness.js", () => ({
  generatePocHarness: generatePocHarnessMock,
  PocHarnessExecutionError: PocHarnessExecutionErrorMock,
}));

function makeFinding(): Finding {
  return {
    scanner: "semgrep",
    fingerprint: "fp-poc-1",
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
    fingerprint: "fp-poc-1",
    verdict: "tp",
    confidence: 0.91,
    rationale: "confirmed by triage",
    verificationSteps: ["trace source", "check sink"],
    fixPatch: null,
  };
}

function makeVerificationResult(): VerificationResult {
  return {
    fingerprint: "fp-poc-1",
    exploitable: true,
    pocPayload: "<script>alert(1)</script>",
    pocDescription: "Inject into unsanitized output.",
    attackVector: "query param",
    preconditions: ["Endpoint is reachable"],
    confidence: 0.88,
  };
}

function makePocHarnessResult(): PocHarnessResult {
  return {
    fingerprint: "fp-poc-1",
    scriptPath: "/tmp/repo/.kuzushi/poc/fp-poc-1-cwe79.ts",
    language: "typescript",
    scriptContent: "console.log('PASS');",
    parsed: true,
    parseError: null,
    skipped: false,
    skipReason: null,
  };
}

function makeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    maxVerifyRetries: 0,
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
  generatePocHarnessMock.mockReset();
});

describe("poc-harness-worker", () => {
  it("publishes poc-harness:result on success", async () => {
    const bus = new InProcessBus();
    const config = makeConfig({
      pocHarnessModel: "claude-haiku-4-5-20251001",
      pocHarnessMaxTurns: 17,
    });

    generatePocHarnessMock.mockResolvedValue({
      result: makePocHarnessResult(),
      costUsd: 0.0065,
    });

    registerPocHarnessWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const finding = makeFinding();
    const triageResult = makeTriageResult();
    const verificationResult = makeVerificationResult();
    const resultPromise = bus.waitFor<PocHarnessResultEvent>(
      "poc-harness:result",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("poc-harness:finding-queued", runId, {
        context,
        finding,
        triageResult,
        verificationResult,
        index: 1,
        total: 1,
      }),
    );

    const event = await resultPromise;
    expect(event.payload.result.skipped).toBe(false);
    expect(event.payload.costUsd).toBe(0.0065);
    expect(event.payload.result.costUsd).toBe(0.0065);
    expect(generatePocHarnessMock).toHaveBeenCalledWith(
      finding,
      triageResult,
      verificationResult,
      "/tmp/repo",
      "repo",
      "claude-haiku-4-5-20251001",
      17,
      undefined,
      expect.objectContaining({
        activityCallback: expect.any(Function),
      }),
    );

    await bus.close();
  });

  it("publishes poc-harness:error with cost when PocHarnessExecutionError is thrown", async () => {
    const bus = new InProcessBus();
    const config = makeConfig();

    generatePocHarnessMock.mockRejectedValue(
      new PocHarnessExecutionErrorMock("generation failed", 0.013),
    );

    registerPocHarnessWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const errorPromise = bus.waitFor<PocHarnessErrorEvent>(
      "poc-harness:error",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("poc-harness:finding-queued", runId, {
        context,
        finding: makeFinding(),
        triageResult: makeTriageResult(),
        verificationResult: makeVerificationResult(),
        index: 1,
        total: 1,
      }),
    );

    const event = await errorPromise;
    expect(event.payload.error).toContain("generation failed");
    expect(event.payload.costUsd).toBe(0.013);

    await bus.close();
  });

  it("forwards activity callback updates as poc-harness:agent-activity events", async () => {
    const bus = new InProcessBus();
    const config = makeConfig();

    generatePocHarnessMock.mockImplementation(async (...args: any[]) => {
      const runtimeOptions = args[8];
      await runtimeOptions?.activityCallback?.({
        kind: "tool-start",
        toolName: "Read",
        toolInput: { file_path: "src/app.ts" },
      });

      return {
        result: makePocHarnessResult(),
        costUsd: 0.004,
      };
    });

    registerPocHarnessWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const activityPromise = bus.waitFor<PocHarnessAgentActivityEvent>(
      "poc-harness:agent-activity",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("poc-harness:finding-queued", runId, {
        context,
        finding: makeFinding(),
        triageResult: makeTriageResult(),
        verificationResult: makeVerificationResult(),
        index: 1,
        total: 1,
      }),
    );

    const activityEvent = await activityPromise;
    expect(activityEvent.payload.kind).toBe("tool-start");
    expect(activityEvent.payload.toolName).toBe("Read");
    expect(activityEvent.payload.fingerprint).toBe("fp-poc-1");

    await bus.close();
  });

  it("retries generation failures and emits poc-harness:result after retry success", async () => {
    const bus = new InProcessBus();
    const config = makeConfig({
      maxVerifyRetries: 2,
      retryBackoffMs: 0,
    });

    generatePocHarnessMock
      .mockRejectedValueOnce(new Error("rate limited"))
      .mockResolvedValueOnce({
        result: makePocHarnessResult(),
        costUsd: 0.008,
      });

    registerPocHarnessWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const resultPromise = bus.waitFor<PocHarnessResultEvent>(
      "poc-harness:result",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("poc-harness:finding-queued", runId, {
        context,
        finding: makeFinding(),
        triageResult: makeTriageResult(),
        verificationResult: makeVerificationResult(),
        index: 1,
        total: 1,
      }),
    );

    const resultEvent = await resultPromise;
    expect(resultEvent.payload.result.skipped).toBe(false);
    expect(resultEvent.payload.attempts).toBe(2);
    expect(generatePocHarnessMock).toHaveBeenCalledTimes(2);

    await bus.close();
  });

  it("uses maxPocHarnessRetries independently from maxVerifyRetries", async () => {
    const bus = new InProcessBus();
    const config = makeConfig({
      maxVerifyRetries: 0,
      maxPocHarnessRetries: 1,
      retryBackoffMs: 0,
    });

    generatePocHarnessMock
      .mockRejectedValueOnce(new Error("service temporarily unavailable"))
      .mockResolvedValueOnce({
        result: makePocHarnessResult(),
        costUsd: 0.003,
      });

    registerPocHarnessWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const resultPromise = bus.waitFor<PocHarnessResultEvent>(
      "poc-harness:result",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("poc-harness:finding-queued", runId, {
        context,
        finding: makeFinding(),
        triageResult: makeTriageResult(),
        verificationResult: makeVerificationResult(),
        index: 1,
        total: 1,
      }),
    );

    const resultEvent = await resultPromise;
    expect(resultEvent.payload.attempts).toBe(2);
    expect(generatePocHarnessMock).toHaveBeenCalledTimes(2);

    await bus.close();
  });
});
