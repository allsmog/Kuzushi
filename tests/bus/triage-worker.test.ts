import { afterEach, describe, expect, it, vi } from "vitest";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import type {
  TriageAgentActivityEvent,
  TriageErrorEvent,
  TriageResultEvent,
} from "../../src/bus/events.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerTriageWorker } from "../../src/bus/workers/triage-worker.js";
import type { Finding } from "../../src/scanners/types.js";
import type { KuzushiConfig } from "../../src/types.js";

const { triageFindingWithAgentMock, triageFindingsBatchMock } = vi.hoisted(() => ({
  triageFindingWithAgentMock: vi.fn(),
  triageFindingsBatchMock: vi.fn(),
}));

vi.mock("../../src/triage.js", () => ({
  triageFindingWithAgent: triageFindingWithAgentMock,
  triageSystemPromptPrefix: () => "mocked-system-prompt-prefix",
  triageFindingsBatch: triageFindingsBatchMock,
  preReadForTriage: async () => "",
  BATCH_TRIAGE_FALLBACK_RATIONALE: "Finding was not included in batch triage agent response.",
}));

function makeFinding(taskId = "semgrep"): Finding {
  return {
    taskId,
    fingerprint: "fp-1",
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: 2,
    severity: "ERROR",
    message: "test",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-79"],
    score: 54,
  };
}

function makeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    maxTriageRetries: 0,
    retryBackoffMs: 0,
    retryBackoffMultiplier: 2,
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: { semgrep: {} },
    ...overrides,
  };
}

afterEach(() => {
  triageFindingWithAgentMock.mockReset();
  triageFindingsBatchMock.mockReset();
});

describe("triage-worker", () => {
  it("publishes triage:result on success", async () => {
    const bus = new InProcessBus();
    const registry = {};
    const config = makeConfig();

    triageFindingWithAgentMock.mockResolvedValue({
      result: {
        fingerprint: "fp-1",
        verdict: "fp",
        confidence: 0.8,
        rationale: "safe",
        verificationSteps: ["check"],
        fixPatch: null,
      },
      costUsd: 0.0042,
    });

    registerTriageWorker(bus, {
      registry: registry as any,
      config,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const finding = makeFinding();
    const resultPromise = bus.waitFor<TriageResultEvent>(
      "triage:result",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("triage:finding-queued", runId, {
        context,
        finding,
        index: 1,
        total: 1,
      }),
    );

    const result = await resultPromise;
    expect(result.payload.result.verdict).toBe("fp");
    expect(result.payload.result.triageCostUsd).toBe(0.0042);
    expect(result.payload.costUsd).toBe(0.0042);
    expect(result.payload.index).toBe(1);
    expect(triageFindingWithAgentMock).toHaveBeenCalledWith(
      expect.objectContaining({
        has: expect.any(Function),
        get: expect.any(Function),
      }),
      finding,
      "/tmp/repo",
      "repo",
      "anthropic:claude-sonnet-4-6",
      undefined,
      expect.objectContaining({
        activityCallback: expect.any(Function),
      }),
      expect.any(String),
      expect.any(String),
      "mocked-system-prompt-prefix",
    );

    await bus.close();
  });

  it("publishes triage:error when triage fails", async () => {
    const bus = new InProcessBus();
    const registry = {};
    const config = makeConfig();

    triageFindingWithAgentMock.mockRejectedValue(new Error("agent failed"));

    registerTriageWorker(bus, {
      registry: registry as any,
      config,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const finding = makeFinding();
    const errorPromise = bus.waitFor<TriageErrorEvent>(
      "triage:error",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("triage:finding-queued", runId, {
        context,
        finding,
        index: 1,
        total: 1,
      }),
    );

    const errorEvent = await errorPromise;
    expect(errorEvent.payload.error).toContain("agent failed");
    expect(errorEvent.payload.costUsd).toBeUndefined();
    expect(triageFindingWithAgentMock).toHaveBeenCalledWith(
      expect.objectContaining({
        has: expect.any(Function),
        get: expect.any(Function),
      }),
      finding,
      "/tmp/repo",
      "repo",
      "anthropic:claude-sonnet-4-6",
      undefined,
      expect.objectContaining({
        activityCallback: expect.any(Function),
      }),
      expect.any(String),
      expect.any(String),
      "mocked-system-prompt-prefix",
    );

    await bus.close();
  });

  it("propagates cost on triage:error events when provided by runtime error", async () => {
    const bus = new InProcessBus();
    const registry = {};
    const config = makeConfig();

    const errorWithCost = Object.assign(new Error("agent failed"), { costUsd: 0.021 });
    triageFindingWithAgentMock.mockRejectedValue(errorWithCost);

    registerTriageWorker(bus, {
      registry: registry as any,
      config,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const finding = makeFinding();
    const errorPromise = bus.waitFor<TriageErrorEvent>(
      "triage:error",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("triage:finding-queued", runId, {
        context,
        finding,
        index: 1,
        total: 1,
      }),
    );

    const errorEvent = await errorPromise;
    expect(errorEvent.payload.error).toContain("agent failed");
    expect(errorEvent.payload.costUsd).toBe(0.021);

    await bus.close();
  });

  it("exposes task-level triage config providers when scanner plugin is missing", async () => {
    const bus = new InProcessBus();
    const registry = {
      has: () => false,
      get: () => {
        throw new Error("scanner missing");
      },
    };
    const taskRegistry = {
      has: (id: string) => id === "custom-task",
      get: () => ({
        id: "custom-task",
        triageAgentConfig: () => ({ prompt: "task triage prompt" }),
      }),
    };
    const config = makeConfig();

    triageFindingWithAgentMock.mockResolvedValue({
      result: {
        fingerprint: "fp-1",
        verdict: "needs_review",
        confidence: 0.5,
        rationale: "unknown",
        verificationSteps: ["step"],
        fixPatch: null,
      },
      costUsd: 0.001,
    });

    registerTriageWorker(bus, {
      registry: registry as any,
      taskRegistry: taskRegistry as any,
      config,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const finding = makeFinding("custom-task");
    const resultPromise = bus.waitFor<TriageResultEvent>(
      "triage:result",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("triage:finding-queued", runId, {
        context,
        finding,
        index: 1,
        total: 1,
      }),
    );

    await resultPromise;

    const provider = triageFindingWithAgentMock.mock.calls[0]?.[0];
    expect(provider?.has("custom-task")).toBe(true);
    expect(provider?.get("custom-task").triageAgentConfig(finding, "repo").prompt).toContain(
      "task triage prompt",
    );

    await bus.close();
  });

  it("publishes triage:agent-activity events from triage callback", async () => {
    const bus = new InProcessBus();
    const registry = {};
    const config = makeConfig();

    triageFindingWithAgentMock.mockImplementation(async (...args: any[]) => {
      const runtimeOptions = args[6];
      await runtimeOptions?.activityCallback?.({
        kind: "tool-start",
        toolName: "Read",
        toolInput: { file_path: "src/app.ts" },
      });
      return {
        result: {
          fingerprint: "fp-1",
          verdict: "fp",
          confidence: 0.9,
          rationale: "safe",
          verificationSteps: ["check"],
          fixPatch: null,
        },
        costUsd: 0.0025,
      };
    });

    registerTriageWorker(bus, {
      registry: registry as any,
      config,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const finding = makeFinding();
    const activityPromise = bus.waitFor<TriageAgentActivityEvent>(
      "triage:agent-activity",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("triage:finding-queued", runId, {
        context,
        finding,
        index: 1,
        total: 1,
      }),
    );

    const activity = await activityPromise;
    expect(activity.payload.kind).toBe("tool-start");
    expect(activity.payload.toolName).toBe("Read");
    expect(activity.payload.fingerprint).toBe("fp-1");

    await bus.close();
  });

  it("retries triage failures and emits triage:result after a successful retry", async () => {
    const bus = new InProcessBus();
    const registry = {};
    const config = makeConfig({
      maxTriageRetries: 2,
      retryBackoffMs: 0,
    });

    triageFindingWithAgentMock
      .mockRejectedValueOnce(new Error("rate limit"))
      .mockResolvedValueOnce({
        result: {
          fingerprint: "fp-1",
          verdict: "tp",
          confidence: 0.83,
          rationale: "confirmed",
          verificationSteps: ["trace input"],
          fixPatch: null,
        },
        costUsd: 0.01,
      });

    registerTriageWorker(bus, {
      registry: registry as any,
      config,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const resultPromise = bus.waitFor<TriageResultEvent>(
      "triage:result",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("triage:finding-queued", runId, {
        context,
        finding: makeFinding(),
        index: 1,
        total: 1,
      }),
    );

    const resultEvent = await resultPromise;
    expect(resultEvent.payload.result.verdict).toBe("tp");
    expect(resultEvent.payload.attempts).toBe(2);
    expect(triageFindingWithAgentMock).toHaveBeenCalledTimes(2);

    await bus.close();
  });

  it("requeues batch-missing findings for individual triage instead of accepting a fallback result", async () => {
    const bus = new InProcessBus();
    const registry = {};
    const config = makeConfig();

    triageFindingsBatchMock.mockResolvedValue({
      results: new Map([
        [
          "fp-1",
          {
            fingerprint: "fp-1",
            verdict: "tp",
            confidence: 0.9,
            rationale: "batch result",
            verificationSteps: ["check"],
            fixPatch: null,
          },
        ],
      ]),
      costUsd: 0.01,
      missingFingerprints: ["fp-2"],
      incomplete: true,
      recoveredByRetry: [],
    });
    triageFindingWithAgentMock.mockResolvedValue({
      result: {
        fingerprint: "fp-2",
        verdict: "fp",
        confidence: 0.7,
        rationale: "retried individually",
        verificationSteps: ["inspect"],
        fixPatch: null,
      },
      costUsd: 0.005,
    });

    registerTriageWorker(bus, {
      registry: registry as any,
      config,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const retriedResultPromise = bus.waitFor<TriageResultEvent>(
      "triage:result",
      (event) => event.meta.runId === runId && event.payload.finding.fingerprint === "fp-2",
    );

    await bus.publish(
      createEvent("triage:batch-queued", runId, {
        context,
        findings: [makeFinding(), { ...makeFinding(), fingerprint: "fp-2" }],
        index: 1,
        total: 2,
      } as any),
    );

    const retriedResult = await retriedResultPromise;
    expect(retriedResult.payload.finding.fingerprint).toBe("fp-2");
    expect(retriedResult.payload.result.rationale).toBe("retried individually");
    expect(triageFindingsBatchMock).toHaveBeenCalledTimes(1);
    expect(triageFindingWithAgentMock).toHaveBeenCalledTimes(1);

    await bus.close();
  });
});
