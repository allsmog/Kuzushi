import { describe, expect, it } from "vitest";
import { TaskRegistry } from "../../src/agents/registry.js";
import type { AgentTask } from "../../src/agents/types.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerOrchestrator } from "../../src/bus/orchestrator.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { registerScanWorker } from "../../src/bus/workers/scan-worker.js";
import type {
  PipelineCompleteEvent,
  PipelineErrorEvent,
  PocHarnessFindingQueuedEvent,
  PocHarnessStartEvent,
  ReportRequestedEvent,
  ScanStartEvent,
  StageCompleteEvent,
  TaskStartEvent,
  TriageBatchQueuedEvent,
  TriageCompleteEvent,
  TriageFindingQueuedEvent,
  TriageQueueDepthEvent,
  TriageStartEvent,
  VerificationCompleteEvent,
  VerificationFindingQueuedEvent,
  VerificationStartEvent,
} from "../../src/bus/events.js";
import {
  createRun,
  getRun,
  initDb,
  updatePocHarnessResult,
  updateVerificationResult,
  updateRunFindings,
  updateRunStatus,
  upsertFinding,
} from "../../src/store.js";
import type { Finding } from "../../src/scanners/types.js";
import type { KuzushiConfig, ScanOpts, TriageResult } from "../../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    enabledTasks: [],
    scanners: ["semgrep"],
    severity: ["ERROR", "WARNING"],
    excludePatterns: ["node_modules"],
    scannerConfig: {
      semgrep: {},
    },
  };
}

function makeFinding(fp: string, score: number): Finding {
  return {
    scanner: "semgrep",
    fingerprint: fp,
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: score,
    severity: "ERROR",
    message: "test",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-79"],
    score,
  };
}

function makeResult(fp: string): TriageResult {
  return {
    fingerprint: fp,
    verdict: "tp",
    confidence: 0.9,
    rationale: "confirmed",
    verificationSteps: ["step"],
    fixPatch: null,
    triageCostUsd: 0,
  };
}

function makeScanOpts(): ScanOpts {
  return {
    severity: ["ERROR"],
    excludePatterns: ["node_modules"],
    scanners: ["semgrep"],
    fresh: false,
  };
}

function registerMockBatchTriageWorker(
  bus: InProcessBus,
  resultFn: (finding: Finding) => TriageResult,
): void {
  bus.subscribe<TriageBatchQueuedEvent>("triage:batch-queued", async (event) => {
    const { context, findings, total } = event.payload;
    const runId = event.meta.runId;
    for (const [idx, finding] of findings.entries()) {
      await bus.publish(
        createEvent("triage:result", runId, {
          context,
          finding,
          result: resultFn(finding),
          costUsd: 0.01,
          attempts: 1,
          index: idx + 1,
          total,
        }),
      );
    }
  });
}

describe("PipelineOrchestrator", () => {
  it("starts scans from pipeline:start", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const scanStartPromise = bus.waitFor<ScanStartEvent>(
      "scan:start",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
      }),
    );

    const scanStart = await scanStartPromise;
    expect(scanStart.payload.scanners).toEqual(["semgrep"]);

    await bus.close();
    db.close();
  });

  it("filters already-triaged findings and completes the pipeline", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    const existing = makeFinding("fp-skip", 50);
    upsertFinding(db, existing, makeResult("fp-skip"), "repo", "HEAD");

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    registerMockBatchTriageWorker(bus, (finding) => makeResult(finding.fingerprint));

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
      }),
    );

    const triageStartPromise = bus.waitFor<TriageStartEvent>(
      "triage:start",
      (event) => event.meta.runId === runId,
    );
    const batchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );
    const queueDepthEvents: TriageQueueDepthEvent[] = [];
    bus.subscribe<TriageQueueDepthEvent>("triage:queue-depth", (event) => {
      if (event.meta.runId === runId) {
        queueDepthEvents.push(event);
      }
    });

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: existing,
        scannerId: "semgrep",
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-triage", 60),
        scannerId: "semgrep",
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-triage", 10),
        scannerId: "semgrep",
      }),
    );

    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 3,
      }),
    );

    const triageStart = await triageStartPromise;
    expect(triageStart.payload.findingCount).toBe(1);

    const batchQueued = await batchQueuedPromise;
    expect(batchQueued.payload.findings).toHaveLength(1);
    expect(batchQueued.payload.findings[0].fingerprint).toBe("fp-triage");

    await reportRequestedPromise;

    const pipelineCompletePromise = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("report:complete", runId, {
        context,
      }),
    );

    const done = await pipelineCompletePromise;

    expect(done.payload.stats.totalFindings).toBe(2);
    expect(done.payload.stats.queuedForTriage).toBe(1);
    expect(done.payload.stats.skippedAlreadyTriaged).toBe(1);
    expect(done.payload.stats.triaged).toBe(1);
    expect(done.payload.stats.triageErrors).toBe(0);
    expect(queueDepthEvents.length).toBeGreaterThan(0);
    const finalDepth = queueDepthEvents[queueDepthEvents.length - 1];
    expect(finalDepth.payload.queued).toBe(0);
    expect(finalDepth.payload.inFlight).toBe(0);
    expect(finalDepth.payload.processed).toBe(1);
    expect(finalDepth.payload.total).toBe(1);

    await bus.close();
    db.close();
  });

  it("accumulates triage costs into triage:complete and pipeline stats", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const config = {
      ...makeConfig(),
      triageConcurrency: 2,
    };

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    const runId = generateRunId();
    createRun(db, runId, "repo", config, makeScanOpts());

    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const costMap: Record<string, number> = {
      "fp-cost-1": 0.12,
      "fp-cost-2": 0.08,
    };
    bus.subscribe<TriageBatchQueuedEvent>("triage:batch-queued", async (event) => {
      const { context: ctx, findings, total } = event.payload;
      const batchRunId = event.meta.runId;
      for (const [idx, finding] of findings.entries()) {
        const cost = costMap[finding.fingerprint] ?? 0;
        await bus.publish(
          createEvent("triage:result", batchRunId, {
            context: ctx,
            finding,
            result: {
              ...makeResult(finding.fingerprint),
              triageCostUsd: cost,
            },
            costUsd: cost,
            attempts: 1,
            index: idx + 1,
            total,
          }),
        );
      }
    });

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-cost-1", 70),
        scannerId: "semgrep",
      }),
    );
    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-cost-2", 60),
        scannerId: "semgrep",
      }),
    );

    const triageCompletePromise = bus.waitFor<TriageCompleteEvent>(
      "triage:complete",
      (event) => event.meta.runId === runId,
    );
    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 2,
      }),
    );

    const triageComplete = await triageCompletePromise;
    expect(triageComplete.payload.totalCostUsd).toBeCloseTo(0.2, 8);
    await reportRequestedPromise;

    const pipelineCompletePromise = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("report:complete", runId, {
        context,
      }),
    );

    const done = await pipelineCompletePromise;
    expect(done.payload.stats.totalCostUsd).toBeCloseTo(0.2, 8);

    const persisted = getRun(db, runId);
    expect(persisted?.totalCostUsd).toBeCloseTo(0.2, 8);
    expect(persisted?.status).toBe("complete");

    await bus.close();
    db.close();
  });

  it("skips verification queueing when scanner config disables verification", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const config: KuzushiConfig = {
      ...makeConfig(),
      verify: true,
      scannerConfig: {
        semgrep: { verify: false },
      },
    };

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    registerMockBatchTriageWorker(bus, (finding) => makeResult(finding.fingerprint));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-no-verify", 55),
        scannerId: "semgrep",
      }),
    );

    let sawVerificationQueued = false;
    let verificationStartFindingCount = -1;
    bus.subscribe<VerificationFindingQueuedEvent>("verification:finding-queued", (event) => {
      if (event.meta.runId === runId) {
        sawVerificationQueued = true;
      }
    });
    bus.subscribe<VerificationStartEvent>("verification:start", (event) => {
      if (event.meta.runId === runId) {
        verificationStartFindingCount = event.payload.findingCount;
      }
    });

    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 1,
      }),
    );

    await reportRequestedPromise;
    expect(sawVerificationQueued).toBe(false);
    expect(verificationStartFindingCount).toBe(0);

    const pipelineCompletePromise = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("report:complete", runId, {
        context,
      }),
    );

    await pipelineCompletePromise;
    await bus.close();
    db.close();
  });

  it("skips low-confidence triage results from verification queue", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const config: KuzushiConfig = {
      ...makeConfig(),
      verify: true,
      verifyConcurrency: 2,
      triageConcurrency: 3,
      verifyMinConfidence: 0.6,
    };

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    const confidenceMap: Record<string, number> = {
      "fp-low": 0.3,
      "fp-mid": 0.7,
      "fp-high": 0.9,
    };
    bus.subscribe<TriageBatchQueuedEvent>("triage:batch-queued", async (event) => {
      const { context: ctx, findings, total } = event.payload;
      const batchRunId = event.meta.runId;
      for (const [idx, finding] of findings.entries()) {
        await bus.publish(
          createEvent("triage:result", batchRunId, {
            context: ctx,
            finding,
            result: {
              ...makeResult(finding.fingerprint),
              confidence: confidenceMap[finding.fingerprint] ?? 0.9,
            },
            costUsd: 0.01,
            attempts: 1,
            index: idx + 1,
            total,
          }),
        );
      }
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-low", 70),
        scannerId: "semgrep",
      }),
    );
    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-mid", 60),
        scannerId: "semgrep",
      }),
    );
    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-high", 50),
        scannerId: "semgrep",
      }),
    );

    const verificationQueued: VerificationFindingQueuedEvent[] = [];
    bus.subscribe<VerificationFindingQueuedEvent>("verification:finding-queued", (event) => {
      if (event.meta.runId === runId) {
        verificationQueued.push(event);
      }
    });

    const verificationStartPromise = bus.waitFor<VerificationStartEvent>(
      "verification:start",
      (event) => event.meta.runId === runId,
    );
    const verificationSecondQueuedPromise = bus.waitFor<VerificationFindingQueuedEvent>(
      "verification:finding-queued",
      (event) => event.meta.runId === runId && event.payload.index === 2,
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 3,
      }),
    );

    const verificationStart = await verificationStartPromise;
    expect(verificationStart.payload.findingCount).toBe(2);
    await verificationSecondQueuedPromise;
    expect(verificationQueued).toHaveLength(2);

    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    for (const queued of verificationQueued) {
      await bus.publish(
        createEvent("verification:result", runId, {
          context,
          finding: queued.payload.finding,
          triageResult: queued.payload.triageResult,
          result: {
            fingerprint: queued.payload.finding.fingerprint,
            exploitable: false,
            pocPayload: null,
            pocDescription: "not exploitable",
            attackVector: null,
            preconditions: [],
            confidence: 0.8,
          },
          index: queued.payload.index,
          total: queued.payload.total,
        }),
      );
    }

    await reportRequestedPromise;

    const completePromise = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    );
    await bus.publish(
      createEvent("report:complete", runId, {
        context,
      }),
    );
    const complete = await completePromise;

    expect(complete.payload.stats.skippedLowConfidence).toBe(1);
    expect(complete.payload.stats.verified).toBe(2);

    await bus.close();
    db.close();
  });

  it("emits verification:complete only once even if duplicate verification results arrive", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const config: KuzushiConfig = {
      ...makeConfig(),
      verify: true,
      pocHarness: true,
    };

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    registerMockBatchTriageWorker(bus, (finding) => makeResult(finding.fingerprint));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    let verificationCompleteCount = 0;
    bus.subscribe<VerificationCompleteEvent>("verification:complete", (event) => {
      if (event.meta.runId === runId) {
        verificationCompleteCount += 1;
      }
    });

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-dup-verify", 60),
        scannerId: "semgrep",
      }),
    );

    const verificationQueuedPromise = bus.waitFor<VerificationFindingQueuedEvent>(
      "verification:finding-queued",
      (event) => event.meta.runId === runId,
    );
    const pocStartPromise = bus.waitFor<PocHarnessStartEvent>(
      "poc-harness:start",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 1,
      }),
    );

    const verificationQueued = await verificationQueuedPromise;
    const payload = {
      context,
      finding: verificationQueued.payload.finding,
      triageResult: verificationQueued.payload.triageResult,
      result: {
        fingerprint: verificationQueued.payload.finding.fingerprint,
        exploitable: true,
        pocPayload: "' OR 1=1 --",
        pocDescription: "inject",
        attackVector: "http",
        preconditions: [],
        confidence: 0.9,
      },
      index: verificationQueued.payload.index,
      total: verificationQueued.payload.total,
    };

    await bus.publish(createEvent("verification:result", runId, payload));
    await pocStartPromise;
    await bus.publish(createEvent("verification:result", runId, payload));
    await Promise.resolve();

    expect(verificationCompleteCount).toBe(1);

    await bus.close();
    db.close();
  });

  it("skips poc-harness phase when disabled", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const config: KuzushiConfig = {
      ...makeConfig(),
      verify: true,
      pocHarness: false,
    };

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    registerMockBatchTriageWorker(bus, (finding) => makeResult(finding.fingerprint));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    let sawPocHarnessStart = false;
    bus.subscribe<PocHarnessStartEvent>("poc-harness:start", (event) => {
      if (event.meta.runId === runId) {
        sawPocHarnessStart = true;
      }
    });

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-no-poc", 80),
        scannerId: "semgrep",
      }),
    );

    const verificationQueuedPromise = bus.waitFor<VerificationFindingQueuedEvent>(
      "verification:finding-queued",
      (event) => event.meta.runId === runId,
    );
    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 1,
      }),
    );

    const verificationQueued = await verificationQueuedPromise;
    await bus.publish(
      createEvent("verification:result", runId, {
        context,
        finding: verificationQueued.payload.finding,
        triageResult: verificationQueued.payload.triageResult,
        result: {
          fingerprint: verificationQueued.payload.finding.fingerprint,
          exploitable: true,
          pocPayload: "' OR 1=1 --",
          pocDescription: "inject input",
          attackVector: "http",
          preconditions: [],
          confidence: 0.9,
        },
        index: verificationQueued.payload.index,
        total: verificationQueued.payload.total,
      }),
    );

    await reportRequestedPromise;
    expect(sawPocHarnessStart).toBe(false);

    await bus.close();
    db.close();
  });

  it("skips poc-harness phase when verification finds no exploitable issues", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const config: KuzushiConfig = {
      ...makeConfig(),
      verify: true,
      pocHarness: true,
    };

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    registerMockBatchTriageWorker(bus, (finding) => makeResult(finding.fingerprint));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    let sawPocHarnessStart = false;
    bus.subscribe<PocHarnessStartEvent>("poc-harness:start", (event) => {
      if (event.meta.runId === runId) {
        sawPocHarnessStart = true;
      }
    });

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-no-exploit", 70),
        scannerId: "semgrep",
      }),
    );

    const verificationQueuedPromise = bus.waitFor<VerificationFindingQueuedEvent>(
      "verification:finding-queued",
      (event) => event.meta.runId === runId,
    );
    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 1,
      }),
    );

    const verificationQueued = await verificationQueuedPromise;
    await bus.publish(
      createEvent("verification:result", runId, {
        context,
        finding: verificationQueued.payload.finding,
        triageResult: verificationQueued.payload.triageResult,
        result: {
          fingerprint: verificationQueued.payload.finding.fingerprint,
          exploitable: false,
          pocPayload: null,
          pocDescription: "blocked by input validation",
          attackVector: null,
          preconditions: [],
          confidence: 0.8,
        },
        index: verificationQueued.payload.index,
        total: verificationQueued.payload.total,
      }),
    );

    await reportRequestedPromise;
    expect(sawPocHarnessStart).toBe(false);

    await bus.close();
    db.close();
  });

  it("waits for poc-harness completion before requesting report", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const config: KuzushiConfig = {
      ...makeConfig(),
      verify: true,
      pocHarness: true,
      pocHarnessConcurrency: 1,
    };

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    registerMockBatchTriageWorker(bus, (finding) => makeResult(finding.fingerprint));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    let sawReportRequested = false;
    bus.subscribe<ReportRequestedEvent>("report:requested", (event) => {
      if (event.meta.runId === runId) {
        sawReportRequested = true;
      }
    });

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-poc-gate", 85),
        scannerId: "semgrep",
      }),
    );

    const verificationQueuedPromise = bus.waitFor<VerificationFindingQueuedEvent>(
      "verification:finding-queued",
      (event) => event.meta.runId === runId,
    );
    const pocStartPromise = bus.waitFor<PocHarnessStartEvent>(
      "poc-harness:start",
      (event) => event.meta.runId === runId,
    );
    const pocQueuedPromise = bus.waitFor<PocHarnessFindingQueuedEvent>(
      "poc-harness:finding-queued",
      (event) => event.meta.runId === runId,
    );
    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 1,
      }),
    );

    const verificationQueued = await verificationQueuedPromise;

    await bus.publish(
      createEvent("verification:result", runId, {
        context,
        finding: verificationQueued.payload.finding,
        triageResult: verificationQueued.payload.triageResult,
        result: {
          fingerprint: verificationQueued.payload.finding.fingerprint,
          exploitable: true,
          pocPayload: "' OR 1=1 --",
          pocDescription: "inject input",
          attackVector: "http",
          preconditions: [],
          confidence: 0.95,
        },
        index: verificationQueued.payload.index,
        total: verificationQueued.payload.total,
      }),
    );

    const pocStart = await pocStartPromise;
    expect(pocStart.payload.findingCount).toBe(1);
    const pocQueued = await pocQueuedPromise;

    await Promise.resolve();
    expect(sawReportRequested).toBe(false);

    await bus.publish(
      createEvent("poc-harness:result", runId, {
        context,
        finding: pocQueued.payload.finding,
        triageResult: pocQueued.payload.triageResult,
        verificationResult: pocQueued.payload.verificationResult,
        result: {
          fingerprint: pocQueued.payload.finding.fingerprint,
          scriptPath: "/tmp/repo/.kuzushi/poc/fp.ts",
          language: "typescript",
          scriptContent: "console.log('PASS')",
          parsed: true,
          parseError: null,
          skipped: false,
          skipReason: null,
        },
        costUsd: 0.02,
        index: pocQueued.payload.index,
        total: pocQueued.payload.total,
      }),
    );

    await reportRequestedPromise;
    expect(sawReportRequested).toBe(true);

    const completePromise = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    );
    await bus.publish(
      createEvent("report:complete", runId, {
        context,
      }),
    );
    const complete = await completePromise;
    expect(complete.payload.stats.pocHarnessCostUsd).toBeCloseTo(0.02, 8);
    // totalCostUsd includes both the mock triage cost (0.01) and poc-harness cost (0.02)
    expect(complete.payload.stats.totalCostUsd).toBeCloseTo(0.03, 8);

    await bus.close();
    db.close();
  });

  it("resumes poc-harnessing runs by dispatching only pending harness generation", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const config: KuzushiConfig = {
      ...makeConfig(),
      verify: true,
      pocHarness: true,
    };

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    const resumeRunId = "resume-poc";
    createRun(db, resumeRunId, "repo", config, makeScanOpts());
    updateRunStatus(db, resumeRunId, "poc-harnessing");

    const completed = makeFinding("fp-poc-done", 80);
    const pending = makeFinding("fp-poc-pending", 70);
    updateRunFindings(db, resumeRunId, [completed, pending]);

    upsertFinding(db, completed, makeResult(completed.fingerprint), "repo", "HEAD");
    upsertFinding(db, pending, makeResult(pending.fingerprint), "repo", "HEAD");

    updateVerificationResult(db, completed.fingerprint, {
      fingerprint: completed.fingerprint,
      exploitable: true,
      pocPayload: "' OR 1=1 --",
      pocDescription: "inject",
      attackVector: "http",
      preconditions: [],
      confidence: 0.9,
      verifyCostUsd: 0.01,
    });
    updateVerificationResult(db, pending.fingerprint, {
      fingerprint: pending.fingerprint,
      exploitable: true,
      pocPayload: "' OR 1=1 --",
      pocDescription: "inject",
      attackVector: "http",
      preconditions: [],
      confidence: 0.9,
      verifyCostUsd: 0.01,
    });

    updatePocHarnessResult(db, completed.fingerprint, {
      fingerprint: completed.fingerprint,
      scriptPath: "/tmp/repo/.kuzushi/poc/fp-poc-done-cwe79.ts",
      language: "typescript",
      scriptContent: "console.log('PASS')",
      parsed: true,
      parseError: null,
      skipped: false,
      skipReason: null,
      costUsd: 0.02,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    let sawScanStart = false;
    let sawTriageStart = false;
    let sawVerificationStart = false;
    bus.subscribe<ScanStartEvent>("scan:start", (event) => {
      if (event.meta.runId === runId) {
        sawScanStart = true;
      }
    });
    bus.subscribe<TriageStartEvent>("triage:start", (event) => {
      if (event.meta.runId === runId) {
        sawTriageStart = true;
      }
    });
    bus.subscribe<VerificationStartEvent>("verification:start", (event) => {
      if (event.meta.runId === runId) {
        sawVerificationStart = true;
      }
    });

    const queuedPromise = bus.waitFor<PocHarnessFindingQueuedEvent>(
      "poc-harness:finding-queued",
      (event) => event.meta.runId === runId,
    );
    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
        resumeRunId,
      }),
    );

    const queued = await queuedPromise;
    expect(queued.payload.finding.fingerprint).toBe("fp-poc-pending");
    expect(sawScanStart).toBe(false);
    expect(sawTriageStart).toBe(false);
    expect(sawVerificationStart).toBe(false);

    await bus.publish(
      createEvent("poc-harness:result", runId, {
        context,
        finding: queued.payload.finding,
        triageResult: queued.payload.triageResult,
        verificationResult: queued.payload.verificationResult,
        result: {
          fingerprint: queued.payload.finding.fingerprint,
          scriptPath: "/tmp/repo/.kuzushi/poc/fp-poc-pending-cwe79.ts",
          language: "typescript",
          scriptContent: "console.log('PASS')",
          parsed: true,
          parseError: null,
          skipped: false,
          skipReason: null,
        },
        index: queued.payload.index,
        total: queued.payload.total,
      }),
    );

    await reportRequestedPromise;

    await bus.close();
    db.close();
  });

  it("resumes from checkpointed findings and skips scan phase", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    const resumeRunId = "resume-run";
    createRun(db, resumeRunId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, resumeRunId, "triaging");

    const alreadyTriaged = makeFinding("fp-old", 90);
    const pending = makeFinding("fp-new", 80);
    updateRunFindings(db, resumeRunId, [alreadyTriaged, pending]);
    upsertFinding(db, alreadyTriaged, makeResult(alreadyTriaged.fingerprint), "repo", "HEAD");

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    bus.subscribe<TriageBatchQueuedEvent>("triage:batch-queued", async (event) => {
      const { context: ctx, findings, total } = event.payload;
      const batchRunId = event.meta.runId;
      for (const [idx, finding] of findings.entries()) {
        await bus.publish(
          createEvent("triage:result", batchRunId, {
            context: ctx,
            finding,
            result: {
              ...makeResult(finding.fingerprint),
              triageCostUsd: 0.05,
            },
            costUsd: 0.05,
            attempts: 1,
            index: idx + 1,
            total,
          }),
        );
      }
    });

    let sawScanStart = false;
    bus.subscribe<ScanStartEvent>("scan:start", (event) => {
      if (event.meta.runId === runId) {
        sawScanStart = true;
      }
    });

    const triageStartPromise = bus.waitFor<TriageStartEvent>(
      "triage:start",
      (event) => event.meta.runId === runId,
    );
    const batchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
        resumeRunId,
      }),
    );

    const triageStart = await triageStartPromise;
    expect(triageStart.payload.findingCount).toBe(1);
    expect(sawScanStart).toBe(false);

    const batchQueued = await batchQueuedPromise;
    expect(batchQueued.payload.findings).toHaveLength(1);
    expect(batchQueued.payload.findings[0].fingerprint).toBe("fp-new");

    await reportRequestedPromise;

    const pipelineCompletePromise = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("report:complete", runId, {
        context,
      }),
    );

    const complete = await pipelineCompletePromise;
    expect(complete.payload.stats.totalFindings).toBe(2);
    expect(complete.payload.stats.queuedForTriage).toBe(1);
    expect(complete.payload.stats.skippedAlreadyTriaged).toBe(1);
    expect(complete.payload.stats.totalCostUsd).toBeCloseTo(0.05, 8);

    const resumedRun = getRun(db, resumeRunId);
    expect(resumedRun?.status).toBe("complete");
    expect(resumedRun?.totalCostUsd).toBeCloseTo(0.05, 8);

    await bus.close();
    db.close();
  });

  it("resumes scanning-stage runs by restarting scan with stored scan options", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    const resumeRunId = "resume-scan-stage";
    createRun(db, resumeRunId, "repo", makeConfig(), {
      ...makeScanOpts(),
      maxFindings: 5,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const errors: PipelineErrorEvent[] = [];
    bus.subscribe<PipelineErrorEvent>("pipeline:error", (event) => {
      if (event.meta.runId === runId && event.payload.fatal) {
        errors.push(event);
      }
    });

    const scanStartPromise = bus.waitFor<ScanStartEvent>(
      "scan:start",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: {
          ...makeScanOpts(),
          maxFindings: 99,
        },
        resumeRunId,
      }),
    );

    const scanStart = await scanStartPromise;
    expect(scanStart.payload.scanOpts.maxFindings).toBe(5);
    expect(errors).toHaveLength(0);

    await bus.close();
    db.close();
  });

  it("does not re-apply current --max to checkpoint findings during resume", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    const resumeRunId = "resume-no-rewrite";
    createRun(db, resumeRunId, "repo", makeConfig(), {
      ...makeScanOpts(),
      maxFindings: 2,
    });
    updateRunStatus(db, resumeRunId, "triaging");

    const first = makeFinding("fp-first", 100);
    const second = makeFinding("fp-second", 90);
    const checkpointFindings = [first, second];
    updateRunFindings(db, resumeRunId, checkpointFindings);

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const triageStartPromise = bus.waitFor<TriageStartEvent>(
      "triage:start",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: {
          ...makeScanOpts(),
          maxFindings: 1,
        },
        resumeRunId,
      }),
    );

    const triageStart = await triageStartPromise;
    expect(triageStart.payload.findingCount).toBe(2);

    const run = getRun(db, resumeRunId);
    expect(run?.findingsJson).toBe(JSON.stringify(checkpointFindings));

    await bus.close();
    db.close();
  });

  it("continues triage when cost checkpoint persistence fails", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    const runId = generateRunId();
    createRun(db, runId, "repo", makeConfig(), makeScanOpts());

    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: makeFinding("fp-cost-fail", 50),
        scannerId: "semgrep",
      }),
    );

    const batchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 1,
      }),
    );

    const batchQueued = await batchQueuedPromise;

    const errors: PipelineErrorEvent[] = [];
    bus.subscribe<PipelineErrorEvent>("pipeline:error", (event) => {
      if (event.meta.runId === runId && event.payload.fatal) {
        errors.push(event);
      }
    });

    db.close();

    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    const finding = batchQueued.payload.findings[0];
    await bus.publish(
      createEvent("triage:result", runId, {
        context,
        finding,
        result: {
          ...makeResult(finding.fingerprint),
          triageCostUsd: 0.11,
        },
        costUsd: 0.11,
        index: 1,
        total: batchQueued.payload.total,
      }),
    );

    await reportRequestedPromise;
    expect(errors).toHaveLength(0);

    await bus.close();
  });

  it("converts bus handler failures into fatal pipeline:error events", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    bus.subscribe("scan:start", () => {
      throw new Error("scan-start crash");
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const pipelineErrorPromise = bus.waitFor<PipelineErrorEvent>(
      "pipeline:error",
      (event) => event.meta.runId === runId && event.payload.fatal,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
      }),
    );

    const pipelineError = await pipelineErrorPromise;
    expect(pipelineError.payload.error).toContain("Bus handler failure on scan:start");
    expect(pipelineError.payload.error).toContain("scan-start crash");
    expect(pipelineError.payload.fatal).toBe(true);

    await bus.close();
    db.close();
  });

  it("threads context-gatherer output into triage queue events", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    const taskRegistry = new TaskRegistry();
    const semgrepTask: AgentTask<ScanOpts, Finding[]> = {
      id: "semgrep",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-context", 80)];
      },
    };

    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return {
          languages: ["TypeScript"],
          frameworks: ["Express"],
          authPatterns: ["JWT"],
          sanitizationLibs: ["helmet"],
          ormOrDb: ["Prisma"],
          entryPoints: ["src/pages/api/*"],
        };
      },
    };

    taskRegistry.register(semgrepTask);
    taskRegistry.register(contextTask);

    registerScanWorker(bus, {
      registry: {
        get: () => {
          throw new Error("legacy scan path should not be used in DAG mode");
        },
      } as any,
      taskRegistry,
      config: makeConfig(),
    });

    registerOrchestrator(bus, {
      registry: registry as any,
      taskRegistry,
      db,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;
    expect(triageBatchQueued.payload.repoContext).toMatchObject({
      frameworks: ["Express"],
      ormOrDb: ["Prisma"],
    });

    await bus.close();
    db.close();
  });

  it("emits fatal error when ALL tasks in a stage fail", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["fail-task-1", "fail-task-2"],
    };

    const taskRegistry = new TaskRegistry();

    const failingTask1: AgentTask<ScanOpts, Finding[]> = {
      id: "fail-task-1",
      displayName: "Fail Task 1",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        throw new Error("intentional failure 1");
      },
    };

    const failingTask2: AgentTask<ScanOpts, Finding[]> = {
      id: "fail-task-2",
      displayName: "Fail Task 2",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        throw new Error("intentional failure 2");
      },
    };

    taskRegistry.register(failingTask1);
    taskRegistry.register(failingTask2);

    registerScanWorker(bus, {
      registry: {
        get: () => {
          throw new Error("legacy scan path should not be used in DAG mode");
        },
      } as any,
      taskRegistry,
      config: makeConfig(),
    });

    registerOrchestrator(bus, {
      registry: registry as any,
      taskRegistry,
      db,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const pipelineErrorPromise = bus.waitFor<PipelineErrorEvent>(
      "pipeline:error",
      (event) => event.meta.runId === runId && event.payload.fatal,
      1000,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
      }),
    );

    const pipelineError = await pipelineErrorPromise;
    expect(pipelineError.payload.error).toContain("All tasks in stage");

    await bus.close();
    db.close();
  });

  it("continues pipeline with partial findings when one scanner fails but others succeed", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["good-scanner", "bad-scanner"],
    };

    const taskRegistry = new TaskRegistry();

    const goodScanner: AgentTask<ScanOpts, Finding[]> = {
      id: "good-scanner",
      displayName: "Good Scanner",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-good", 80)];
      },
    };

    const badScanner: AgentTask<ScanOpts, Finding[]> = {
      id: "bad-scanner",
      displayName: "Bad Scanner",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        throw new Error("scanner crashed");
      },
    };

    taskRegistry.register(goodScanner);
    taskRegistry.register(badScanner);

    registerScanWorker(bus, {
      registry: {
        get: () => {
          throw new Error("legacy scan path should not be used in DAG mode");
        },
      } as any,
      taskRegistry,
      config: makeConfig(),
    });

    registerOrchestrator(bus, {
      registry: registry as any,
      taskRegistry,
      db,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    // Collect non-fatal pipeline errors
    const nonFatalErrors: PipelineErrorEvent[] = [];
    bus.subscribe<PipelineErrorEvent>("pipeline:error", (event) => {
      if (!event.payload.fatal) nonFatalErrors.push(event);
    });

    const stageCompletePromise = bus.waitFor<StageCompleteEvent>(
      "stage:complete",
      (event) => event.meta.runId === runId,
      1000,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
      }),
    );

    // Stage should complete (not abort)
    const stageComplete = await stageCompletePromise;
    expect(stageComplete.payload.taskIds).toContain("good-scanner");
    expect(stageComplete.payload.taskIds).toContain("bad-scanner");

    // Non-fatal error should have been emitted for the bad scanner
    expect(nonFatalErrors.length).toBeGreaterThanOrEqual(1);
    expect(nonFatalErrors.some((e) => e.payload.error.includes("bad-scanner"))).toBe(true);

    await bus.close();
    db.close();
  });

  it("runs DAG stages and passes upstream outputs to dependent tasks", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    const taskRegistry = new TaskRegistry();
    let upstreamFromSemgrep: unknown = undefined;

    const semgrepTask: AgentTask<ScanOpts, Finding[]> = {
      id: "semgrep",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-semgrep", 54)];
      },
    };

    const dependentTask: AgentTask<ScanOpts, { ok: boolean }> = {
      id: "post-analysis",
      displayName: "Post Analysis",
      outputKind: "custom",
      dependsOn: ["semgrep"],
      async run(_input, context) {
        upstreamFromSemgrep = context.upstreamOutputs.get("semgrep");
        return { ok: true };
      },
    };

    taskRegistry.register(semgrepTask);
    taskRegistry.register(dependentTask);

    registerScanWorker(bus, {
      registry: {
        get: () => {
          throw new Error("legacy scan path should not be used in DAG mode");
        },
      } as any,
      taskRegistry,
      config: makeConfig(),
    });

    registerOrchestrator(bus, {
      registry: registry as any,
      taskRegistry,
      db,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const taskStartOrder: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStartOrder.push(event.payload.taskId);
      }
    });

    const stage2Done = bus.waitFor<StageCompleteEvent>(
      "stage:complete",
      (event) => event.meta.runId === runId && event.payload.stageIndex === 1,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enabledTasks: ["post-analysis"],
        },
        scanOpts: makeScanOpts(),
      }),
    );

    await stage2Done;

    expect(taskStartOrder).toEqual(["semgrep", "post-analysis"]);
    expect(Array.isArray(upstreamFromSemgrep)).toBe(true);
    expect((upstreamFromSemgrep as Finding[])[0].fingerprint).toBe("fp-semgrep");

    await bus.close();
    db.close();
  });

  it("triggers verification after batch triage produces TPs with verify enabled", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    registerMockBatchTriageWorker(bus, (finding) => ({
      ...makeResult(finding.fingerprint),
      verdict: "tp",
      confidence: 0.9,
    }));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const verificationStartPromise = bus.waitFor<VerificationStartEvent>(
      "verification:start",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          verify: true,
          verifyVerdicts: ["tp"],
        },
        scanOpts: { ...makeScanOpts(), fresh: true },
      }),
    );

    const findings = [
      makeFinding("fp-verify-1", 80),
      makeFinding("fp-verify-2", 70),
      makeFinding("fp-verify-3", 60),
    ];

    for (const finding of findings) {
      await bus.publish(
        createEvent("scan:finding", runId, {
          context,
          finding,
          scannerId: "semgrep",
        }),
      );
    }

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: findings.length,
      }),
    );

    const verificationStart = await verificationStartPromise;
    expect(verificationStart.payload.findingCount).toBe(3);

    await bus.close();
    db.close();
  });

  it("keeps context-gatherer when enableContextGathering is false but tasks depend on it", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["dependent-task"],
    };

    const taskRegistry = new TaskRegistry();

    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return { languages: ["TypeScript"] };
      },
    };

    const dependentTask: AgentTask<ScanOpts, Finding[]> = {
      id: "dependent-task",
      displayName: "Dependent Task",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-dep", 80)];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(dependentTask);

    registerScanWorker(bus, {
      registry: {
        get: () => {
          throw new Error("legacy scan path should not be used in DAG mode");
        },
      } as any,
      taskRegistry,
      config: makeConfig(),
    });

    registerOrchestrator(bus, {
      registry: registry as any,
      taskRegistry,
      db,
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const config = { ...makeConfig(), enableContextGathering: false, enabledTasks: ["dependent-task"] };

    // Pipeline should NOT crash — context-gatherer kept because dependent-task needs it
    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;
    expect(triageBatchQueued.payload.findings).toHaveLength(1);

    await bus.close();
    db.close();
  });

});
