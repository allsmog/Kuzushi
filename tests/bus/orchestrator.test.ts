import { describe, expect, it } from "vitest";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import { TaskRegistry } from "../../src/agents/registry.js";
import type { AgentTask } from "../../src/agents/types.js";
import { SELECTABLE_TASK_IDS } from "../../src/agents/tasks/task-selector.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerOrchestrator } from "../../src/bus/orchestrator.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { registerScanWorker } from "../../src/bus/workers/scan-worker.js";
import { getScanPlanSummary } from "../../src/cli/commands/scan.js";
import type {
  PipelineCompleteEvent,
  PipelineErrorEvent,
  PocHarnessFindingQueuedEvent,
  PocHarnessStartEvent,
  ReportRequestedEvent,
  ScanStartEvent,
  StageCompleteEvent,
  TaskCompleteEvent,
  TaskStartEvent,
  TriageBatchQueuedEvent,
  TriageCompleteEvent,
  TriageFindingQueuedEvent,
  TriageQueueDepthEvent,
  TriageStartEvent,
  VerificationBatchQueuedEvent,
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
    const completePromise = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
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

  it("builds the triage queue from clustered findings instead of the pre-dedup scan list", async () => {
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

    const triageStartPromise = bus.waitFor<TriageStartEvent>(
      "triage:start",
      (event) => event.meta.runId === runId,
    );
    const batchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: { ...makeScanOpts(), fresh: true },
      }),
    );

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: {
          ...makeFinding("fp-semgrep", 70),
          filePath: "src/db.ts",
          startLine: 44,
          cwe: ["CWE-89"],
        },
        scannerId: "semgrep",
      }),
    );
    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: {
          ...makeFinding("fp-codeql", 90),
          scanner: "codeql",
          ruleId: "js/sql-injection",
          filePath: "src/db.ts",
          startLine: 44,
          cwe: ["CWE-89"],
        },
        scannerId: "codeql",
      }),
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 2,
      }),
    );

    const triageStart = await triageStartPromise;
    const batchQueued = await batchQueuedPromise;
    expect(triageStart.payload.findingCount).toBe(1);
    expect(batchQueued.payload.findings).toHaveLength(1);
    expect(batchQueued.payload.findings[0].fingerprint).toBe("fp-codeql");

    await bus.close();
    db.close();
  });

  it("queues high-confidence agentic findings for normal triage instead of auto-classifying them", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const config: KuzushiConfig = {
      ...makeConfig(),
      skipTriageForHighConfidenceAgentic: true,
    };

    const registry = {
      resolveEnabled: () => ["semgrep", "agentic"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

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
    const batchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
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

    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: {
          ...makeFinding("fp-semgrep", 50),
          scanner: "semgrep",
        },
        scannerId: "semgrep",
      }),
    );
    await bus.publish(
      createEvent("scan:finding", runId, {
        context,
        finding: {
          ...makeFinding("fp-agentic", 80),
          scanner: "agentic",
          ruleId: "agentic.sql-injection",
          scannerConfidence: "HIGH",
        },
        scannerId: "agentic",
      }),
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 2,
      }),
    );

    const triageStart = await triageStartPromise;
    const batchQueued = await batchQueuedPromise;

    expect(triageStart.payload.findingCount).toBe(2);
    expect(batchQueued.payload.findings.map((finding) => finding.fingerprint)).toEqual([
      "fp-agentic",
      "fp-semgrep",
    ]);

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

    const verificationQueued: Array<{ finding: any; triageResult: any; index: number; total: number }> = [];
    bus.subscribe<VerificationFindingQueuedEvent>("verification:finding-queued", (event) => {
      if (event.meta.runId === runId) {
        verificationQueued.push(event.payload);
      }
    });
    bus.subscribe<VerificationBatchQueuedEvent>("verification:batch-queued", (event) => {
      if (event.meta.runId === runId) {
        for (const item of event.payload.items) {
          verificationQueued.push(item);
        }
      }
    });

    const verificationStartPromise = bus.waitFor<VerificationStartEvent>(
      "verification:start",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 3,
      }),
    );

    const verificationStart = await verificationStartPromise;
    expect(verificationStart.payload.findingCount).toBe(2);
    // Wait briefly for batch/individual dispatch to complete
    await new Promise((r) => setTimeout(r, 50));
    expect(verificationQueued).toHaveLength(2);

    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );
    const completePromise = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    );

    for (const queued of verificationQueued) {
      await bus.publish(
        createEvent("verification:result", runId, {
          context,
          finding: queued.finding,
          triageResult: queued.triageResult,
          result: {
            fingerprint: queued.finding.fingerprint,
            exploitable: false,
            pocPayload: null,
            pocDescription: "not exploitable",
            attackVector: null,
            preconditions: [],
            confidence: 0.8,
          },
          index: queued.index,
          total: queued.total,
        }),
      );
    }

    await reportRequestedPromise;
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
    expect(run?.findingsJson).toBeDefined();
    const persistedCheckpoint = JSON.parse(run!.findingsJson!);
    expect(persistedCheckpoint).toHaveLength(2);
    expect(persistedCheckpoint.map((finding: Finding) => finding.fingerprint)).toEqual([
      "fp-first",
      "fp-second",
    ]);
    expect(persistedCheckpoint.every((finding: Finding) => typeof finding.adjustedScore === "number")).toBe(true);

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

  it("threads context-enricher output into triage queue events when enabled", async () => {
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
        return [makeFinding("fp-enriched", 80)];
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
          authPatterns: [],
          sanitizationLibs: [],
          ormOrDb: [],
          entryPoints: ["src/pages/api/*"],
        };
      },
    };

    const enrichmentTask: AgentTask<ScanOpts, unknown> = {
      id: "context-enricher",
      displayName: "Context Enricher",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        return {
          customMiddleware: [{ name: "auth", filePath: "src/middleware/auth.ts", purpose: "auth gate" }],
          customSanitizers: [],
          trustBoundaries: [],
          dataClassifications: [],
          architecturalNotes: ["Background jobs process user uploads."],
        };
      },
    };

    taskRegistry.register(semgrepTask);
    taskRegistry.register(contextTask);
    taskRegistry.register(enrichmentTask);

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
        config: {
          ...makeConfig(),
          enableContextEnrichment: true,
        },
        scanOpts: makeScanOpts(),
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;
    expect(triageBatchQueued.payload.enrichedContext).toMatchObject({
      customMiddleware: [
        { name: "auth", filePath: "src/middleware/auth.ts" },
      ],
      architecturalNotes: ["Background jobs process user uploads."],
    });

    await bus.close();
    db.close();
  });

  it("normalizes dynamic task selections into runnable task ids", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return {
          languages: ["TypeScript"],
          frameworks: [],
          authPatterns: [],
          sanitizationLibs: [],
          ormOrDb: [],
          entryPoints: [],
        };
      },
    };
    const selectorTask: AgentTask<ScanOpts, unknown> = {
      id: "task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        return {
          recommendedTasks: ["dangerous-api", "secrets", "security-misconfig"],
          reasoning: {},
        };
      },
    };
    const codeConfigTask: AgentTask<ScanOpts, Finding[]> = {
      id: "code-config-detect",
      displayName: "Code & Config",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-dynamic", 91)];
      },
    };
    const secretsCryptoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(selectorTask);
    taskRegistry.register(codeConfigTask);
    taskRegistry.register(secretsCryptoTask);

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableDynamicTaskSelection: true,
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;
    expect(taskStarts).toContain("task-selector");
    expect(taskStarts).toContain("code-config-detect");
    expect(taskStarts).toContain("secrets-crypto-detect");
    expect(triageBatchQueued.payload.findings.map((finding) => finding.fingerprint)).toEqual(["fp-dynamic"]);

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

  it("dynamic selection excludes selectable tasks from initial candidate set", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return {
          languages: ["Go"],
          frameworks: [],
          authPatterns: [],
          sanitizationLibs: [],
          ormOrDb: [],
          entryPoints: [],
        };
      },
    };
    const selectorTask: AgentTask<ScanOpts, unknown> = {
      id: "task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        return {
          recommendedTasks: ["secrets", "ssrf"],
          reasoning: {},
        };
      },
    };
    // Register two selectable tasks — only the recommended ones should run
    const secretsCryptoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-secrets", 80)];
      },
    };
    const ssrfTask: AgentTask<ScanOpts, Finding[]> = {
      id: "ssrf-detect",
      displayName: "SSRF",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-ssrf", 70)];
      },
    };
    const protoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "prototype-pollution-detect",
      displayName: "Prototype Pollution",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-proto", 60)];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(selectorTask);
    taskRegistry.register(secretsCryptoTask);
    taskRegistry.register(ssrfTask);
    taskRegistry.register(protoTask);

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableDynamicTaskSelection: true,
          enabledTasks: [],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Only task-selector-recommended tasks should have run
    expect(taskStarts).toContain("task-selector");
    expect(taskStarts).toContain("secrets-crypto-detect");
    expect(taskStarts).toContain("ssrf-detect");
    // prototype-pollution-detect was NOT recommended, so it should NOT run
    expect(taskStarts).not.toContain("prototype-pollution-detect");
    // Findings should come from the two recommended tasks only
    const fps = triageBatchQueued.payload.findings.map((f) => f.fingerprint);
    expect(fps).toContain("fp-secrets");
    expect(fps).toContain("fp-ssrf");
    expect(fps).not.toContain("fp-proto");

    await bus.close();
    db.close();
  });

  it("falls back to all selectable tasks when task-selector fails", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return { languages: ["Go"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] };
      },
    };
    const failingSelectorTask: AgentTask<ScanOpts, unknown> = {
      id: "task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        throw new Error("task-selector crash");
      },
    };
    const secretsCryptoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-fallback-secrets", 80)];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(failingSelectorTask);
    taskRegistry.register(secretsCryptoTask);

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableDynamicTaskSelection: true,
          enabledTasks: [],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Despite task-selector failing, the fallback should enable selectable tasks
    expect(taskStarts).toContain("secrets-crypto-detect");
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toContain("fp-fallback-secrets");

    await bus.close();
    db.close();
  });

  it("preserves explicit enabledTasks when dynamic selection is active", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return { languages: ["TypeScript"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] };
      },
    };
    const selectorTask: AgentTask<ScanOpts, unknown> = {
      id: "task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        return {
          recommendedTasks: ["ssrf"],
          reasoning: {},
        };
      },
    };
    const secretsCryptoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-explicit-secrets", 80)];
      },
    };
    const ssrfTask: AgentTask<ScanOpts, Finding[]> = {
      id: "ssrf-detect",
      displayName: "SSRF",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-dynamic-ssrf", 70)];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(selectorTask);
    taskRegistry.register(secretsCryptoTask);
    taskRegistry.register(ssrfTask);

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    // User explicitly sets enabledTasks — dynamic selection adds to it, doesn't replace
    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableDynamicTaskSelection: true,
          enabledTasks: ["secrets-crypto-detect"],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Explicit task should always run
    expect(taskStarts).toContain("secrets-crypto-detect");
    // task-selector should run even with explicit enabledTasks
    expect(taskStarts).toContain("task-selector");
    // Dynamic ssrf-detect added by task-selector
    expect(taskStarts).toContain("ssrf-detect");
    const fps = triageBatchQueued.payload.findings.map((f) => f.fingerprint);
    expect(fps).toContain("fp-explicit-secrets");
    expect(fps).toContain("fp-dynamic-ssrf");

    await bus.close();
    db.close();
  });

  it("runs only explicit enabled tasks when taskMode is explicit", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    const taskRegistry = new TaskRegistry();
    const scannerTask: AgentTask<ScanOpts, Finding[]> = {
      id: "semgrep",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-semgrep-explicit", 90)];
      },
    };
    const secretsTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-explicit-secrets-only", 80)];
      },
    };
    const protoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "prototype-pollution-detect",
      displayName: "Prototype Pollution",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-explicit-proto", 60)];
      },
    };

    taskRegistry.register(scannerTask);
    taskRegistry.register(secretsTask);
    taskRegistry.register(protoTask);

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
    const config = {
      ...makeConfig(),
      taskMode: "explicit" as const,
      enableDynamicTaskSelection: false,
      enabledTasks: ["secrets-crypto-detect"],
    };
    const scanOpts = { ...makeScanOpts(), scanners: ["semgrep"] };

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts,
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;
    const scanPlan = getScanPlanSummary(config, scanOpts, taskRegistry);
    const nonScannerTaskStarts = taskStarts.filter((id) => id !== "semgrep");

    expect(taskStarts).toContain("semgrep");
    expect(taskStarts).toContain("secrets-crypto-detect");
    expect(taskStarts).not.toContain("prototype-pollution-detect");
    expect(scanPlan.taskMode).toBe("explicit");
    expect(scanPlan.resolvedTaskIds).toEqual(nonScannerTaskStarts);
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint).sort()).toEqual([
      "fp-explicit-secrets-only",
      "fp-semgrep-explicit",
    ]);

    await bus.close();
    db.close();
  });

  it("runs only scanner tasks when taskMode is scanners-only", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    const taskRegistry = new TaskRegistry();
    const scannerTask: AgentTask<ScanOpts, Finding[]> = {
      id: "semgrep",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-scanners-only", 95)];
      },
    };
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return {};
      },
    };
    const detectorTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-should-not-run", 80)];
      },
    };

    taskRegistry.register(scannerTask);
    taskRegistry.register(contextTask);
    taskRegistry.register(detectorTask);

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
    const config = {
      ...makeConfig(),
      taskMode: "scanners-only" as const,
      enableDynamicTaskSelection: true,
      enabledTasks: ["secrets-crypto-detect"],
    };
    const scanOpts = { ...makeScanOpts(), scanners: ["semgrep"] };

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts,
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;
    const scanPlan = getScanPlanSummary(config, scanOpts, taskRegistry);
    const nonScannerTaskStarts = taskStarts.filter((id) => id !== "semgrep");

    expect(taskStarts).toEqual(["semgrep"]);
    expect(scanPlan.taskMode).toBe("scanners-only");
    expect(scanPlan.resolvedTaskIds).toEqual(nonScannerTaskStarts);
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toEqual([
      "fp-scanners-only",
    ]);

    await bus.close();
    db.close();
  });

  it("runs all tasks when taskMode is compat and dynamic selection is disabled", { timeout: 15_000 }, async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return { languages: ["Go"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] };
      },
    };
    const selectorTask: AgentTask<ScanOpts, unknown> = {
      id: "task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        return { recommendedTasks: ["secrets"], reasoning: {} };
      },
    };
    const secretsCryptoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [];
      },
    };
    const protoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "prototype-pollution-detect",
      displayName: "Prototype Pollution",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-proto-compat", 60)];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(selectorTask);
    taskRegistry.register(secretsCryptoTask);
    taskRegistry.register(protoTask);

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    // Dynamic selection disabled — all tasks should run
    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          taskMode: "compat",
          enableDynamicTaskSelection: false,
          enabledTasks: [],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Both selectable tasks ran — no filtering when dynamic selection is disabled
    expect(taskStarts).toContain("secrets-crypto-detect");
    expect(taskStarts).toContain("prototype-pollution-detect");
    const scanPlan = getScanPlanSummary({
      ...makeConfig(),
      taskMode: "compat",
      enableDynamicTaskSelection: false,
      enabledTasks: [],
    }, { ...makeScanOpts(), scanners: [] }, taskRegistry);
    expect([...scanPlan.resolvedTaskIds].sort()).toEqual(
      [...taskStarts].sort(),
    );
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toContain("fp-proto-compat");

    await bus.close();
    db.close();
  });

  it("enabledTasks ['*'] with dynamic selection runs all tasks without filtering", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return { languages: ["Go"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] };
      },
    };
    const selectorTask: AgentTask<ScanOpts, unknown> = {
      id: "task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        // Should not matter — ["*"] bypasses dynamic filtering
        return { recommendedTasks: ["secrets"], reasoning: {} };
      },
    };
    const secretsCryptoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-star-secrets", 80)];
      },
    };
    const protoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "prototype-pollution-detect",
      displayName: "Prototype Pollution",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-star-proto", 60)];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(selectorTask);
    taskRegistry.register(secretsCryptoTask);
    taskRegistry.register(protoTask);

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableDynamicTaskSelection: true,
          enabledTasks: ["*"],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Both selectable tasks run — ["*"] means run everything, no filtering
    expect(taskStarts).toContain("secrets-crypto-detect");
    expect(taskStarts).toContain("prototype-pollution-detect");
    const fps = triageBatchQueued.payload.findings.map((f) => f.fingerprint);
    expect(fps).toContain("fp-star-secrets");
    expect(fps).toContain("fp-star-proto");

    await bus.close();
    db.close();
  });

  it("falls back to all selectable tasks when task-selector returns empty recommendations", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return { languages: ["Go"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] };
      },
    };
    const emptySelectorTask: AgentTask<ScanOpts, unknown> = {
      id: "task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        return { recommendedTasks: [], reasoning: {} };
      },
    };
    const secretsCryptoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-empty-fallback", 80)];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(emptySelectorTask);
    taskRegistry.register(secretsCryptoTask);

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableDynamicTaskSelection: true,
          enabledTasks: [],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Despite empty recommendations, fallback should enable all selectable tasks
    expect(taskStarts).toContain("secrets-crypto-detect");
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toContain("fp-empty-fallback");

    await bus.close();
    db.close();
  });

  it("threat-model-randori does not run when not recommended by task-selector", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return { languages: ["Go"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] };
      },
    };
    const selectorTask: AgentTask<ScanOpts, unknown> = {
      id: "task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        // Only recommend secrets — NOT stride or pasta
        return { recommendedTasks: ["secrets"], reasoning: {} };
      },
    };
    const secretsCryptoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-secrets-only", 80)];
      },
    };
    const randoriTask: AgentTask<ScanOpts, Finding[]> = {
      id: "threat-model-randori",
      displayName: "Randori PASTA Threat Model",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-randori", 70)];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(selectorTask);
    taskRegistry.register(secretsCryptoTask);
    taskRegistry.register(randoriTask);

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableDynamicTaskSelection: true,
          enabledTasks: [],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Randori should not run — it is selectable and was not recommended
    expect(taskStarts).not.toContain("threat-model-randori");
    // Only secrets should have produced findings
    const fps = triageBatchQueued.payload.findings.map((f) => f.fingerprint);
    expect(fps).toContain("fp-secrets-only");
    expect(fps).not.toContain("fp-randori");

    await bus.close();
    db.close();
  });

  it("auto-enables Randori threat model for threat-aware detectors", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    let ssrfUpstream: Map<string, unknown> | undefined;

    taskRegistry.register({
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return {
          repoContext: { languages: ["TypeScript"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] },
          fileIndex: { tree: [], totalFiles: 0, truncated: false, patternMatches: {} },
        };
      },
    });
    taskRegistry.register({
      id: "threat-model-randori",
      displayName: "Randori PASTA Threat Model",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        return {
          document: {
            version: "1.0",
            dfd: { elements: [], trustBoundaries: [] },
            threats: [],
            summary: {
              total: 0,
              bySeverity: {},
              byCategory: {
                spoofing: 0,
                tampering: 0,
                repudiation: 0,
                "information-disclosure": 0,
                "denial-of-service": 0,
                "elevation-of-privilege": 0,
              },
            },
          },
          findings: [],
        };
      },
    });
    taskRegistry.register({
      id: "ssrf-detect",
      displayName: "SSRF Detector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run(_input, context) {
        ssrfUpstream = new Map(context.upstreamOutputs);
        return { findings: ["ssrf"] };
      },
    });

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );
    const completePromise = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enabledTasks: ["ssrf-detect"],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    await reportRequestedPromise;
    await bus.publish(
      createEvent("report:complete", runId, {
        context,
      }),
    );
    await completePromise;

    expect(taskStarts).toContain("threat-model-randori");
    expect(taskStarts.indexOf("threat-model-randori")).toBeLessThan(taskStarts.indexOf("ssrf-detect"));
    expect(ssrfUpstream?.has("threat-model-randori")).toBe(true);

    await bus.close();
    db.close();
  });

  it("does not auto-inject Randori for non-threat-aware detector runs", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    taskRegistry.register({
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return {
          repoContext: { languages: ["TypeScript"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] },
          fileIndex: { tree: [], totalFiles: 0, truncated: false, patternMatches: {} },
        };
      },
    });
    taskRegistry.register({
      id: "threat-model-randori",
      displayName: "Randori PASTA Threat Model",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        return {};
      },
    });
    // Use diff-review as a non-threat-aware task (not in THREAT_AWARE_DETECTOR_TASK_IDS)
    taskRegistry.register({
      id: "diff-review",
      displayName: "Diff Review",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        return {};
      },
    });

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );
    const completePromise = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enabledTasks: ["diff-review"],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    await reportRequestedPromise;
    await bus.publish(
      createEvent("report:complete", runId, {
        context,
      }),
    );
    await completePromise;

    expect(taskStarts).toContain("diff-review");
    expect(taskStarts).not.toContain("threat-model-randori");

    await bus.close();
    db.close();
  });

  it("does not re-schedule failed task-selector after fallback fires", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return { languages: ["Go"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] };
      },
    };
    const failingSelectorTask: AgentTask<ScanOpts, unknown> = {
      id: "task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        throw new Error("task-selector crash");
      },
    };
    const secretsCryptoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-no-resched", 80)];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(failingSelectorTask);
    taskRegistry.register(secretsCryptoTask);

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableDynamicTaskSelection: true,
          enabledTasks: [],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    await triageBatchQueuedPromise;

    // task-selector should be started exactly once — not re-scheduled after failure
    expect(taskStarts.filter((id) => id === "task-selector")).toHaveLength(1);
    // Fallback should still fire and run selectable tasks
    expect(taskStarts).toContain("secrets-crypto-detect");

    await bus.close();
    db.close();
  });

  it("fallback fires when only recommended selectable task fails", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return { languages: ["Go"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] };
      },
    };
    const selectorTask: AgentTask<ScanOpts, unknown> = {
      id: "task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        // Recommend only the task that will fail
        return { recommendedTasks: ["secrets"], reasoning: {} };
      },
    };
    // Selectable task that will fail — use "custom" outputKind so the fatal
    // "all findings producers failed" abort doesn't fire (we're testing the
    // hasSelectableTasks fallback guard, not the fatal abort path).
    const failingSecretsTask: AgentTask<ScanOpts, unknown> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        throw new Error("secrets-crypto crash");
      },
    };
    // This selectable task should be added by fallback
    const ssrfTask: AgentTask<ScanOpts, Finding[]> = {
      id: "ssrf-detect",
      displayName: "SSRF",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-fallback-ssrf", 70)];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(selectorTask);
    taskRegistry.register(failingSecretsTask);
    taskRegistry.register(ssrfTask);

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableDynamicTaskSelection: true,
          enabledTasks: [],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // secrets-crypto-detect failed, so fallback should add other selectable tasks
    expect(taskStarts).toContain("ssrf-detect");
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toContain("fp-fallback-ssrf");

    await bus.close();
    db.close();
  });

  it("does not fatally abort when condition-skipped findings task is in a stage with a failing non-findings task", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => ["findings-task", "meta-task"],
    };

    const taskRegistry = new TaskRegistry();

    const findingsTask: AgentTask<ScanOpts, Finding[]> = {
      id: "findings-task",
      displayName: "Findings Task",
      outputKind: "findings",
      dependsOn: [],
      condition: () => false, // intentionally skipped
      async run() {
        return [makeFinding("fp-should-not-run", 80)];
      },
    };

    const metaTask: AgentTask<ScanOpts, unknown> = {
      id: "meta-task",
      displayName: "Meta Task",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        throw new Error("meta-task crash");
      },
    };

    taskRegistry.register(findingsTask);
    taskRegistry.register(metaTask);

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

    // Collect fatal errors
    const fatalErrors: PipelineErrorEvent[] = [];
    bus.subscribe<PipelineErrorEvent>("pipeline:error", (event) => {
      if (event.meta.runId === runId && event.payload.fatal) {
        fatalErrors.push(event);
      }
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

    // Stage should complete — not fatally abort, because the findings task was
    // intentionally skipped (condition=false), not a failed findings producer.
    await stageCompletePromise;
    expect(fatalErrors).toHaveLength(0);

    await bus.close();
    db.close();
  });

  it("keeps context-gatherer when enableContextGathering is false and dynamic selection is active", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const registry = {
      resolveEnabled: () => [],
    };

    const taskRegistry = new TaskRegistry();
    const contextTask: AgentTask<ScanOpts, unknown> = {
      id: "context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return { languages: ["Go"], frameworks: [], authPatterns: [], sanitizationLibs: [], ormOrDb: [], entryPoints: [] };
      },
    };
    const selectorTask: AgentTask<ScanOpts, unknown> = {
      id: "task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context-gatherer"],
      async run() {
        return { recommendedTasks: ["secrets"], reasoning: {} };
      },
    };
    const secretsCryptoTask: AgentTask<ScanOpts, Finding[]> = {
      id: "secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context-gatherer"],
      async run() {
        return [makeFinding("fp-ctx-kept", 80)];
      },
    };

    taskRegistry.register(contextTask);
    taskRegistry.register(selectorTask);
    taskRegistry.register(secretsCryptoTask);

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

    const taskStarts: string[] = [];
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId) {
        taskStarts.push(event.payload.taskId);
      }
    });

    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    // enableContextGathering: false BUT enableDynamicTaskSelection: true —
    // context-gatherer should be kept because task-selector depends on it
    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableContextGathering: false,
          enableDynamicTaskSelection: true,
          enabledTasks: [],
        },
        scanOpts: { ...makeScanOpts(), scanners: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Pipeline should complete — context-gatherer kept despite enableContextGathering: false
    expect(taskStarts).toContain("context-gatherer");
    expect(taskStarts).toContain("task-selector");
    expect(taskStarts).toContain("secrets-crypto-detect");
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toContain("fp-ctx-kept");

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

  it("ranks verification candidates by score descending, then triage confidence", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const config: KuzushiConfig = {
      ...makeConfig(),
      verify: true,
      verifyConcurrency: 1,
      triageConcurrency: 3,
    };

    const registry = {
      resolveEnabled: () => ["semgrep"],
    };

    registerOrchestrator(bus, { registry: registry as any, db });

    // Create findings with different scores
    const findingHigh = makeFinding("fp-high-score", 90);
    const findingMid = makeFinding("fp-mid-score", 60);
    const findingLow = makeFinding("fp-low-score", 30);
    // Give mid-score finding a taintPath to test tiebreaking
    findingMid.taintPath = [{ filePath: "a.ts", line: 1, message: "source" }];

    const confidenceMap: Record<string, number> = {
      "fp-high-score": 0.7,
      "fp-mid-score": 0.9,
      "fp-low-score": 0.8,
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

    // Publish findings in non-score order
    for (const f of [findingMid, findingLow, findingHigh]) {
      await bus.publish(
        createEvent("scan:finding", runId, {
          context,
          finding: f,
          scannerId: "semgrep",
        }),
      );
    }

    const verificationQueued: Array<{ finding: any; index: number }> = [];
    bus.subscribe<VerificationFindingQueuedEvent>("verification:finding-queued", (event) => {
      if (event.meta.runId === runId) {
        verificationQueued.push({ finding: event.payload.finding, index: event.payload.index });
      }
    });
    bus.subscribe<VerificationBatchQueuedEvent>("verification:batch-queued", (event) => {
      if (event.meta.runId === runId) {
        for (const item of event.payload.items) {
          verificationQueued.push({ finding: item.finding, index: item.index });
        }
      }
    });

    const verificationStartPromise = bus.waitFor<VerificationStartEvent>(
      "verification:start",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 3,
      }),
    );

    await verificationStartPromise;
    await new Promise((r) => setTimeout(r, 50));

    // Verification queue should be ordered: high-score (90), mid-score (60), low-score (30)
    expect(verificationQueued.length).toBeGreaterThanOrEqual(1);
    const queuedFingerprints = verificationQueued.map(q => q.finding.fingerprint);
    expect(queuedFingerprints[0]).toBe("fp-high-score");
    if (queuedFingerprints.length >= 2) {
      expect(queuedFingerprints[1]).toBe("fp-mid-score");
    }
    if (queuedFingerprints.length >= 3) {
      expect(queuedFingerprints[2]).toBe("fp-low-score");
    }

    await bus.close();
    db.close();
  });

});
