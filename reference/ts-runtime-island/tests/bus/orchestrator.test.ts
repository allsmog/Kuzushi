import type Database from "better-sqlite3";
import { describe, expect, it } from "vitest";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import type { DagNodeImpl } from "../../src/agents/types.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import type {
  PipelineCompleteEvent,
  PipelineErrorEvent,
  PocHarnessFindingQueuedEvent,
  PocHarnessStartEvent,
  ReportRequestedEvent,
  StageCompleteEvent,
  TaskStartEvent,
  TriageBatchQueuedEvent,
  TriageCompleteEvent,
  TriageQueueDepthEvent,
  TriageStartEvent,
  VerificationBatchQueuedEvent,
  VerificationCompleteEvent,
  VerificationFindingQueuedEvent,
  VerificationStartEvent,
} from "../../src/bus/events.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import type { OrchestratorDeps } from "../../src/bus/orchestrator/types.js";
import { registerOrchestrator } from "../../src/bus/orchestrator.js";
import { registerScanWorker } from "../../src/bus/workers/scan-worker.js";
import { registerStoreWorker } from "../../src/bus/workers/store-worker.js";
import { getScanPlanSummary } from "../../src/cli/commands/scan.js";
import { DagRegistry } from "../../src/modules/dag-registry.js";
import type { Finding } from "../../src/scanners/types.js";
import {
  createRun,
  getRun,
  initDb,
  updatePocHarnessResult,
  updateRunContext,
  updateRunFindings,
  updateRunStatus,
  updateVerificationResult,
  upsertFinding,
} from "../../src/store.js";
import type { KuzushiConfig, ScanOpts, TriageResult } from "../../src/types.js";

function makeDeps(db: Database.Database, dagRegistry?: DagRegistry): OrchestratorDeps {
  return { dagRegistry: dagRegistry ?? new DagRegistry(), db, runtime: {} as AgentRuntime };
}

function makeScanWorkerDeps(dagRegistry: DagRegistry, config?: KuzushiConfig) {
  return { dagRegistry, config: config ?? makeConfig(), runtime: {} as AgentRuntime };
}

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep:scan"],
    severity: ["ERROR", "WARNING"],
    excludePatterns: ["node_modules"],
    taskConfig: {
      semgrep: {},
    },
  };
}

function makeFinding(fp: string, score: number): Finding {
  return {
    taskId: "semgrep:scan",
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

/** Create a DagRegistry with a semgrep task that returns the given findings. */
function makeRegistryWithFindings(...findings: Finding[]): DagRegistry {
  const dagRegistry = new DagRegistry();
  dagRegistry.register({
    id: "semgrep:scan",
    displayName: "Semgrep",
    outputKind: "findings",
    dependsOn: [],
    async run() {
      return findings;
    },
  });
  return dagRegistry;
}

function makeScanOpts(): ScanOpts {
  return {
    severity: ["ERROR"],
    excludePatterns: ["node_modules"],
    tasks: ["semgrep:scan"],
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
  it("starts task DAG from pipeline:start", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const semgrepTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "semgrep:scan",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-start", 80)];
      },
    };
    dagRegistry.register(semgrepTask);

    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerStoreWorker(bus, { db });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const taskStartPromise = bus.waitFor<TaskStartEvent>(
      "task:start",
      (event) => event.meta.runId === runId && event.payload.taskId === "semgrep:scan",
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
      }),
    );

    const taskStart = await taskStartPromise;
    expect(taskStart.payload.taskId).toBe("semgrep:scan");

    await bus.close();
    db.close();
  });

  it("filters already-triaged findings and completes the pipeline", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const existing = makeFinding("fp-skip", 50);
    const toTriage = makeFinding("fp-triage", 60);
    const dagRegistry = makeRegistryWithFindings(existing, toTriage);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

    upsertFinding(db, existing, makeResult("fp-skip"), "repo", "HEAD");

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    registerMockBatchTriageWorker(bus, (finding) => makeResult(finding.fingerprint));

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

    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
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

    const dagRegistry = new DagRegistry();
    dagRegistry.register({
      id: "semgrep:scan",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [
          {
            ...makeFinding("fp-semgrep", 70),
            filePath: "src/db.ts",
            startLine: 44,
            cwe: ["CWE-89"],
          },
        ];
      },
    });
    dagRegistry.register({
      id: "codeql:scan",
      displayName: "CodeQL",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [
          {
            ...makeFinding("fp-codeql", 90),
            taskId: "codeql:scan",
            ruleId: "js/sql-injection",
            filePath: "src/db.ts",
            startLine: 44,
            cwe: ["CWE-89"],
          },
        ];
      },
    });

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
        config: {
          ...makeConfig(),
          tasks: ["semgrep:scan", "codeql:scan"],
        },
        scanOpts: { ...makeScanOpts(), fresh: true, tasks: ["semgrep:scan", "codeql:scan"] },
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
      tasks: ["semgrep:scan", "agentic"],
    };

    const dagRegistry = new DagRegistry();
    dagRegistry.register({
      id: "semgrep:scan",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [
          {
            ...makeFinding("fp-semgrep", 50),
            taskId: "semgrep:scan",
          },
        ];
      },
    });
    dagRegistry.register({
      id: "agentic",
      displayName: "Agentic",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [
          {
            ...makeFinding("fp-agentic", 80),
            taskId: "agentic",
            ruleId: "agentic.sql-injection",
            scannerConfidence: "HIGH",
          },
        ];
      },
    });

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
        scanOpts: { ...makeScanOpts(), tasks: ["semgrep:scan", "agentic"] },
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

    const dagRegistry = makeRegistryWithFindings(
      makeFinding("fp-cost-1", 70),
      makeFinding("fp-cost-2", 60),
    );

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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

    const triageCompletePromise = bus.waitFor<TriageCompleteEvent>(
      "triage:complete",
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
      taskConfig: {
        semgrep: { verify: false },
      },
    };

    const dagRegistry = makeRegistryWithFindings(makeFinding("fp-no-verify", 55));
    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

    registerMockBatchTriageWorker(bus, (finding) => makeResult(finding.fingerprint));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

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
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
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

    const dagRegistry = makeRegistryWithFindings(
      makeFinding("fp-low", 70),
      makeFinding("fp-mid", 60),
      makeFinding("fp-high", 50),
    );

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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

    const verificationQueued: Array<{
      finding: any;
      triageResult: any;
      index: number;
      total: number;
    }> = [];
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
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
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

    const dagRegistry = makeRegistryWithFindings(makeFinding("fp-dup-verify", 60));
    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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

    const verificationQueuedPromise = bus.waitFor<VerificationFindingQueuedEvent>(
      "verification:finding-queued",
      (event) => event.meta.runId === runId,
    );
    const pocStartPromise = bus.waitFor<PocHarnessStartEvent>(
      "poc-harness:start",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
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
    const dagRegistry = makeRegistryWithFindings(makeFinding("fp-no-poc", 80));

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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

    const verificationQueuedPromise = bus.waitFor<VerificationFindingQueuedEvent>(
      "verification:finding-queued",
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
    const dagRegistry = makeRegistryWithFindings(makeFinding("fp-no-exploit", 70));

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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

    const verificationQueuedPromise = bus.waitFor<VerificationFindingQueuedEvent>(
      "verification:finding-queued",
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
    const dagRegistry = makeRegistryWithFindings(makeFinding("fp-poc-gate", 85));

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
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

    registerOrchestrator(bus, makeDeps(db));
    registerStoreWorker(bus, { db });

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
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId && event.payload.taskId === "semgrep:scan") {
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

    registerOrchestrator(bus, makeDeps(db));
    registerStoreWorker(bus, { db });

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
    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      if (event.meta.runId === runId && event.payload.taskId === "semgrep:scan") {
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
    const dagRegistry = makeRegistryWithFindings();

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

    const resumeRunId = "resume-scan-stage";
    createRun(db, resumeRunId, "repo", makeConfig(), {
      ...makeScanOpts(),
      maxFindings: 5,
    });
    updateRunContext(db, resumeRunId, { languages: ["TypeScript"] });

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

    const taskStartPromise = bus.waitFor<TaskStartEvent>(
      "task:start",
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

    // The orchestrator should have resumed with stored scan options via runTaskDag
    const taskStart = await taskStartPromise;
    expect(taskStart.payload.taskId).toBeDefined();
    expect(errors).toHaveLength(0);

    await bus.close();
    db.close();
  });

  it("does not re-apply current --max to checkpoint findings during resume", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    registerOrchestrator(bus, makeDeps(db));
    registerStoreWorker(bus, { db });

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
    expect(
      persistedCheckpoint.every((finding: Finding) => typeof finding.adjustedScore === "number"),
    ).toBe(true);

    await bus.close();
    db.close();
  });

  it("continues triage when cost checkpoint persistence fails", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const dagRegistry = makeRegistryWithFindings(makeFinding("fp-cost-fail", 50));

    // Intentionally no store-worker — this test closes the DB mid-pipeline
    // to verify the orchestrator handles DB failures gracefully.
    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));

    const runId = generateRunId();
    createRun(db, runId, "repo", makeConfig(), makeScanOpts());

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

    const batchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
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

    const batchQueued = await batchQueuedPromise;

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
    const dagRegistry = makeRegistryWithFindings();

    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

    bus.subscribe("task:start", () => {
      throw new Error("task-start crash");
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
    expect(pipelineError.payload.error).toContain("Bus handler failure on task:start");
    expect(pipelineError.payload.error).toContain("task-start crash");
    expect(pipelineError.payload.fatal).toBe(true);

    await bus.close();
    db.close();
  });

  it("threads context-gatherer output into triage queue events", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const semgrepTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "semgrep:scan",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-context", 80)];
      },
    };

    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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

    dagRegistry.register(semgrepTask);
    dagRegistry.register(contextTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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

  it("treats seeded task outputs as already satisfied DAG dependencies", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    let contextGathererRuns = 0;
    const taskStarts: string[] = [];
    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        contextGathererRuns += 1;
        return {
          repoContext: {
            languages: ["TypeScript"],
            frameworks: ["Express"],
            authPatterns: ["JWT"],
            sanitizationLibs: [],
            ormOrDb: [],
            entryPoints: ["src/api.ts"],
          },
          fileIndex: {
            tree: [{ path: "src/api.ts" }],
            totalFiles: 1,
            truncated: false,
            patternMatches: {},
          },
        };
      },
    };
    const dependentTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "context:code-config-detect",
      displayName: "Code Config Detect",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run(_input, context) {
        const seeded = context.upstreamOutputs.get("context:context-gatherer") as
          | Record<string, unknown>
          | undefined;
        if (!seeded || !("repoContext" in seeded)) {
          throw new Error("missing seeded context");
        }
        return [makeFinding("seeded-context", 90)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(dependentTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });
    registerMockBatchTriageWorker(bus, (finding) => makeResult(finding.fingerprint));

    bus.subscribe<TaskStartEvent>("task:start", (event) => {
      taskStarts.push(event.payload.taskId);
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };
    bus.subscribe<ReportRequestedEvent>("report:requested", async (event) => {
      if (event.meta.runId !== runId) {
        return;
      }
      await bus.publish(
        createEvent("report:complete", runId, {
          context: event.payload.context,
        }),
      );
    });

    const pipelineCompletePromise = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          tasks: ["context:code-config-detect"],
          enableDynamicTaskSelection: false,
        },
        scanOpts: {
          ...makeScanOpts(),
          tasks: [],
        },
        seedTaskOutputs: new Map([
          [
            "context:context-gatherer",
            {
              repoContext: {
                languages: ["TypeScript"],
                frameworks: ["Express"],
                authPatterns: ["JWT"],
                sanitizationLibs: [],
                ormOrDb: [],
                entryPoints: ["src/api.ts"],
              },
              fileIndex: {
                tree: [{ path: "src/api.ts" }],
                totalFiles: 1,
                truncated: false,
                patternMatches: {},
              },
            },
          ],
        ]),
      }),
    );

    await pipelineCompletePromise;

    expect(contextGathererRuns).toBe(0);
    expect(taskStarts).not.toContain("context:context-gatherer");
    expect(taskStarts).toContain("context:code-config-detect");

    await bus.close();
    db.close();
  });

  it("threads context-enricher output into triage queue events when enabled", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const semgrepTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "semgrep:scan",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-enriched", 80)];
      },
    };

    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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

    const enrichmentTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-enricher",
      displayName: "Context Enricher",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return {
          customMiddleware: [
            { name: "auth", filePath: "src/middleware/auth.ts", purpose: "auth gate" },
          ],
          customSanitizers: [],
          trustBoundaries: [],
          dataClassifications: [],
          architecturalNotes: ["Background jobs process user uploads."],
        };
      },
    };

    dagRegistry.register(semgrepTask);
    dagRegistry.register(contextTask);
    dagRegistry.register(enrichmentTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
      customMiddleware: [{ name: "auth", filePath: "src/middleware/auth.ts" }],
      architecturalNotes: ["Background jobs process user uploads."],
    });

    await bus.close();
    db.close();
  });

  it("normalizes dynamic task selections into runnable task ids", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const selectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return {
          recommendedTasks: ["dangerous-api", "secrets", "security-misconfig"],
          reasoning: {},
        };
      },
    };
    const codeConfigTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "context:code-config-detect",
      displayName: "Code & Config",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-dynamic", 91)];
      },
    };
    const secretsCryptoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(selectorTask);
    dagRegistry.register(codeConfigTask);
    dagRegistry.register(secretsCryptoTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: [],
          enableDynamicTaskSelection: true,
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;
    expect(taskStarts).toContain("pipeline:task-selector");
    expect(taskStarts).toContain("context:code-config-detect");
    expect(taskStarts).toContain("agentic-sast:secrets-crypto-detect");
    expect(triageBatchQueued.payload.findings.map((finding) => finding.fingerprint)).toEqual([
      "fp-dynamic",
    ]);

    await bus.close();
    db.close();
  });

  it("emits fatal error when ALL tasks in a stage fail", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();

    const failingTask1: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "fail-task-1",
      displayName: "Fail Task 1",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        throw new Error("intentional failure 1");
      },
    };

    const failingTask2: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "fail-task-2",
      displayName: "Fail Task 2",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        throw new Error("intentional failure 2");
      },
    };

    dagRegistry.register(failingTask1);
    dagRegistry.register(failingTask2);

    const config: KuzushiConfig = {
      ...makeConfig(),
      tasks: ["fail-task-1", "fail-task-2"],
    };

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
        config,
        scanOpts: { ...makeScanOpts(), tasks: ["fail-task-1", "fail-task-2"] },
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

    const dagRegistry = new DagRegistry();

    const goodScanner: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "good-scanner",
      displayName: "Good Scanner",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-good", 80)];
      },
    };

    const badScanner: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "bad-scanner",
      displayName: "Bad Scanner",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        throw new Error("scanner crashed");
      },
    };

    dagRegistry.register(goodScanner);
    dagRegistry.register(badScanner);

    const config: KuzushiConfig = {
      ...makeConfig(),
      tasks: ["good-scanner", "bad-scanner"],
    };

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
        config,
        scanOpts: { ...makeScanOpts(), tasks: ["good-scanner", "bad-scanner"] },
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

    const dagRegistry = new DagRegistry();
    let upstreamFromSemgrep: unknown;

    const semgrepTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "semgrep:scan",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-semgrep", 54)];
      },
    };

    const dependentTask: DagNodeImpl<ScanOpts, { ok: boolean }> = {
      id: "post-analysis",
      displayName: "Post Analysis",
      outputKind: "custom",
      dependsOn: ["semgrep:scan"],
      async run(_input, context) {
        upstreamFromSemgrep = context.upstreamOutputs.get("semgrep:scan");
        return { ok: true };
      },
    };

    dagRegistry.register(semgrepTask);
    dagRegistry.register(dependentTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: ["post-analysis"],
        },
        scanOpts: makeScanOpts(),
      }),
    );

    await stage2Done;

    expect(taskStartOrder).toEqual(["semgrep:scan", "post-analysis"]);
    expect(Array.isArray(upstreamFromSemgrep)).toBe(true);
    expect((upstreamFromSemgrep as Finding[])[0].fingerprint).toBe("fp-semgrep");

    await bus.close();
    db.close();
  });

  it("triggers verification after batch triage produces TPs with verify enabled", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const findings = [
      makeFinding("fp-verify-1", 80),
      makeFinding("fp-verify-2", 70),
      makeFinding("fp-verify-3", 60),
    ];
    const config: KuzushiConfig = {
      ...makeConfig(),
      verify: true,
      verifyVerdicts: ["tp"],
    };
    const dagRegistry = makeRegistryWithFindings(...findings);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
        config,
        scanOpts: { ...makeScanOpts(), fresh: true },
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

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const selectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return {
          recommendedTasks: ["secrets", "ssrf"],
          reasoning: {},
        };
      },
    };
    // Register two selectable tasks — only the recommended ones should run
    const secretsCryptoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-secrets", 80)];
      },
    };
    const ssrfTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:ssrf-detect",
      displayName: "SSRF",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-ssrf", 70)];
      },
    };
    const protoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:prototype-pollution-detect",
      displayName: "Prototype Pollution",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-proto", 60)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(selectorTask);
    dagRegistry.register(secretsCryptoTask);
    dagRegistry.register(ssrfTask);
    dagRegistry.register(protoTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: [],
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Only task-selector-recommended tasks should have run
    expect(taskStarts).toContain("pipeline:task-selector");
    expect(taskStarts).toContain("agentic-sast:secrets-crypto-detect");
    expect(taskStarts).toContain("agentic-sast:ssrf-detect");
    // prototype-pollution-detect was NOT recommended, so it should NOT run
    expect(taskStarts).not.toContain("agentic-sast:prototype-pollution-detect");
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

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const failingSelectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        throw new Error("task-selector crash");
      },
    };
    const secretsCryptoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-fallback-secrets", 80)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(failingSelectorTask);
    dagRegistry.register(secretsCryptoTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: [],
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Despite task-selector failing, the fallback should enable selectable tasks
    expect(taskStarts).toContain("agentic-sast:secrets-crypto-detect");
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toContain(
      "fp-fallback-secrets",
    );

    await bus.close();
    db.close();
  });

  it("preserves explicit tasks when dynamic selection is active", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const selectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return {
          recommendedTasks: ["ssrf"],
          reasoning: {},
        };
      },
    };
    const secretsCryptoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-explicit-secrets", 80)];
      },
    };
    const ssrfTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:ssrf-detect",
      displayName: "SSRF",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-dynamic-ssrf", 70)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(selectorTask);
    dagRegistry.register(secretsCryptoTask);
    dagRegistry.register(ssrfTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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

    // User explicitly sets tasks — dynamic selection adds to it, doesn't replace
    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableDynamicTaskSelection: true,
          tasks: ["agentic-sast:secrets-crypto-detect"],
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Explicit task should always run
    expect(taskStarts).toContain("agentic-sast:secrets-crypto-detect");
    // task-selector should run even with explicit tasks
    expect(taskStarts).toContain("pipeline:task-selector");
    // Dynamic ssrf-detect added by task-selector
    expect(taskStarts).toContain("agentic-sast:ssrf-detect");
    const fps = triageBatchQueued.payload.findings.map((f) => f.fingerprint);
    expect(fps).toContain("fp-explicit-secrets");
    expect(fps).toContain("fp-dynamic-ssrf");

    await bus.close();
    db.close();
  });

  it("runs only explicitly enabled tasks when dynamic selection is disabled", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const scannerTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "semgrep:scan",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-semgrep-explicit", 90)];
      },
    };
    const secretsTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-explicit-secrets-only", 80)];
      },
    };
    const protoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:prototype-pollution-detect",
      displayName: "Prototype Pollution",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding("fp-explicit-proto", 60)];
      },
    };

    dagRegistry.register(scannerTask);
    dagRegistry.register(secretsTask);
    dagRegistry.register(protoTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };
    const config = {
      ...makeConfig(),
      enableDynamicTaskSelection: false,
      tasks: ["semgrep:scan", "agentic-sast:secrets-crypto-detect"],
    };
    const scanOpts = { ...makeScanOpts(), tasks: ["semgrep:scan"] };

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
    const scanPlan = getScanPlanSummary(config, scanOpts, dagRegistry);

    expect(taskStarts).toContain("semgrep:scan");
    expect(taskStarts).toContain("agentic-sast:secrets-crypto-detect");
    expect(taskStarts).not.toContain("agentic-sast:prototype-pollution-detect");
    expect(scanPlan.dynamicSelectionActive).toBe(false);
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint).sort()).toEqual([
      "fp-explicit-secrets-only",
      "fp-semgrep-explicit",
    ]);

    await bus.close();
    db.close();
  });

  it("runs all explicitly listed tasks when dynamic selection is disabled", {
    timeout: 15_000,
  }, async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const selectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return { recommendedTasks: ["secrets"], reasoning: {} };
      },
    };
    const secretsCryptoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [];
      },
    };
    const protoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:prototype-pollution-detect",
      displayName: "Prototype Pollution",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-proto-compat", 60)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(selectorTask);
    dagRegistry.register(secretsCryptoTask);
    dagRegistry.register(protoTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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

    // Dynamic selection disabled — explicitly listed tasks run
    const taskList = [
      "context:context-gatherer",
      "agentic-sast:secrets-crypto-detect",
      "agentic-sast:prototype-pollution-detect",
    ];
    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: {
          ...makeConfig(),
          enableDynamicTaskSelection: false,
          tasks: taskList,
        },
        scanOpts: { ...makeScanOpts(), tasks: taskList },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Both selectable tasks ran
    expect(taskStarts).toContain("agentic-sast:secrets-crypto-detect");
    expect(taskStarts).toContain("agentic-sast:prototype-pollution-detect");
    const scanPlan = getScanPlanSummary(
      {
        ...makeConfig(),
        enableDynamicTaskSelection: false,
        tasks: taskList,
      },
      { ...makeScanOpts(), tasks: taskList },
      dagRegistry,
    );
    expect(scanPlan.dynamicSelectionActive).toBe(false);
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toContain(
      "fp-proto-compat",
    );

    await bus.close();
    db.close();
  });

  it("tasks ['*'] with dynamic selection runs all tasks without filtering", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const selectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        // Should not matter — ["*"] bypasses dynamic filtering
        return { recommendedTasks: ["secrets"], reasoning: {} };
      },
    };
    const secretsCryptoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-star-secrets", 80)];
      },
    };
    const protoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:prototype-pollution-detect",
      displayName: "Prototype Pollution",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-star-proto", 60)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(selectorTask);
    dagRegistry.register(secretsCryptoTask);
    dagRegistry.register(protoTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: ["*"],
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Both selectable tasks run — ["*"] means run everything, no filtering
    expect(taskStarts).toContain("agentic-sast:secrets-crypto-detect");
    expect(taskStarts).toContain("agentic-sast:prototype-pollution-detect");
    const fps = triageBatchQueued.payload.findings.map((f) => f.fingerprint);
    expect(fps).toContain("fp-star-secrets");
    expect(fps).toContain("fp-star-proto");

    await bus.close();
    db.close();
  });

  it("falls back to all selectable tasks when task-selector returns empty recommendations", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const emptySelectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return { recommendedTasks: [], reasoning: {} };
      },
    };
    const secretsCryptoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-empty-fallback", 80)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(emptySelectorTask);
    dagRegistry.register(secretsCryptoTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: [],
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Despite empty recommendations, fallback should enable all selectable tasks
    expect(taskStarts).toContain("agentic-sast:secrets-crypto-detect");
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toContain(
      "fp-empty-fallback",
    );

    await bus.close();
    db.close();
  });

  it("does not re-add disabled tasks from task-selector recommendations or fallback", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const selectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return { recommendedTasks: ["secrets"], reasoning: {} };
      },
    };
    const secretsCryptoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-disabled-secrets", 80)];
      },
    };
    const protoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:prototype-pollution-detect",
      displayName: "Prototype Pollution",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-fallback-proto", 60)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(selectorTask);
    dagRegistry.register(secretsCryptoTask);
    dagRegistry.register(protoTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: [],
        },
        scanOpts: { ...makeScanOpts(), tasks: [], disabledTasks: ["secrets"] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    expect(taskStarts).not.toContain("agentic-sast:secrets-crypto-detect");
    expect(taskStarts).toContain("agentic-sast:prototype-pollution-detect");
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toEqual([
      "fp-fallback-proto",
    ]);

    await bus.close();
    db.close();
  });

  it("threat-model-randori does not run when not recommended by task-selector", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const selectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        // Only recommend secrets — NOT stride or pasta
        return { recommendedTasks: ["secrets"], reasoning: {} };
      },
    };
    const secretsCryptoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-secrets-only", 80)];
      },
    };
    const randoriTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "threat-model:threat-model-randori",
      displayName: "Randori PASTA Threat Model",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-randori", 70)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(selectorTask);
    dagRegistry.register(secretsCryptoTask);
    dagRegistry.register(randoriTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: [],
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Randori should not run — it is selectable and was not recommended
    expect(taskStarts).not.toContain("threat-model:threat-model-randori");
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

    const dagRegistry = new DagRegistry();
    let ssrfUpstream: Map<string, unknown> | undefined;

    dagRegistry.register({
      id: "context:context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return {
          repoContext: {
            languages: ["TypeScript"],
            frameworks: [],
            authPatterns: [],
            sanitizationLibs: [],
            ormOrDb: [],
            entryPoints: [],
          },
          fileIndex: { tree: [], totalFiles: 0, truncated: false, patternMatches: {} },
        };
      },
    });
    dagRegistry.register({
      id: "threat-model:threat-model-randori",
      displayName: "Randori PASTA Threat Model",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
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
    dagRegistry.register({
      id: "agentic-sast:ssrf-detect",
      displayName: "SSRF Detector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run(_input, context) {
        ssrfUpstream = new Map(context.upstreamOutputs);
        return { findings: ["ssrf"] };
      },
    });

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: ["agentic-sast:ssrf-detect"],
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    await reportRequestedPromise;
    await bus.publish(
      createEvent("report:complete", runId, {
        context,
      }),
    );
    await completePromise;

    expect(taskStarts).toContain("threat-model:threat-model-randori");
    expect(taskStarts.indexOf("threat-model:threat-model-randori")).toBeLessThan(
      taskStarts.indexOf("agentic-sast:ssrf-detect"),
    );
    expect(ssrfUpstream?.has("threat-model:threat-model-randori")).toBe(true);

    await bus.close();
    db.close();
  });

  it("does not auto-inject Randori for non-threat-aware detector runs", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    dagRegistry.register({
      id: "context:context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return {
          repoContext: {
            languages: ["TypeScript"],
            frameworks: [],
            authPatterns: [],
            sanitizationLibs: [],
            ormOrDb: [],
            entryPoints: [],
          },
          fileIndex: { tree: [], totalFiles: 0, truncated: false, patternMatches: {} },
        };
      },
    });
    dagRegistry.register({
      id: "threat-model:threat-model-randori",
      displayName: "Randori PASTA Threat Model",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return {};
      },
    });
    // Use diff-review as a non-threat-aware task (not in THREAT_AWARE_DETECTOR_TASK_IDS)
    dagRegistry.register({
      id: "agentic-sast:diff-review",
      displayName: "Diff Review",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return {};
      },
    });

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: ["agentic-sast:diff-review"],
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    await reportRequestedPromise;
    await bus.publish(
      createEvent("report:complete", runId, {
        context,
      }),
    );
    await completePromise;

    expect(taskStarts).toContain("agentic-sast:diff-review");
    expect(taskStarts).not.toContain("threat-model:threat-model-randori");

    await bus.close();
    db.close();
  });

  it("does not re-schedule failed task-selector after fallback fires", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const failingSelectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        throw new Error("task-selector crash");
      },
    };
    const secretsCryptoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-no-resched", 80)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(failingSelectorTask);
    dagRegistry.register(secretsCryptoTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: [],
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    await triageBatchQueuedPromise;

    // task-selector should be started exactly once — not re-scheduled after failure
    expect(taskStarts.filter((id) => id === "pipeline:task-selector")).toHaveLength(1);
    // Fallback should still fire and run selectable tasks
    expect(taskStarts).toContain("agentic-sast:secrets-crypto-detect");

    await bus.close();
    db.close();
  });

  it("fallback fires when only recommended selectable task fails", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const selectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        // Recommend only the task that will fail
        return { recommendedTasks: ["secrets"], reasoning: {} };
      },
    };
    // Selectable task that will fail — use "custom" outputKind so the fatal
    // "all findings producers failed" abort doesn't fire (we're testing the
    // hasSelectableTasks fallback guard, not the fatal abort path).
    const failingSecretsTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        throw new Error("secrets-crypto crash");
      },
    };
    // This selectable task should be added by fallback
    const ssrfTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:ssrf-detect",
      displayName: "SSRF",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-fallback-ssrf", 70)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(selectorTask);
    dagRegistry.register(failingSecretsTask);
    dagRegistry.register(ssrfTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: [],
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // secrets-crypto-detect failed, so fallback should add other selectable tasks
    expect(taskStarts).toContain("agentic-sast:ssrf-detect");
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toContain(
      "fp-fallback-ssrf",
    );

    await bus.close();
    db.close();
  });

  it("does not fatally abort when condition-skipped findings task is in a stage with a failing non-findings task", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();

    const findingsTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "findings-task",
      displayName: "Findings Task",
      outputKind: "findings",
      dependsOn: [],
      condition: () => false, // intentionally skipped
      async run() {
        return [makeFinding("fp-should-not-run", 80)];
      },
    };

    const metaTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "meta-task",
      displayName: "Meta Task",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        throw new Error("meta-task crash");
      },
    };

    dagRegistry.register(findingsTask);
    dagRegistry.register(metaTask);

    const config: KuzushiConfig = {
      ...makeConfig(),
      tasks: ["findings-task", "meta-task"],
    };

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
        config,
        scanOpts: { ...makeScanOpts(), tasks: ["findings-task", "meta-task"] },
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

    const dagRegistry = new DagRegistry();
    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
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
    const selectorTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "pipeline:task-selector",
      displayName: "Task Selector",
      outputKind: "custom",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return { recommendedTasks: ["secrets"], reasoning: {} };
      },
    };
    const secretsCryptoTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "agentic-sast:secrets-crypto-detect",
      displayName: "Secrets & Crypto",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-ctx-kept", 80)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(selectorTask);
    dagRegistry.register(secretsCryptoTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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
          tasks: [],
        },
        scanOpts: { ...makeScanOpts(), tasks: [] },
      }),
    );

    const triageBatchQueued = await triageBatchQueuedPromise;

    // Pipeline should complete — context-gatherer kept despite enableContextGathering: false
    expect(taskStarts).toContain("context:context-gatherer");
    expect(taskStarts).toContain("pipeline:task-selector");
    expect(taskStarts).toContain("agentic-sast:secrets-crypto-detect");
    expect(triageBatchQueued.payload.findings.map((f) => f.fingerprint)).toContain("fp-ctx-kept");

    await bus.close();
    db.close();
  });

  it("keeps context-gatherer when enableContextGathering is false but tasks depend on it", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();

    const contextTask: DagNodeImpl<ScanOpts, unknown> = {
      id: "context:context-gatherer",
      displayName: "Context Gatherer",
      outputKind: "custom",
      dependsOn: [],
      async run() {
        return { languages: ["TypeScript"] };
      },
    };

    const dependentTask: DagNodeImpl<ScanOpts, Finding[]> = {
      id: "dependent-task",
      displayName: "Dependent Task",
      outputKind: "findings",
      dependsOn: ["context:context-gatherer"],
      async run() {
        return [makeFinding("fp-dep", 80)];
      },
    };

    dagRegistry.register(contextTask);
    dagRegistry.register(dependentTask);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const config: KuzushiConfig = {
      ...makeConfig(),
      enableContextGathering: false,
      tasks: ["dependent-task"],
    };

    // Pipeline should NOT crash — context-gatherer kept because dependent-task needs it
    const triageBatchQueuedPromise = bus.waitFor<TriageBatchQueuedEvent>(
      "triage:batch-queued",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: { ...makeScanOpts(), tasks: ["dependent-task"] },
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

    // Create findings with different scores
    const findingHigh = makeFinding("fp-high-score", 90);
    const findingMid = makeFinding("fp-mid-score", 60);
    const findingLow = makeFinding("fp-low-score", 30);
    // Give mid-score finding a taintPath to test tiebreaking
    findingMid.taintPath = [{ filePath: "a.ts", line: 1, message: "source" }];

    const config: KuzushiConfig = {
      ...makeConfig(),
      verify: true,
      verifyConcurrency: 1,
      triageConcurrency: 3,
    };
    const dagRegistry = makeRegistryWithFindings(findingMid, findingLow, findingHigh);

    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry, config));
    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerStoreWorker(bus, { db });

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

    await verificationStartPromise;
    await new Promise((r) => setTimeout(r, 50));

    // Verification queue should be ordered: high-score (90), mid-score (60), low-score (30)
    expect(verificationQueued.length).toBeGreaterThanOrEqual(1);
    const queuedFingerprints = verificationQueued.map((q) => q.finding.fingerprint);
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

  it("classifies bus:handler-error from triage:assertions as non-fatal", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    // A semgrep task that never completes — keeps run state populated
    // so handleBusHandlerError can find it instead of early-returning.
    const dagRegistry = new DagRegistry();
    dagRegistry.register({
      id: "semgrep:scan",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return new Promise<Finding[]>(() => {
          /* never resolves — keeps state alive for the test */
        });
      },
    });

    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const taskStarted = bus.waitFor<TaskStartEvent>(
      "task:start",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
      }),
    );

    await taskStarted;

    const pipelineErrorPromise = bus.waitFor<PipelineErrorEvent>(
      "pipeline:error",
      (event) => event.meta.runId === runId && event.payload.error.includes("triage:assertions"),
      1_000,
    );

    await bus.publish(
      createEvent("bus:handler-error", runId, {
        sourceEventType: "triage:assertions",
        sourceEventId: "evt-1",
        error: "FOREIGN KEY constraint failed",
      }),
    );

    const pipelineError = await pipelineErrorPromise;
    expect(pipelineError.payload.fatal).toBe(false);

    await bus.close();
    db.close();
  });

  it("classifies bus:handler-error from triage:result as fatal", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const dagRegistry = new DagRegistry();
    dagRegistry.register({
      id: "semgrep:scan",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return new Promise<Finding[]>(() => {
          /* never resolves */
        });
      },
    });

    registerOrchestrator(bus, makeDeps(db, dagRegistry));
    registerScanWorker(bus, makeScanWorkerDeps(dagRegistry));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const taskStarted = bus.waitFor<TaskStartEvent>(
      "task:start",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config: makeConfig(),
        scanOpts: makeScanOpts(),
      }),
    );

    await taskStarted;

    const pipelineErrorPromise = bus.waitFor<PipelineErrorEvent>(
      "pipeline:error",
      (event) => event.meta.runId === runId && event.payload.error.includes("triage:result"),
      1_000,
    );

    await bus.publish(
      createEvent("bus:handler-error", runId, {
        sourceEventType: "triage:result",
        sourceEventId: "evt-2",
        error: "boom",
      }),
    );

    const pipelineError = await pipelineErrorPromise;
    expect(pipelineError.payload.fatal).toBe(true);

    await bus.close();
    db.close();
  });
});
