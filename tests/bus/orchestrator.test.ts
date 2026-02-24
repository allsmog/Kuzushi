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
  ReportRequestedEvent,
  ScanStartEvent,
  StageCompleteEvent,
  TaskStartEvent,
  TriageFindingQueuedEvent,
  TriageQueueDepthEvent,
  TriageStartEvent,
} from "../../src/bus/events.js";
import { initDb, upsertFinding } from "../../src/store.js";
import type { Finding } from "../../src/scanners/types.js";
import type { KuzushiConfig, ScanOpts, TriageResult } from "../../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    model: "claude-sonnet-4-20250514",
    triageMaxTurns: 10,
    busBackend: "in-process",
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
    startLine: 10,
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
    const queuedPromise = bus.waitFor<TriageFindingQueuedEvent>(
      "triage:finding-queued",
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

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 3,
      }),
    );

    const triageStart = await triageStartPromise;
    expect(triageStart.payload.findingCount).toBe(1);

    const queued = await queuedPromise;
    expect(queued.payload.finding.fingerprint).toBe("fp-triage");

    const reportRequestedPromise = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("triage:result", runId, {
        context,
        finding: queued.payload.finding,
        result: makeResult(queued.payload.finding.fingerprint),
        index: queued.payload.index,
        total: queued.payload.total,
      }),
    );

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
});
