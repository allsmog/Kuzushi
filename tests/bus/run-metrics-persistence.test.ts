import { describe, expect, it } from "vitest";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import type { DagNodeImpl } from "../../src/agents/types.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import type {
  PipelineCompleteEvent,
  ReportRequestedEvent,
  TriageBatchQueuedEvent,
} from "../../src/bus/events.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerOrchestrator } from "../../src/bus/orchestrator.js";
import { registerScanWorker } from "../../src/bus/workers/scan-worker.js";
import { registerStoreWorker } from "../../src/bus/workers/store-worker.js";
import { DagRegistry } from "../../src/modules/dag-registry.js";
import type { Finding } from "../../src/scanners/types.js";
import { createRun, getRun, initDb } from "../../src/store.js";
import type { KuzushiConfig, ScanOpts, TriageResult } from "../../src/types.js";

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: { semgrep: {} },
  };
}

function makeScanOpts(): ScanOpts {
  return {
    severity: ["ERROR"],
    excludePatterns: [],
    tasks: ["semgrep"],
    fresh: false,
  };
}

function makeFinding(): Finding {
  return {
    taskId: "semgrep",
    fingerprint: "fp-metrics-1",
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
    score: 42,
  };
}

function makeResult(): TriageResult {
  return {
    fingerprint: "fp-metrics-1",
    verdict: "tp",
    confidence: 0.9,
    rationale: "confirmed",
    verificationSteps: ["step"],
    fixPatch: null,
    triageCostUsd: 0,
  };
}

describe("run metrics persistence", () => {
  it("persists verdict-based run metrics from stored triage results", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const config = makeConfig();

    const dagRegistry = new DagRegistry();
    dagRegistry.register({
      id: "semgrep",
      displayName: "Semgrep",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [makeFinding()];
      },
    } as DagNodeImpl<any, any>);

    registerScanWorker(bus, { dagRegistry, config, runtime: {} as AgentRuntime });
    registerOrchestrator(bus, { dagRegistry, db, runtime: {} as AgentRuntime });
    registerStoreWorker(bus, { db });

    bus.subscribe<TriageBatchQueuedEvent>("triage:batch-queued", async (event) => {
      await bus.publish(
        createEvent("triage:result", event.meta.runId, {
          context: event.payload.context,
          finding: event.payload.findings[0],
          result: makeResult(),
          costUsd: 0,
          index: 1,
          total: event.payload.total,
        }),
      );
    });

    const runId = generateRunId();
    createRun(db, runId, "repo", config, makeScanOpts());

    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const reportRequested = bus.waitFor<ReportRequestedEvent>(
      "report:requested",
      (event) => event.meta.runId === runId,
    );
    const pipelineComplete = bus.waitFor<PipelineCompleteEvent>(
      "pipeline:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: makeScanOpts(),
      }),
    );

    await reportRequested;
    await bus.publish(createEvent("report:complete", runId, { context }));
    await pipelineComplete;

    const run = getRun(db, runId);
    expect(run?.metricsJson).toBeTruthy();

    const metrics = JSON.parse(run!.metricsJson!);
    expect(metrics.verdictCounts.tp).toBe(1);
    expect(metrics.averageConfidence).toBe(0.9);
    expect(metrics.tpRate).toBe(1);
    expect(metrics.taskYield.semgrep).toBe(1);

    await bus.close();
    db.close();
  });
});
