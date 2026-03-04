import { describe, expect, it } from "vitest";
import type { ScannerPlugin, Finding, TriageAgentConfig } from "../../src/scanners/types.js";
import type { ScanOpts, KuzushiConfig } from "../../src/types.js";
import { registerScanWorker } from "../../src/bus/workers/scan-worker.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import type {
  ScanCompleteEvent,
  ScanFindingEvent,
  ScanScannerCompleteEvent,
  TaskErrorEvent,
} from "../../src/bus/events.js";
import { TaskRegistry } from "../../src/agents/registry.js";
import type { AgentTask } from "../../src/agents/types.js";

class FakePlugin implements ScannerPlugin {
  initCalled = 0;
  scanRoots: string[] = [];

  constructor(
    readonly id: string,
    readonly displayName: string,
    private readonly findings: Finding[],
    private readonly delayMs: number = 0,
  ) {}

  async init(): Promise<void> {
    this.initCalled += 1;
  }

  async scan(repoRoot: string, _opts: ScanOpts, _config: Record<string, unknown>): Promise<Finding[]> {
    this.scanRoots.push(repoRoot);
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    return this.findings;
  }

  triageAgentConfig(): TriageAgentConfig {
    return { prompt: "triage prompt" };
  }
}

function makeFinding(scanner: string, fp: string): Finding {
  return {
    scanner,
    fingerprint: fp,
    ruleId: "test.rule",
    filePath: "src/a.ts",
    startLine: 1,
    severity: "ERROR",
    message: "test",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: [],
    score: 54,
  };
}

function makeConfig(scanMode: KuzushiConfig["scanMode"]): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode,
    scanners: ["a", "b"],
    severity: ["ERROR"],
    excludePatterns: [],
    scannerConfig: {
      a: {},
      b: {},
    },
  };
}

describe("scan-worker", () => {
  it("runs scanners sequentially and streams findings", async () => {
    const bus = new InProcessBus();
    const a = new FakePlugin("a", "A", [makeFinding("a", "fp-a")]);
    const b = new FakePlugin("b", "B", [makeFinding("b", "fp-b")]);

    const registry = {
      get: (id: string) => (id === "a" ? a : b),
    };

    registerScanWorker(bus, {
      registry: registry as any,
      config: makeConfig("sequential"),
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const findingEvents: ScanFindingEvent[] = [];
    bus.subscribe<ScanFindingEvent>("scan:finding", (event) => {
      if (event.meta.runId === runId) {
        findingEvents.push(event);
      }
    });

    const scannerDoneEvents: ScanScannerCompleteEvent[] = [];
    bus.subscribe<ScanScannerCompleteEvent>("scan:scanner-complete", (event) => {
      if (event.meta.runId === runId) {
        scannerDoneEvents.push(event);
      }
    });

    const scanCompletePromise = bus.waitFor<ScanCompleteEvent>(
      "scan:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:start", runId, {
        context,
        scanners: ["a", "b"],
        scanOpts: {
          severity: ["ERROR"],
          excludePatterns: [],
          fresh: false,
        },
      }),
    );

    const scanComplete = await scanCompletePromise;

    expect(a.initCalled).toBe(1);
    expect(b.initCalled).toBe(1);
    expect(a.scanRoots).toEqual(["/tmp/repo"]);
    expect(b.scanRoots).toEqual(["/tmp/repo"]);
    expect(findingEvents).toHaveLength(2);
    expect(scannerDoneEvents).toHaveLength(2);
    expect(scanComplete.payload.totalFindings).toBe(2);

    await bus.close();
  });

  it("runs scanners concurrently when configured", async () => {
    const bus = new InProcessBus();
    const a = new FakePlugin("a", "A", [makeFinding("a", "fp-a")], 20);
    const b = new FakePlugin("b", "B", [makeFinding("b", "fp-b")], 20);

    const registry = {
      get: (id: string) => (id === "a" ? a : b),
    };

    registerScanWorker(bus, {
      registry: registry as any,
      config: makeConfig("concurrent"),
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const scanCompletePromise = bus.waitFor<ScanCompleteEvent>(
      "scan:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:start", runId, {
        context,
        scanners: ["a", "b"],
        scanOpts: {
          severity: ["ERROR"],
          excludePatterns: [],
          fresh: false,
        },
      }),
    );

    const scanComplete = await scanCompletePromise;
    expect(scanComplete.payload.totalFindings).toBe(2);
    expect(a.scanRoots).toEqual(["/tmp/repo"]);
    expect(b.scanRoots).toEqual(["/tmp/repo"]);

    await bus.close();
  });

  it("uses scanPath when provided in run context", async () => {
    const bus = new InProcessBus();
    const a = new FakePlugin("a", "A", [makeFinding("a", "fp-a")]);

    const registry = {
      get: () => a,
    };

    registerScanWorker(bus, {
      registry: registry as any,
      config: makeConfig("sequential"),
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      scanPath: "/tmp/repo/subdir",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const scanCompletePromise = bus.waitFor<ScanCompleteEvent>(
      "scan:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("scan:start", runId, {
        context,
        scanners: ["a"],
        scanOpts: {
          severity: ["ERROR"],
          excludePatterns: [],
          fresh: false,
        },
      }),
    );

    await scanCompletePromise;
    expect(a.scanRoots).toEqual(["/tmp/repo/subdir"]);

    await bus.close();
  });

  it("emits task:error when taskId is not in registry", async () => {
    const bus = new InProcessBus();
    const registry = new TaskRegistry();
    registerScanWorker(bus, {
      scannerPlugins: [],
      config: makeConfig("sequential"),
      taskRegistry: registry,
    });

    const errors: TaskErrorEvent[] = [];
    bus.subscribe<TaskErrorEvent>("task:error", (event) => {
      errors.push(event);
    });

    const runId = generateRunId();
    const context = { repoRoot: "/tmp/repo", repoName: "test-repo" };

    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "nonexistent-task",
        input: {},
        upstreamOutputs: new Map(),
      }),
    );

    // Give async subscriber a tick
    await new Promise((r) => setTimeout(r, 50));

    expect(errors).toHaveLength(1);
    expect(errors[0].payload.taskId).toBe("nonexistent-task");
    expect(errors[0].payload.error).toContain("not found in registry");

    await bus.close();
  });
});
