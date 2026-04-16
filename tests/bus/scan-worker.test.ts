import { describe, expect, it } from "vitest";
import type { AgentRuntime } from "../../src/agent-runtime/types.js";
import { TaskRegistry } from "../../src/agents/registry.js";
import type { AgentTask, TaskContext } from "../../src/agents/types.js";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import type { ScanFindingEvent, TaskCompleteEvent, TaskErrorEvent } from "../../src/bus/events.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerScanWorker } from "../../src/bus/workers/scan-worker.js";
import type { Finding } from "../../src/scanners/types.js";
import { attachTaskOutputMeta } from "../../src/task-output-meta.js";
import type { KuzushiConfig, ScanOpts } from "../../src/types.js";

function makeFinding(taskId: string, fp: string): Finding {
  return {
    taskId,
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

function makeConfig(overrides: Partial<KuzushiConfig> = {}): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    busBackend: "in-process",
    triageBatchSize: 15,
    triageConcurrency: 1,
    scanMode: "sequential",
    tasks: ["a", "b"],
    severity: ["ERROR"],
    excludePatterns: [],
    taskConfig: {
      a: {},
      b: {},
    },
    ...overrides,
  };
}

function makeDeps(taskRegistry: TaskRegistry, config?: KuzushiConfig) {
  return {
    taskRegistry,
    config: config ?? makeConfig(),
    runtime: {} as AgentRuntime,
  };
}

function createFakeTask(
  id: string,
  findings: Finding[],
  tracker?: { roots: string[] },
): AgentTask<unknown, Finding[]> {
  return {
    id,
    displayName: id.toUpperCase(),
    outputKind: "findings" as const,
    dependsOn: [],
    async run(_input: unknown, context: TaskContext) {
      tracker?.roots.push(context.repoRoot);
      return findings;
    },
  };
}

describe("scan-worker", () => {
  it("runs a task and streams findings via task:start", async () => {
    const bus = new InProcessBus();
    const trackerA = { roots: [] as string[] };
    const trackerB = { roots: [] as string[] };
    const taskRegistry = new TaskRegistry();
    taskRegistry.register(createFakeTask("a", [makeFinding("a", "fp-a")], trackerA));
    taskRegistry.register(createFakeTask("b", [makeFinding("b", "fp-b")], trackerB));

    registerScanWorker(bus, makeDeps(taskRegistry));

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

    const completeA = bus.waitFor<TaskCompleteEvent>(
      "task:complete",
      (event) => event.meta.runId === runId && event.payload.taskId === "a",
    );
    const completeB = bus.waitFor<TaskCompleteEvent>(
      "task:complete",
      (event) => event.meta.runId === runId && event.payload.taskId === "b",
    );

    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "a",
        outputKind: "findings",
        input: {},
        upstreamOutputs: new Map(),
      }),
    );
    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "b",
        outputKind: "findings",
        input: {},
        upstreamOutputs: new Map(),
      }),
    );

    await completeA;
    await completeB;

    expect(trackerA.roots).toEqual(["/tmp/repo"]);
    expect(trackerB.roots).toEqual(["/tmp/repo"]);
    expect(findingEvents).toHaveLength(2);

    await bus.close();
  });

  it("uses scanPath when provided in run context", async () => {
    const bus = new InProcessBus();
    const tracker = { roots: [] as string[] };
    const taskRegistry = new TaskRegistry();
    taskRegistry.register(createFakeTask("a", [makeFinding("a", "fp-a")], tracker));

    registerScanWorker(bus, makeDeps(taskRegistry));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      scanPath: "/tmp/repo/subdir",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const completePromise = bus.waitFor<TaskCompleteEvent>(
      "task:complete",
      (event) => event.meta.runId === runId && event.payload.taskId === "a",
    );

    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "a",
        outputKind: "findings",
        input: {},
        upstreamOutputs: new Map(),
      }),
    );

    await completePromise;
    expect(tracker.roots).toEqual(["/tmp/repo/subdir"]);

    await bus.close();
  });

  it("passes projectRoot and workRoot while preserving repoRoot as a legacy alias", async () => {
    const bus = new InProcessBus();
    const taskRegistry = new TaskRegistry();
    const task: AgentTask<
      unknown,
      { projectRoot?: string; workRoot?: string; repoRoot: string; scanPath?: string }
    > = {
      id: "context-check",
      displayName: "Context Check",
      outputKind: "custom",
      dependsOn: [],
      async run(_input, context) {
        return {
          projectRoot: context.projectRoot,
          workRoot: context.workRoot,
          repoRoot: context.repoRoot,
          scanPath: context.scanPath,
        };
      },
    };
    taskRegistry.register(task);

    registerScanWorker(bus, makeDeps(taskRegistry));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      scanPath: "/tmp/repo/subdir",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const completePromise = bus.waitFor<TaskCompleteEvent>(
      "task:complete",
      (event) => event.meta.runId === runId && event.payload.taskId === "context-check",
    );

    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "context-check",
        outputKind: "custom",
        input: {},
        upstreamOutputs: new Map(),
      }),
    );

    const complete = await completePromise;
    expect(complete.payload.output).toEqual({
      projectRoot: "/tmp/repo",
      workRoot: "/tmp/repo/subdir",
      repoRoot: "/tmp/repo/subdir",
      scanPath: "/tmp/repo/subdir",
    });

    await bus.close();
  });

  it("emits task:error when taskId is not in registry", async () => {
    const bus = new InProcessBus();
    const taskRegistry = new TaskRegistry();
    registerScanWorker(bus, makeDeps(taskRegistry));

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

  it("propagates task cost metadata on task:complete", async () => {
    const bus = new InProcessBus();
    const taskRegistry = new TaskRegistry();
    const task: AgentTask<ScanOpts, Finding[]> = {
      id: "costed-task",
      displayName: "Costed Task",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return attachTaskOutputMeta([makeFinding("costed-task", "fp-task")], { costUsd: 0.034 });
      },
    };
    taskRegistry.register(task);

    registerScanWorker(bus, makeDeps(taskRegistry));

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const completePromise = bus.waitFor<TaskCompleteEvent>(
      "task:complete",
      (event) => event.meta.runId === runId && event.payload.taskId === "costed-task",
    );

    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "costed-task",
        outputKind: "findings",
        input: {
          severity: ["ERROR"],
          excludePatterns: [],
          fresh: false,
        } satisfies ScanOpts,
        upstreamOutputs: new Map(),
      }),
    );

    const complete = await completePromise;
    expect(complete.payload.costUsd).toBeCloseTo(0.034, 8);

    await bus.close();
  });

  it("fans out eligible agentic tasks across ensemble models and merges findings", async () => {
    const bus = new InProcessBus();
    const taskRegistry = new TaskRegistry();
    const task: AgentTask = {
      id: "ssrf-detect",
      displayName: "SSRF Detector",
      outputKind: "findings",
      dependsOn: [],
      async run() {
        return [];
      },
    };
    task.run = async (_input, context) => {
      if (context.modelOverride === "openai:gpt-4o") {
        return [
          {
            ...makeFinding("ssrf-detect", "dup-openai"),
            taskId: "ssrf-detect",
            filePath: "src/http.ts",
            startLine: 12,
            cwe: ["CWE-918"],
            score: 70,
            scannerConfidence: "MEDIUM",
          },
          {
            ...makeFinding("ssrf-detect", "unique-openai"),
            taskId: "ssrf-detect",
            filePath: "src/http.ts",
            startLine: 20,
            cwe: ["CWE-918"],
            score: 55,
            scannerConfidence: "LOW",
          },
        ];
      }

      return [
        {
          ...makeFinding("ssrf-detect", "dup-anthropic"),
          taskId: "ssrf-detect",
          filePath: "src/http.ts",
          startLine: 12,
          cwe: ["CWE-918"],
          score: 60,
          scannerConfidence: "HIGH",
        },
      ];
    };
    taskRegistry.register(task as AgentTask<any, any>);

    registerScanWorker(
      bus,
      makeDeps(taskRegistry, {
        ...makeConfig(),
        ensembleModels: ["anthropic:claude-haiku-4-5", "openai:gpt-4o"],
      }),
    );

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const completePromise = bus.waitFor<TaskCompleteEvent>(
      "task:complete",
      (event) => event.meta.runId === runId && event.payload.taskId === "ssrf-detect",
    );

    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "ssrf-detect",
        outputKind: "findings",
        input: {},
        upstreamOutputs: new Map(),
      }),
    );

    const complete = await completePromise;
    const findings = complete.payload.output as Finding[];
    expect(findings).toHaveLength(2);
    expect(findings[0]).toEqual(
      expect.objectContaining({
        filePath: "src/http.ts",
        startLine: 12,
        adjustedScore: 75,
        scannerConfidence: "HIGH",
      }),
    );
    expect(findings[0]?.corroboratingSignals).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ taskId: "ssrf-detect:anthropic:claude-haiku-4-5" }),
      ]),
    );
    expect(findings[1]).toEqual(
      expect.objectContaining({
        filePath: "src/http.ts",
        startLine: 20,
      }),
    );
    expect(complete.payload.costUsd).toBe(0);

    await bus.close();
  });
});
