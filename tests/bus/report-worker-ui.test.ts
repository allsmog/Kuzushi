import { existsSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerReportWorker } from "../../src/bus/workers/report-worker.js";
import { initDb } from "../../src/store.js";
import type { KuzushiConfig } from "../../src/types.js";
import { createUIStore } from "../../src/ui/state.js";

const tempDirs: string[] = [];

beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("report-worker with UI store", () => {
  it("routes scan progress, failures, and report writes into store state", async () => {
    const tempDir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-report-ui-"));
    tempDirs.push(tempDir);
    const reportPath = path.join(tempDir, "report.md");

    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const store = createUIStore();
    store.update({
      mode: "shell",
      shell: {
        modules: ["sast"],
        tools: ["sast:scan"],
        focusedModule: "sast",
        target: "/tmp/repo",
        workspace: "acme",
        history: [],
        commandHistory: ["scan ."],
        moduleOptions: {},
        processing: false,
      },
    });

    const config: KuzushiConfig = {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: ["semgrep", "codeql"],
      severity: ["ERROR"],
      excludePatterns: [],
      reportOutput: reportPath,
      taskConfig: { semgrep: {}, codeql: {} },
    };

    registerReportWorker(bus, { db, config }, store);

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
        scanOpts: {
          severity: ["ERROR"],
          excludePatterns: [],
          tasks: ["semgrep", "codeql"],
          fresh: false,
        },
      }),
    );

    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "semgrep",
        outputKind: "findings",
        input: null,
        upstreamOutputs: new Map(),
      }),
    );
    await bus.publish(
      createEvent("task:progress", runId, {
        context,
        taskId: "semgrep",
        outputKind: "findings",
        progress: {
          ruleId: "test.rule",
          filePath: "src/app.ts",
          startLine: 10,
        },
      }),
    );
    await bus.publish(
      createEvent("task:complete", runId, {
        context,
        taskId: "semgrep",
        outputKind: "findings",
        output: [],
        durationMs: 1250,
      }),
    );
    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "codeql",
        outputKind: "findings",
        input: null,
        upstreamOutputs: new Map(),
      }),
    );
    await bus.publish(
      createEvent("task:error", runId, {
        context,
        taskId: "codeql",
        outputKind: "findings",
        error: "database lock timeout",
      }),
    );
    await bus.publish(
      createEvent("budget:warning", runId, {
        currentSpend: 4.2,
        maxBudget: 5,
        percentUsed: 84,
      }),
    );
    await bus.publish(
      createEvent("report:requested", runId, {
        context,
        reportMode: "full",
      }),
    );

    const state = store.getState();
    const scanStage = state.stages.find((stage) => stage.id === "scan");
    const semgrepTask = scanStage?.subTasks.find((task) => task.id === "semgrep");
    const codeqlTask = scanStage?.subTasks.find((task) => task.id === "codeql");

    expect(state.mode).toBe("summary");
    expect(state.shell?.focusedModule).toBe("sast");
    expect(state.shell?.workspace).toBe("acme");
    expect(state.shell?.commandHistory).toEqual(["scan ."]);
    expect(scanStage?.detail).toContain("2 tasks");
    expect(scanStage?.detail).toContain("1 finding");
    expect(semgrepTask?.findingCount).toBe(1);
    expect(semgrepTask?.detail).toContain("test.rule");
    expect(codeqlTask?.status).toBe("error");
    expect(state.notices.some((notice) => notice.message === "Task failed: codeql")).toBe(true);
    expect(state.notices.some((notice) => notice.message === "Markdown report written")).toBe(true);
    expect(state.notices.some((notice) => notice.message === "Budget nearing limit")).toBe(true);
    expect(existsSync(reportPath)).toBe(true);
    expect(console.log).not.toHaveBeenCalled();
    expect(console.error).not.toHaveBeenCalled();

    await bus.close();
    db.close();
  });

  it("uses scan/report stages only for scan-only runs", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const store = createUIStore();

    const config: KuzushiConfig = {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: ["semgrep"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: { semgrep: {} },
    };

    registerReportWorker(bus, { db, config }, store);

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
      postProcessMode: "scan-only" as const,
    };

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: {
          severity: ["ERROR"],
          excludePatterns: [],
          tasks: ["semgrep"],
          fresh: false,
        },
      }),
    );

    expect(store.getState().stages.map((stage) => stage.id)).toEqual(["scan", "report"]);

    await bus.close();
    db.close();
  });

  it("keeps shell-owned module runs in shell mode and fills module-run steps", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const store = createUIStore();
    store.update({
      mode: "shell",
      shell: {
        modules: ["taint-iris"],
        tools: ["taint-iris:hunt"],
        focusedModule: "taint-iris",
        shellView: "module-run",
        openFindingId: null,
        target: "/tmp/repo",
        workspace: "acme",
        history: [],
        commandHistory: ["use taint-iris", "run"],
        moduleOptions: {},
        processing: true,
        moduleRun: {
          moduleId: "taint-iris",
          source: "shell",
          toolName: "taint-iris:hunt",
          displayName: "Taint IRIS",
          startedAtMs: Date.now(),
          status: "running",
          steps: [],
          evidenceTail: [],
          findingCount: 0,
          costUsd: 0,
          model: "anthropic:claude-opus-4-6",
        },
      },
    });

    const config: KuzushiConfig = {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: ["taint-cwe-select", "taint-iris"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: { "taint-cwe-select": {}, "taint-iris": {} },
    };

    registerReportWorker(bus, { db, config }, store);

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
      postProcessMode: "scan-only" as const,
    };

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: {
          severity: ["ERROR"],
          excludePatterns: [],
          tasks: ["taint-cwe-select", "taint-iris"],
          fresh: false,
        },
      }),
    );
    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "taint-cwe-select",
        outputKind: "custom",
        input: null,
        upstreamOutputs: new Map(),
      }),
    );
    await bus.publish(
      createEvent("task:complete", runId, {
        context,
        taskId: "taint-cwe-select",
        outputKind: "custom",
        output: {},
        durationMs: 500,
      }),
    );
    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "taint-iris",
        outputKind: "findings",
        input: null,
        upstreamOutputs: new Map(),
      }),
    );
    await bus.publish(
      createEvent("task:progress", runId, {
        context,
        taskId: "taint-iris",
        outputKind: "findings",
        progress: {
          ruleId: "taint.sql",
          filePath: "src/app.ts",
          startLine: 42,
        },
      }),
    );
    await bus.publish(
      createEvent("task:progress", runId, {
        context,
        taskId: "taint-iris",
        outputKind: "findings",
        progress: {
          ruleId: "taint.sql.duplicate",
          filePath: "src/app.ts",
          startLine: 42,
        },
      }),
    );
    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 2,
      }),
    );
    await bus.publish(
      createEvent("report:requested", runId, {
        context,
        reportMode: "full",
        stats: {
          tasks: ["taint-cwe-select", "taint-iris"],
          totalFindings: 1,
          queuedForTriage: 0,
          skippedAlreadyTriaged: 0,
          triaged: 0,
          triageErrors: 0,
          totalCostUsd: 0.12,
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
        },
      }),
    );

    const state = store.getState();
    expect(state.mode).toBe("shell");
    expect(state.shell?.shellView).toBe("module-run");
    expect(state.shell?.commandHistory).toEqual(["use taint-iris", "run"]);
    expect(state.shell?.moduleRun?.runId).toBe(runId);
    expect(state.shell?.moduleRun?.activeTaskLabel).toBeUndefined();
    expect(state.shell?.moduleRun?.status).toBe("done");
    expect(state.shell?.moduleRun?.postProcessMode).toBe("scan-only");
    expect(state.shell?.moduleRun?.completedAtMs).toEqual(expect.any(Number));
    expect(state.shell?.moduleRun?.findingCount).toBe(1);
    expect(state.shell?.moduleRun?.costUsd).toBe(0.12);
    expect(state.shell?.moduleRun?.steps.find((step) => step.id === "taint-iris")?.count).toBe(
      "1 finding",
    );
    expect(state.shell?.moduleRun?.steps.find((step) => step.id === "report")?.count).toBe(
      "1 finding",
    );
    expect(state.shell?.moduleRun?.steps.map((step) => [step.id, step.status])).toEqual([
      ["taint-cwe-select", "done"],
      ["taint-iris", "done"],
      ["report", "done"],
    ]);

    await bus.close();
    db.close();
  });

  it("does not surface fatal pipeline errors through the transient notice rail in shell mode", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const store = createUIStore();
    store.update({
      mode: "running",
      shell: {
        modules: ["sast"],
        tools: ["sast:scan"],
        focusedModule: "sast",
        shellView: "module",
        openFindingId: null,
        target: "/tmp/repo",
        workspace: "acme",
        history: [],
        commandHistory: ["scan ."],
        moduleOptions: {},
        processing: true,
      },
    });

    const config: KuzushiConfig = {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: ["semgrep"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: { semgrep: {} },
    };

    registerReportWorker(bus, { db, config }, store);

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    await bus.publish(
      createEvent("pipeline:error", runId, {
        context,
        error: "FOREIGN KEY constraint failed",
        fatal: true,
      }),
    );

    expect(store.getState().notices.some((notice) => notice.message === "Pipeline failed")).toBe(
      false,
    );

    await bus.close();
    db.close();
  });

  it("inline runs without module-run state stay in shell mode and publish task activity", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const store = createUIStore();
    store.update({
      mode: "shell",
      shell: {
        modules: ["carlini-threat-hunt"],
        tools: ["carlini-threat-hunt:run"],
        focusedModule: "carlini-threat-hunt",
        shellView: "module",
        openFindingId: null,
        target: "/tmp/repo",
        workspace: "acme",
        history: [],
        commandHistory: [],
        moduleOptions: {},
        processing: true,
      },
    });

    const config: KuzushiConfig = {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: ["carlini-threat-hunt"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: { "carlini-threat-hunt": {} },
    };

    registerReportWorker(bus, { db, config }, store);

    const activityEvents: Array<{ taskId: string; description: string }> = [];
    bus.subscribe("task:activity", (event) => {
      activityEvents.push({
        taskId: event.payload.taskId,
        description: event.payload.description,
      });
    });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
      postProcessMode: "scan-only" as const,
      inline: true,
    };

    await bus.publish(
      createEvent("pipeline:start", runId, {
        context,
        config,
        scanOpts: {
          severity: ["ERROR"],
          excludePatterns: [],
          tasks: ["carlini-threat-hunt"],
          fresh: false,
        },
      }),
    );

    expect(store.getState().stages).toEqual([]);
    expect(store.getState().mode).toBe("shell");
    expect(store.getState().shell?.shellView).toBe("module");

    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "carlini-threat-hunt",
        outputKind: "findings",
        input: null,
        upstreamOutputs: new Map(),
      }),
    );

    expect(activityEvents).toContainEqual({
      taskId: "carlini-threat-hunt",
      description: "analyzing threats from attack surface",
    });

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 0,
        durationMs: 1000,
      }),
    );
    await bus.publish(
      createEvent("report:requested", runId, {
        context,
        reportMode: "full",
      }),
    );

    expect(store.getState().mode).toBe("shell");
    expect(store.getState().summary).toBeFalsy();
    expect(store.getState().stages).toEqual([]);

    await bus.close();
    db.close();
  });

  it("labels carlini-threat-hunt start with 'analyzing threats from attack surface' instead of 'initializing'", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const store = createUIStore();

    const config: KuzushiConfig = {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: ["carlini-threat-hunt"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: { "carlini-threat-hunt": {} },
    };

    registerReportWorker(bus, { db, config }, store);

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
        scanOpts: {
          severity: ["ERROR"],
          excludePatterns: [],
          tasks: ["carlini-threat-hunt"],
          fresh: false,
        },
      }),
    );
    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "carlini-threat-hunt",
        outputKind: "findings",
        input: null,
        upstreamOutputs: new Map(),
      }),
    );

    const scanStage = store.getState().stages.find((stage) => stage.id === "scan");
    const carliniThreatHuntTask = scanStage?.subTasks.find(
      (task) => task.id === "carlini-threat-hunt",
    );
    expect(carliniThreatHuntTask?.detail).toBe("analyzing threats from attack surface");
    expect(carliniThreatHuntTask?.detail).not.toBe("initializing");

    await bus.close();
    db.close();
  });

  it("uses 'preparing task' for unknown task start detail", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const store = createUIStore();

    const config: KuzushiConfig = {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: ["custom-task"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: { "custom-task": {} },
    };

    registerReportWorker(bus, { db, config }, store);

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
        scanOpts: {
          severity: ["ERROR"],
          excludePatterns: [],
          tasks: ["custom-task"],
          fresh: false,
        },
      }),
    );
    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "custom-task",
        outputKind: "findings",
        input: null,
        upstreamOutputs: new Map(),
      }),
    );

    const scanStage = store.getState().stages.find((stage) => stage.id === "scan");
    const customTask = scanStage?.subTasks.find((task) => task.id === "custom-task");
    expect(customTask?.detail).toBe("preparing task");

    await bus.close();
    db.close();
  });
});
