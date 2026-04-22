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
    expect(scanStage?.detail).toContain("2 scanners");
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

  it("labels threat-hunt start with 'analyzing threats from attack surface' instead of 'initializing'", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");
    const store = createUIStore();

    const config: KuzushiConfig = {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 2,
      scanMode: "parallel",
      tasks: ["threat-hunt"],
      severity: ["ERROR"],
      excludePatterns: [],
      taskConfig: { "threat-hunt": {} },
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
          tasks: ["threat-hunt"],
          fresh: false,
        },
      }),
    );
    await bus.publish(
      createEvent("task:start", runId, {
        context,
        taskId: "threat-hunt",
        outputKind: "findings",
        input: null,
        upstreamOutputs: new Map(),
      }),
    );

    const scanStage = store.getState().stages.find((stage) => stage.id === "scan");
    const threatHuntTask = scanStage?.subTasks.find((task) => task.id === "threat-hunt");
    expect(threatHuntTask?.detail).toBe("analyzing threats from attack surface");
    expect(threatHuntTask?.detail).not.toBe("initializing");

    await bus.close();
    db.close();
  });
});
