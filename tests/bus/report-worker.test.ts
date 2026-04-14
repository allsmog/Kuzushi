import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerReportWorker } from "../../src/bus/workers/report-worker.js";
import { initDb } from "../../src/store.js";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import type { Finding } from "../../src/scanners/types.js";
import type { KuzushiConfig, TriageResult } from "../../src/types.js";
import type { ReportCompleteEvent } from "../../src/bus/events.js";

function makeFinding(fp: string): Finding {
  return {
    taskId: "semgrep",
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
    score: 54,
  };
}

function makeResult(fp: string): TriageResult {
  return {
    fingerprint: fp,
    verdict: "tp",
    confidence: 0.92,
    rationale: "confirmed",
    verificationSteps: ["step"],
    fixPatch: null,
  };
}

beforeEach(() => {
  vi.spyOn(console, "log").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("report-worker", () => {
  it("prints progress and emits report:complete", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const config: KuzushiConfig = {
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

    registerReportWorker(bus, { db, config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    await bus.publish(
      createEvent("scan:start", runId, {
        context,
        tasks: ["semgrep"],
        scanOpts: {
          severity: ["ERROR"],
          excludePatterns: [],
          fresh: false,
        },
      }),
    );

    await bus.publish(
      createEvent("scan:complete", runId, {
        context,
        totalFindings: 1,
      }),
    );

    await bus.publish(
      createEvent("triage:start", runId, {
        context,
        findingCount: 1,
        model: "anthropic:claude-sonnet-4-6",
      }),
    );

    await bus.publish(
      createEvent("triage:result", runId, {
        context,
        finding: makeFinding("fp-1"),
        result: makeResult("fp-1"),
        index: 1,
        total: 1,
      }),
    );

    await bus.publish(
      createEvent("triage:agent-activity", runId, {
        context,
        fingerprint: "fp-1",
        kind: "tool-start",
        toolName: "Read",
        toolInput: { file_path: "src/app.ts" },
        index: 1,
        total: 1,
      }),
    );

    const reportCompletePromise = bus.waitFor<ReportCompleteEvent>(
      "report:complete",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("report:requested", runId, {
        context,
        fingerprints: ["fp-1"],
      }),
    );

    await reportCompletePromise;

    expect(console.log).toHaveBeenCalled();
    expect(vi.mocked(console.log).mock.calls.some(
      (call) => call.some((arg) => String(arg).includes("Reading src/app.ts")),
    )).toBe(true);

    await bus.close();
    db.close();
  });

  it("does not label max-capped findings as already triaged", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const config: KuzushiConfig = {
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

    registerReportWorker(bus, { db, config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    await bus.publish(createEvent("scan:start", runId, {
      context,
      tasks: ["semgrep"],
      scanOpts: {
        severity: ["ERROR"],
        excludePatterns: [],
        fresh: false,
      },
    }));
    await bus.publish(createEvent("scan:complete", runId, { context, totalFindings: 5 }));
    await bus.publish(createEvent("triage:start", runId, {
      context,
      findingCount: 1,
      model: "anthropic:claude-sonnet-4-6",
      skippedAlreadyTriaged: 0,
    }));

    const output = vi.mocked(console.log).mock.calls.flat().join("\n");
    expect(output).not.toContain("already-triaged");

    await bus.close();
    db.close();
  });

  it("suppresses final report output for child module runs", async () => {
    const tempDir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-report-"));
    tempDirs.push(tempDir);
    const reportPath = path.join(tempDir, "report.md");

    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const config: KuzushiConfig = {
      model: "anthropic:claude-sonnet-4-6",
      busBackend: "in-process",
      triageBatchSize: 15,
      triageConcurrency: 1,
      scanMode: "sequential",
      tasks: ["semgrep"],
      severity: ["ERROR"],
      excludePatterns: [],
      reportOutput: reportPath,
      taskConfig: { semgrep: {} },
    };

    registerReportWorker(bus, { db, config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/monorepo",
      scanPath: "/tmp/monorepo/services/auth",
      repoName: "monorepo/auth",
      dbPath: "/tmp/monorepo/.kuzushi/findings.sqlite3",
      reportMode: "suppress" as const,
    };

    const reportCompletePromise = bus.waitFor<ReportCompleteEvent>(
      "report:complete",
      (event) => event.meta.runId === runId,
    );

    vi.mocked(console.log).mockClear();

    await bus.publish(
      createEvent("report:requested", runId, {
        context,
        reportMode: "suppress",
      }),
    );

    await reportCompletePromise;

    expect(existsSync(reportPath)).toBe(false);
    expect(console.log).not.toHaveBeenCalled();

    await bus.close();
    db.close();
  });

  it("prints resume info only for actually skipped triaged findings", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const config: KuzushiConfig = {
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

    registerReportWorker(bus, { db, config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    await bus.publish(createEvent("scan:start", runId, {
      context,
      tasks: ["semgrep"],
      scanOpts: {
        severity: ["ERROR"],
        excludePatterns: [],
        fresh: false,
      },
    }));
    await bus.publish(createEvent("scan:complete", runId, { context, totalFindings: 3 }));
    await bus.publish(createEvent("triage:start", runId, {
      context,
      findingCount: 1,
      model: "anthropic:claude-sonnet-4-6",
      skippedAlreadyTriaged: 2,
    }));

    const output = vi.mocked(console.log).mock.calls.flat().join("\n");
    expect(output).toContain("Skipping 2 already-triaged findings, 1 remaining");

    await bus.close();
    db.close();
  });

  it("prints skipped poc harness results without parse-error suffix", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const config: KuzushiConfig = {
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

    registerReportWorker(bus, { db, config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    await bus.publish(
      createEvent("poc-harness:result", runId, {
        context,
        finding: makeFinding("fp-poc-skip"),
        triageResult: makeResult("fp-poc-skip"),
        verificationResult: {
          fingerprint: "fp-poc-skip",
          exploitable: true,
          pocPayload: "' OR 1=1 --",
          pocDescription: "inject",
          attackVector: "query",
          preconditions: [],
          confidence: 0.8,
        },
        result: {
          fingerprint: "fp-poc-skip",
          scriptPath: null,
          language: "typescript",
          scriptContent: null,
          parsed: false,
          parseError: null,
          skipped: true,
          skipReason: "cannot isolate",
          costUsd: 0.01,
        },
        index: 1,
        total: 1,
      }),
    );

    const output = vi.mocked(console.log).mock.calls
      .map((call) => call.map((arg) => String(arg)).join(" "))
      .join("\n");
    expect(output).toContain("SKIPPED");
    expect(output).not.toContain("parse-error");

    await bus.close();
    db.close();
  });

  it("prints triage/verification/poc error progress lines", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const config: KuzushiConfig = {
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

    registerReportWorker(bus, { db, config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    await bus.publish(
      createEvent("triage:error", runId, {
        context,
        finding: makeFinding("fp-triage-error"),
        error: "triage failed",
        index: 1,
        total: 1,
      }),
    );

    await bus.publish(
      createEvent("verification:error", runId, {
        context,
        finding: makeFinding("fp-verify-error"),
        triageResult: makeResult("fp-verify-error"),
        error: "verification failed",
        index: 1,
        total: 1,
      }),
    );

    await bus.publish(
      createEvent("poc-harness:error", runId, {
        context,
        finding: makeFinding("fp-poc-error"),
        triageResult: makeResult("fp-poc-error"),
        verificationResult: {
          fingerprint: "fp-poc-error",
          exploitable: true,
          pocPayload: "payload",
          pocDescription: "desc",
          attackVector: null,
          preconditions: [],
          confidence: 0.8,
        },
        error: "poc failed",
        index: 1,
        total: 1,
      }),
    );

    const output = vi.mocked(console.log).mock.calls
      .map((call) => call.map((arg) => String(arg)).join(" "))
      .join("\n");

    expect(output).toContain("TRIAGE ERROR");
    expect(output).toContain("VERIFY ERROR");
    expect(output).toContain("POC ERROR");

    await bus.close();
    db.close();
  });
});
