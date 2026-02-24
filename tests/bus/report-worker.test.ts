import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerReportWorker } from "../../src/bus/workers/report-worker.js";
import { initDb } from "../../src/store.js";
import type { Finding } from "../../src/scanners/types.js";
import type { TriageResult } from "../../src/types.js";
import type { ReportCompleteEvent } from "../../src/bus/events.js";

function makeFinding(fp: string): Finding {
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

describe("report-worker", () => {
  it("prints progress and emits report:complete", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    registerReportWorker(bus, { db });

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
        scanners: ["semgrep"],
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
        model: "claude-sonnet-4-20250514",
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
});
