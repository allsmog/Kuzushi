import { existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerAuditWorker } from "../../src/bus/workers/audit-worker.js";
import type { Finding } from "../../src/scanners/types.js";
import type { KuzushiConfig, TriageResult } from "../../src/types.js";

const TMP_ROOT = path.join(import.meta.dirname, "..", ".tmp-audit-worker");

function makeConfig(): KuzushiConfig {
  return {
    model: "anthropic:claude-sonnet-4-6",
    auditLog: true,
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

function makeFinding(): Finding {
  return {
    taskId: "semgrep",
    fingerprint: "fp-audit-1",
    ruleId: "test.rule",
    filePath: "src/app.ts",
    startLine: 11,
    severity: "ERROR",
    message: "test finding",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-79"],
    score: 77,
  };
}

function makeTriageResult(): TriageResult {
  return {
    fingerprint: "fp-audit-1",
    verdict: "tp",
    confidence: 0.9,
    rationale: "confirmed",
    verificationSteps: ["trace flow"],
    fixPatch: null,
  };
}

beforeEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
  mkdirSync(TMP_ROOT, { recursive: true });
});

afterEach(() => {
  rmSync(TMP_ROOT, { recursive: true, force: true });
});

describe("audit-worker", () => {
  it("writes per-run JSONL and metadata files", async () => {
    const bus = new InProcessBus();
    const config = makeConfig();
    registerAuditWorker(bus, { config });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: TMP_ROOT,
      repoName: "repo",
      dbPath: path.join(TMP_ROOT, ".kuzushi", "findings.sqlite3"),
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

    await bus.publish(
      createEvent("triage:agent-activity", runId, {
        context,
        fingerprint: "fp-audit-1",
        kind: "tool-start",
        toolName: "Read",
        toolInput: { path: "src/app.ts" },
        index: 1,
        total: 1,
      }),
    );

    await bus.publish(
      createEvent("triage:result", runId, {
        context,
        finding: makeFinding(),
        result: makeTriageResult(),
        attempts: 2,
        index: 1,
        total: 1,
      }),
    );

    await bus.publish(
      createEvent("verification:error", runId, {
        context,
        finding: makeFinding(),
        triageResult: makeTriageResult(),
        error: "verification failed",
        attempts: 3,
        index: 1,
        total: 1,
      }),
    );

    await bus.publish(
      createEvent("pipeline:complete", runId, {
        context,
        stats: {
          tasks: ["semgrep"],
          totalFindings: 1,
          queuedForTriage: 1,
          skippedAlreadyTriaged: 0,
          triaged: 1,
          triageErrors: 0,
          startedAt: new Date().toISOString(),
          completedAt: new Date().toISOString(),
        },
      }),
    );

    const runDir = path.join(TMP_ROOT, ".kuzushi", "runs", runId);
    const runFile = path.join(runDir, "run.json");
    const triageLog = path.join(runDir, "triage.jsonl");
    const verifyLog = path.join(runDir, "verify.jsonl");
    const statsFile = path.join(runDir, "stats.json");

    expect(existsSync(runFile)).toBe(true);
    expect(existsSync(triageLog)).toBe(true);
    expect(existsSync(verifyLog)).toBe(true);
    expect(existsSync(statsFile)).toBe(true);

    const triageContent = readFileSync(triageLog, "utf-8");
    const verifyContent = readFileSync(verifyLog, "utf-8");
    expect(triageContent).toContain("triage:agent-activity");
    expect(triageContent).toContain("triage:result");
    expect(verifyContent).toContain("verification:error");

    await bus.close();
  });
});
