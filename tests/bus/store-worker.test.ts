import { describe, expect, it } from "vitest";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import type { BusHandlerErrorEvent, StoreUpsertedEvent } from "../../src/bus/events.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerStoreWorker } from "../../src/bus/workers/store-worker.js";
import type { Finding } from "../../src/scanners/types.js";
import { getVerdictCounts, initDb } from "../../src/store.js";
import type { TriageResult } from "../../src/types.js";

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
    confidence: 0.91,
    rationale: "real",
    verificationSteps: ["step 1"],
    fixPatch: null,
  };
}

describe("store-worker", () => {
  it("upserts triage results and emits store:upserted", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    const store = registerStoreWorker(bus, { db });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const upserted = bus.waitFor<StoreUpsertedEvent>(
      "store:upserted",
      (event) => event.meta.runId === runId,
    );

    await bus.publish(
      createEvent("triage:result", runId, {
        context,
        finding: makeFinding("fp-1"),
        result: makeResult("fp-1"),
        costUsd: 0.055,
        index: 1,
        total: 1,
      }),
    );

    const event = await upserted;
    expect(event.payload.verdict).toBe("tp");

    // Flush the batched upsert queue before reading back from the DB.
    store.flush();

    const counts = getVerdictCounts(db, "repo");
    expect(counts.tp).toBe(1);

    const row = db
      .prepare("SELECT triage_cost_usd as triageCostUsd FROM findings WHERE fingerprint = ?")
      .get("fp-1") as { triageCostUsd: number };
    expect(row.triageCostUsd).toBeCloseTo(0.055, 8);

    await bus.close();
    db.close();
  });

  it("persists verification cost from verification:error events", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    registerStoreWorker(bus, { db });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const finding = makeFinding("fp-verify-error");
    const triageResult = makeResult("fp-verify-error");

    await bus.publish(
      createEvent("triage:result", runId, {
        context,
        finding,
        result: triageResult,
        index: 1,
        total: 1,
      }),
    );

    await bus.publish(
      createEvent("verification:error", runId, {
        context,
        finding,
        triageResult,
        error: "verification agent failed",
        costUsd: 0.031,
        index: 1,
        total: 1,
      }),
    );

    const row = db
      .prepare("SELECT verify_cost_usd as verifyCostUsd FROM findings WHERE fingerprint = ?")
      .get("fp-verify-error") as { verifyCostUsd: number | null };
    expect(row.verifyCostUsd).toBeCloseTo(0.031, 8);

    await bus.close();
    db.close();
  });

  it("persists poc harness result fields and error cost", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    registerStoreWorker(bus, { db });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    const finding = makeFinding("fp-poc-store");
    const triageResult = makeResult("fp-poc-store");

    await bus.publish(
      createEvent("triage:result", runId, {
        context,
        finding,
        result: triageResult,
        index: 1,
        total: 1,
      }),
    );

    await bus.publish(
      createEvent("poc-harness:result", runId, {
        context,
        finding,
        triageResult,
        verificationResult: {
          fingerprint: finding.fingerprint,
          exploitable: true,
          pocPayload: "' OR 1=1 --",
          pocDescription: "inject",
          attackVector: "http",
          preconditions: [],
          confidence: 0.88,
        },
        result: {
          fingerprint: finding.fingerprint,
          scriptPath: "/tmp/repo/.kuzushi/poc/fp-poc-store-cwe79.ts",
          language: "typescript",
          scriptContent: "console.log('PASS')",
          parsed: true,
          parseError: null,
          skipped: false,
          skipReason: null,
        },
        costUsd: 0.012,
        index: 1,
        total: 1,
      }),
    );

    await bus.publish(
      createEvent("poc-harness:error", runId, {
        context,
        finding,
        triageResult,
        verificationResult: {
          fingerprint: finding.fingerprint,
          exploitable: true,
          pocPayload: "' OR 1=1 --",
          pocDescription: "inject",
          attackVector: "http",
          preconditions: [],
          confidence: 0.88,
        },
        error: "generator crashed",
        costUsd: 0.02,
        index: 1,
        total: 1,
      }),
    );

    const row = db
      .prepare(`
      SELECT
        poc_harness_path as pocHarnessPath,
        poc_harness_parsed as pocHarnessParsed,
        poc_harness_cost_usd as pocHarnessCostUsd
      FROM findings
      WHERE fingerprint = ?
    `)
      .get("fp-poc-store") as {
      pocHarnessPath: string | null;
      pocHarnessParsed: number | null;
      pocHarnessCostUsd: number | null;
    };

    expect(row.pocHarnessPath).toContain(".kuzushi/poc");
    expect(row.pocHarnessParsed).toBe(1);
    expect(row.pocHarnessCostUsd).toBeCloseTo(0.02, 8);

    await bus.close();
    db.close();
  });

  it("persists triage assertions even when the finding upsert is still queued", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    registerStoreWorker(bus, { db });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    // Seed a pipeline_runs row so the run_id FK is satisfied.
    db.prepare(`
      INSERT INTO pipeline_runs (run_id, repo, started_at, status, config_json, scan_opts_json)
      VALUES (?, ?, datetime('now'), 'triaging', '{}', '{}')
    `).run(runId, "repo");

    const finding = makeFinding("fp-assert");
    const result = makeResult("fp-assert");

    await bus.publish(
      createEvent("triage:result", runId, {
        context,
        finding,
        result,
        index: 1,
        total: 1,
      }),
    );

    // Assertions fire immediately after triage:result for the same finding,
    // before the upsert queue's 50-entry batch threshold is reached. The
    // handler must flush the queue so the FK on finding_assertions.fingerprint
    // resolves.
    await bus.publish(
      createEvent("triage:assertions", runId, {
        context,
        fingerprint: finding.fingerprint,
        assertions: [{ name: "verdict_present", passed: true, score: 1, weight: 1, reason: "ok" }],
        qualityScore: 1,
      }),
    );

    const row = db
      .prepare(
        "SELECT assertion_name as name FROM finding_assertions WHERE run_id = ? AND fingerprint = ?",
      )
      .get(runId, "fp-assert") as { name: string } | undefined;
    expect(row?.name).toBe("verdict_present");

    await bus.close();
    db.close();
  });

  it("swallows triage:assertions FK failures so the pipeline survives (#54)", async () => {
    // Regression for the e2e smoke harness FK fault: when the
    // pipeline_runs row is absent (or the upsert flush hits any other
    // FK / DB error), the handler must NOT surface a bus:handler-error.
    // Triage assertions are informational quality scoring; a DB error
    // here must never tear down the run.
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    registerStoreWorker(bus, { db });

    const runId = generateRunId();
    const context = {
      runId,
      repoRoot: "/tmp/repo",
      repoName: "repo",
      dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
    };

    // Intentionally do NOT seed pipeline_runs — saveAssertionResults will
    // hit `FOREIGN KEY constraint failed` on the run_id FK.
    db.prepare(`
      INSERT INTO findings (
        fingerprint, task_id, repo, ref, rule_id, file_path, start_line,
        severity, message, verdict, confidence, rationale, verification_steps
      ) VALUES (?, 'semgrep', 'repo', 'HEAD', 'r', 'f.ts', 1, 'ERROR', 'm',
                'tp', 1, 'r', '[]')
    `).run("fp-orphan");

    const handlerError = bus
      .waitFor<BusHandlerErrorEvent>(
        "bus:handler-error",
        (event) => event.meta.runId === runId,
        300,
      )
      .catch((err: Error) => ({ timedOut: true, message: err.message }));

    await bus.publish(
      createEvent("triage:assertions", runId, {
        context,
        fingerprint: "fp-orphan",
        assertions: [{ name: "verdict_present", passed: true, score: 1, weight: 1, reason: "ok" }],
        qualityScore: 1,
      }),
    );

    const result = await handlerError;
    expect((result as { timedOut?: boolean }).timedOut).toBe(true);

    await bus.close();
    db.close();
  });

  it("rejects invalid run status values before persistence", async () => {
    const bus = new InProcessBus();
    const db = initDb(":memory:");

    registerStoreWorker(bus, { db });

    const runId = generateRunId();
    const handlerError = bus.waitFor<BusHandlerErrorEvent>(
      "bus:handler-error",
      (event) => event.meta.runId === runId,
      1_000,
    );

    await bus.publish(
      createEvent("run:status", runId, {
        context: {
          runId,
          repoRoot: "/tmp/repo",
          repoName: "repo",
          dbPath: "/tmp/repo/.kuzushi/findings.sqlite3",
        },
        status: "not-a-status",
      } as never),
    );

    const event = await handlerError;
    expect(event.payload.error).toContain("Invalid run status");

    await bus.close();
    db.close();
  });
});
