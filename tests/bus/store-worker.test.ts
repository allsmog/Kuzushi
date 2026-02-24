import { describe, expect, it } from "vitest";
import { InProcessBus } from "../../src/bus/adapters/in-process.js";
import { createEvent, generateRunId } from "../../src/bus/helpers.js";
import { registerStoreWorker } from "../../src/bus/workers/store-worker.js";
import { getVerdictCounts, initDb } from "../../src/store.js";
import type { Finding } from "../../src/scanners/types.js";
import type { TriageResult } from "../../src/types.js";
import type { StoreUpsertedEvent } from "../../src/bus/events.js";

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

    registerStoreWorker(bus, { db });

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
        index: 1,
        total: 1,
      }),
    );

    const event = await upserted;
    expect(event.payload.verdict).toBe("tp");

    const counts = getVerdictCounts(db, "repo");
    expect(counts.tp).toBe(1);

    await bus.close();
    db.close();
  });
});
