import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import {
  createRun,
  getLatestResumableRun,
  getRun,
  getTotalCost,
  initDb,
  getTriagedFingerprints,
  getVerdictCounts,
  getActionableFindings,
  updateRunCost,
  updateRunContext,
  updateRunFindings,
  updateRunStatus,
  upsertFinding,
} from "../src/store.js";
import type { KuzushiConfig, ScanOpts, TriageResult } from "../src/types.js";
import type { Finding } from "../src/scanners/types.js";

const TMP_DIR = path.join(import.meta.dirname, ".tmp-store-test");
let dbPath: string;

function makeFinding(fp: string): Finding {
  return {
    scanner: "semgrep",
    fingerprint: fp,
    ruleId: "test.rule",
    filePath: "src/test.ts",
    startLine: 10,
    severity: "ERROR",
    message: "test finding",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-79"],
    score: 54,
  };
}

function makeResult(fp: string, verdict: "tp" | "fp" | "needs_review" = "fp"): TriageResult {
  return {
    fingerprint: fp,
    verdict,
    confidence: 0.95,
    rationale: "test rationale",
    verificationSteps: ["step 1", "step 2"],
    fixPatch: null,
  };
}

function makeConfig(): KuzushiConfig {
  return {
    model: "claude-sonnet-4-20250514",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageConcurrency: 2,
    scanMode: "sequential",
    enabledTasks: [],
    scanners: ["semgrep"],
    severity: ["ERROR"],
    excludePatterns: ["node_modules"],
    scannerConfig: { semgrep: {} },
  };
}

function makeScanOpts(): ScanOpts {
  return {
    severity: ["ERROR"],
    excludePatterns: ["node_modules"],
    scanners: ["semgrep"],
    fresh: false,
  };
}

beforeEach(() => {
  mkdirSync(TMP_DIR, { recursive: true });
  dbPath = path.join(TMP_DIR, `test-${Date.now()}.sqlite3`);
});

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

describe("initDb", () => {
  it("creates database with findings table", () => {
    const db = initDb(dbPath);
    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table'")
      .all() as Array<{ name: string }>;
    expect(tables.map((t) => t.name)).toContain("findings");
    db.close();
  });

  it("is idempotent", () => {
    const db1 = initDb(dbPath);
    db1.close();
    const db2 = initDb(dbPath);
    db2.close();
  });

  it("migrates existing findings table to include triage_cost_usd", () => {
    const db = initDb(dbPath);
    db.exec("DROP TABLE findings");
    db.exec(`
      CREATE TABLE findings (
        fingerprint        TEXT PRIMARY KEY,
        scanner            TEXT NOT NULL DEFAULT 'semgrep',
        repo               TEXT NOT NULL,
        ref                TEXT NOT NULL,
        rule_id            TEXT NOT NULL,
        file_path          TEXT NOT NULL,
        start_line         INTEGER NOT NULL,
        severity           TEXT NOT NULL,
        message            TEXT NOT NULL,
        verdict            TEXT NOT NULL CHECK (verdict IN ('tp','fp','needs_review')),
        confidence         REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
        rationale          TEXT NOT NULL,
        verification_steps TEXT NOT NULL,
        fix_patch          TEXT,
        created_at         TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `);
    db.close();

    const migrated = initDb(dbPath);
    const columns = migrated.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    expect(columns.some((column) => column.name === "triage_cost_usd")).toBe(true);
    migrated.close();
  });
});

describe("upsertFinding", () => {
  it("inserts a new finding", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("fp1"), makeResult("fp1"), "repo", "HEAD");
    const rows = db.prepare("SELECT scanner, fingerprint FROM findings").all() as Array<{
      scanner: string;
      fingerprint: string;
    }>;
    expect(rows).toHaveLength(1);
    expect(rows[0].scanner).toBe("semgrep");
    db.close();
  });

  it("updates on conflict (same fingerprint)", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("fp1"), makeResult("fp1", "fp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("fp1"), makeResult("fp1", "tp"), "repo", "HEAD");
    const rows = db.prepare("SELECT verdict FROM findings").all() as Array<{
      verdict: string;
    }>;
    expect(rows).toHaveLength(1);
    expect(rows[0].verdict).toBe("tp");
    db.close();
  });
});

describe("getTriagedFingerprints", () => {
  it("returns empty set for empty db", () => {
    const db = initDb(dbPath);
    expect(getTriagedFingerprints(db).size).toBe(0);
    db.close();
  });

  it("returns fingerprints of existing findings", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("aaa"), makeResult("aaa"), "repo", "HEAD");
    upsertFinding(db, makeFinding("bbb"), makeResult("bbb"), "repo", "HEAD");
    const fps = getTriagedFingerprints(db);
    expect(fps.size).toBe(2);
    expect(fps.has("aaa")).toBe(true);
    expect(fps.has("bbb")).toBe(true);
    db.close();
  });
});

describe("getVerdictCounts", () => {
  it("returns zero counts for empty db", () => {
    const db = initDb(dbPath);
    const counts = getVerdictCounts(db);
    expect(counts).toEqual({ tp: 0, fp: 0, needs_review: 0 });
    db.close();
  });

  it("counts by verdict correctly", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("a"), makeResult("a", "fp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("b"), makeResult("b", "fp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("c"), makeResult("c", "tp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("d"), makeResult("d", "needs_review"), "repo", "HEAD");
    const counts = getVerdictCounts(db);
    expect(counts).toEqual({ tp: 1, fp: 2, needs_review: 1 });
    db.close();
  });

  it("filters by repo when provided", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("a"), makeResult("a", "tp"), "repo-a", "HEAD");
    upsertFinding(db, makeFinding("b"), makeResult("b", "fp"), "repo-b", "HEAD");
    const counts = getVerdictCounts(db, "repo-a");
    expect(counts).toEqual({ tp: 1, fp: 0, needs_review: 0 });
    db.close();
  });
});

describe("getTotalCost", () => {
  it("aggregates triage cost across findings", () => {
    const db = initDb(dbPath);
    const a = makeResult("a", "tp");
    const b = makeResult("b", "fp");
    a.triageCostUsd = 0.12;
    b.triageCostUsd = 0.03;
    upsertFinding(db, makeFinding("a"), a, "repo", "HEAD");
    upsertFinding(db, makeFinding("b"), b, "repo", "HEAD");
    expect(getTotalCost(db, "repo")).toBeCloseTo(0.15, 8);
    db.close();
  });

  it("returns zero when no costs exist", () => {
    const db = initDb(dbPath);
    expect(getTotalCost(db, "repo")).toBe(0);
    db.close();
  });
});

describe("getActionableFindings", () => {
  it("excludes FP findings", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("a"), makeResult("a", "fp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("b"), makeResult("b", "tp"), "repo", "HEAD");
    const actionable = getActionableFindings(db);
    expect(actionable).toHaveLength(1);
    expect(actionable[0].scanner).toBe("semgrep");
    expect(actionable[0].verdict).toBe("tp");
    db.close();
  });

  it("orders TP before needs_review", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("a"), makeResult("a", "needs_review"), "repo", "HEAD");
    upsertFinding(db, makeFinding("b"), makeResult("b", "tp"), "repo", "HEAD");
    const actionable = getActionableFindings(db);
    expect(actionable[0].verdict).toBe("tp");
    expect(actionable[1].verdict).toBe("needs_review");
    db.close();
  });
});

describe("pipeline_runs", () => {
  it("supports run lifecycle CRUD", () => {
    const db = initDb(dbPath);
    const runId = "run-1";
    const findings = [makeFinding("fp-a"), makeFinding("fp-b")];

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, runId, "triaging");
    updateRunFindings(db, runId, findings);
    updateRunCost(db, runId, 0.42);
    updateRunStatus(db, runId, "complete");

    const run = getRun(db, runId);
    expect(run).toBeDefined();
    expect(run?.repo).toBe("repo");
    expect(run?.status).toBe("complete");
    expect(run?.totalCostUsd).toBeCloseTo(0.42, 8);
    expect(run?.findingsJson).toBe(JSON.stringify(findings));
    expect(run?.completedAt).toBeTypeOf("string");
    db.close();
  });

  it("returns latest resumable run for a repo", () => {
    const db = initDb(dbPath);

    createRun(db, "run-old", "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, "run-old", "error");

    createRun(db, "run-complete", "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, "run-complete", "complete");

    expect(getLatestResumableRun(db, "repo")).toBeUndefined();

    createRun(db, "run-new", "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, "run-new", "triaging");

    const latest = getLatestResumableRun(db, "repo");
    expect(latest?.runId).toBe("run-new");
    expect(latest?.status).toBe("triaging");

    updateRunStatus(db, "run-new", "complete");
    updateRunStatus(db, "run-old", "complete");
    expect(getLatestResumableRun(db, "repo")).toBeUndefined();
    db.close();
  });

  it("persists and reloads context_json checkpoints", () => {
    const db = initDb(dbPath);
    const runId = "run-context";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunContext(db, runId, {
      languages: ["TypeScript"],
      frameworks: ["Express"],
      authPatterns: ["JWT"],
      sanitizationLibs: ["helmet"],
      ormOrDb: ["Prisma"],
      entryPoints: ["src/pages/api/*"],
    });

    const run = getRun(db, runId);
    expect(run?.contextJson).toContain("TypeScript");
    expect(run?.contextJson).toContain("Prisma");
    db.close();
  });
});
