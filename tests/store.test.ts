import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import {
  initDb,
  upsertFinding,
  getTriagedFingerprints,
  getVerdictCounts,
  getActionableFindings,
} from "../src/store.js";
import type { RawFinding, TriageResult } from "../src/types.js";

const TMP_DIR = path.join(import.meta.dirname, ".tmp-store-test");
let dbPath: string;

function makeFinding(fp: string): RawFinding {
  return {
    fingerprint: fp,
    ruleId: "test.rule",
    filePath: "src/test.ts",
    startLine: 10,
    severity: "ERROR",
    message: "test finding",
    semgrepConfidence: "HIGH",
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
    // No error = success
  });
});

describe("upsertFinding", () => {
  it("inserts a new finding", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("fp1"), makeResult("fp1"), "repo", "HEAD");
    const rows = db.prepare("SELECT * FROM findings").all();
    expect(rows).toHaveLength(1);
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

describe("getActionableFindings", () => {
  it("excludes FP findings", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("a"), makeResult("a", "fp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("b"), makeResult("b", "tp"), "repo", "HEAD");
    const actionable = getActionableFindings(db);
    expect(actionable).toHaveLength(1);
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
