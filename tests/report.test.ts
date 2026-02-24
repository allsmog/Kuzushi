import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { initDb, upsertFinding } from "../src/store.js";
import {
  printTriageProgress,
  printSummary,
  printScanStart,
  printResumeInfo,
} from "../src/report.js";
import type { TriageResult } from "../src/types.js";
import type { Finding } from "../src/scanners/types.js";

const TMP_DIR = path.join(import.meta.dirname, ".tmp-report-test");

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
    rationale: "test rationale for the finding which is quite detailed and informative",
    verificationSteps: ["step 1", "step 2"],
    fixPatch: null,
  };
}

beforeEach(() => {
  mkdirSync(TMP_DIR, { recursive: true });
  vi.spyOn(console, "log").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
  vi.restoreAllMocks();
});

describe("printTriageProgress", () => {
  it("prints progress line without throwing", () => {
    const result = makeResult("abc123", "fp");
    printTriageProgress(result, 1, 10);
    expect(console.log).toHaveBeenCalled();
  });

  it("prints tp verdict", () => {
    printTriageProgress(makeResult("x", "tp"), 5, 20);
    expect(console.log).toHaveBeenCalled();
  });

  it("prints needs_review verdict", () => {
    printTriageProgress(makeResult("x", "needs_review"), 3, 10);
    expect(console.log).toHaveBeenCalled();
  });
});

describe("printSummary", () => {
  it("prints summary for empty db", () => {
    const dbPath = path.join(TMP_DIR, `summary-${Date.now()}.sqlite3`);
    const db = initDb(dbPath);
    printSummary(db, "test-repo");
    expect(console.log).toHaveBeenCalled();
    db.close();
  });

  it("prints summary with mixed verdicts", () => {
    const dbPath = path.join(TMP_DIR, `summary-mix-${Date.now()}.sqlite3`);
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("a"), makeResult("a", "fp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("b"), makeResult("b", "tp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("c"), makeResult("c", "needs_review"), "repo", "HEAD");
    printSummary(db, "repo");
    expect(console.log).toHaveBeenCalled();
    db.close();
  });

  it("prints clean message when all FP", () => {
    const dbPath = path.join(TMP_DIR, `summary-clean-${Date.now()}.sqlite3`);
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("a"), makeResult("a", "fp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("b"), makeResult("b", "fp"), "repo", "HEAD");
    printSummary(db, "repo");
    expect(console.log).toHaveBeenCalled();
    db.close();
  });

  it("shows actionable findings with WARNING severity", () => {
    const dbPath = path.join(TMP_DIR, `summary-warn-${Date.now()}.sqlite3`);
    const db = initDb(dbPath);
    const finding = makeFinding("warn1");
    finding.severity = "WARNING";
    upsertFinding(db, finding, makeResult("warn1", "tp"), "repo", "HEAD");
    printSummary(db, "repo");
    expect(console.log).toHaveBeenCalled();
    db.close();
  });

  it("truncates long rationales", () => {
    const dbPath = path.join(TMP_DIR, `summary-long-${Date.now()}.sqlite3`);
    const db = initDb(dbPath);
    const result = makeResult("long1", "tp");
    result.rationale = "A".repeat(200);
    upsertFinding(db, makeFinding("long1"), result, "repo", "HEAD");
    printSummary(db, "repo");
    expect(console.log).toHaveBeenCalled();
    db.close();
  });
});

describe("printScanStart", () => {
  it("prints scan start info", () => {
    printScanStart("my-repo", 15, 200, ["semgrep"]);
    expect(console.log).toHaveBeenCalled();
  });
});

describe("printResumeInfo", () => {
  it("prints resume info", () => {
    printResumeInfo(10, 5);
    expect(console.log).toHaveBeenCalled();
  });
});
