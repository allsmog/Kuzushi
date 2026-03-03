import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { initDb, updateVerificationCost, upsertFinding } from "../src/store.js";
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

  it("prints retry suffix when attempts > 1", () => {
    printTriageProgress(makeResult("x", "tp"), 2, 10, 3);
    const output = (console.log as unknown as { mock: { calls: Array<Array<unknown>> } }).mock.calls
      .map((call) => String(call[0] ?? ""))
      .join("\n");
    expect(output).toContain("retry #3");
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

  it("shows verification cost section when only verification errors were persisted", () => {
    const dbPath = path.join(TMP_DIR, `summary-verify-cost-${Date.now()}.sqlite3`);
    const db = initDb(dbPath);

    upsertFinding(db, makeFinding("verify-cost-only"), makeResult("verify-cost-only", "tp"), "repo", "HEAD");
    updateVerificationCost(db, "verify-cost-only", 0.022);

    printSummary(db, "repo");

    const output = (console.log as unknown as { mock: { calls: Array<Array<unknown>> } }).mock.calls
      .map((call) => String(call[0] ?? ""))
      .join("\n");

    expect(output).toContain("Verification:");
    expect(output).toContain("Total verification cost");
    db.close();
  });

  it("prints skipped low confidence stat when provided", () => {
    const dbPath = path.join(TMP_DIR, `summary-skip-low-${Date.now()}.sqlite3`);
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("a"), makeResult("a", "tp"), "repo", "HEAD");

    printSummary(db, "repo", {
      stats: { skippedLowConfidence: 2 },
    });

    const output = (console.log as unknown as { mock: { calls: Array<Array<unknown>> } }).mock.calls
      .map((call) => String(call[0] ?? ""))
      .join("\n");
    expect(output).toContain("Skipped (low confidence)");
    db.close();
  });

  it("prints triage and verification error counts from pipeline stats", () => {
    const dbPath = path.join(TMP_DIR, `summary-error-counts-${Date.now()}.sqlite3`);
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("a"), makeResult("a", "tp"), "repo", "HEAD");

    printSummary(db, "repo", {
      stats: {
        triageErrors: 2,
        verifyErrors: 3,
      },
    });

    const output = (console.log as unknown as { mock: { calls: Array<Array<unknown>> } }).mock.calls
      .map((call) => String(call[0] ?? ""))
      .join("\n");
    expect(output).toContain("Triage errors");
    expect(output).toContain("Verification errors");
    db.close();
  });

  it("scopes report to fingerprints when provided", () => {
    const dbPath = path.join(TMP_DIR, `summary-fp-filter-${Date.now()}.sqlite3`);
    const db = initDb(dbPath);

    upsertFinding(db, makeFinding("current-1"), makeResult("current-1", "tp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("current-2"), makeResult("current-2", "needs_review"), "repo", "HEAD");
    upsertFinding(db, makeFinding("stale-1"), makeResult("stale-1", "tp"), "repo", "HEAD");

    printSummary(db, "repo", {
      fingerprints: ["current-1", "current-2"],
    });

    const output = (console.log as unknown as { mock: { calls: Array<Array<unknown>> } }).mock.calls
      .map((call) => String(call[0] ?? ""))
      .join("\n");

    expect(output).toContain("Total triaged:");
    expect(output).toContain("2");
    expect(output).not.toContain("3");
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
