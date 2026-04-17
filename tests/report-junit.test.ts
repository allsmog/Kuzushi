import { mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { generateJunitReport } from "../src/report-junit.js";
import type { Finding } from "../src/scanners/types.js";
import { initDb, upsertFinding } from "../src/store.js";
import type { TriageResult } from "../src/types.js";

const TMP_DIR = path.join(import.meta.dirname, ".tmp-junit-test");
let dbPath: string;

function makeFinding(fp: string, overrides: Partial<Finding> = {}): Finding {
  return {
    taskId: "semgrep",
    fingerprint: fp,
    ruleId: "sql-injection/raw",
    filePath: "src/db.ts",
    startLine: 42,
    severity: "ERROR",
    message: "Raw SQL concatenation",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-89"],
    score: 80,
    ...overrides,
  };
}

function makeTriage(fp: string, verdict: TriageResult["verdict"] = "tp"): TriageResult {
  return {
    fingerprint: fp,
    verdict,
    confidence: 0.9,
    rationale: "looks real",
    verificationSteps: ["step"],
    fixPatch: null,
  };
}

beforeEach(() => {
  mkdirSync(TMP_DIR, { recursive: true });
  dbPath = path.join(TMP_DIR, `junit-${Date.now()}.sqlite3`);
});

afterEach(() => {
  rmSync(TMP_DIR, { recursive: true, force: true });
});

describe("generateJunitReport", () => {
  it("emits a single empty testsuite when there are no findings", () => {
    const db = initDb(dbPath);
    const xml = generateJunitReport(db, { repo: "myrepo", stats: {}, runId: "run-1" });
    db.close();

    expect(xml).toContain('<?xml version="1.0"');
    expect(xml).toContain('<testsuites name="kuzushi"');
    expect(xml).toMatch(/tests="0"/);
    expect(xml).toContain('name="myrepo"');
  });

  it("emits <failure> for tp findings and <skipped> for by_design", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("fp-tp"), makeTriage("fp-tp", "tp"), "myrepo", "HEAD");
    upsertFinding(
      db,
      makeFinding("fp-design", { filePath: "src/by-design.ts", ruleId: "cli-exec" }),
      makeTriage("fp-design", "by_design"),
      "myrepo",
      "HEAD",
    );

    const xml = generateJunitReport(db, { repo: "myrepo", stats: {}, runId: "run-1" });
    db.close();

    expect(xml).toContain("<failure");
    expect(xml).toContain("<skipped");
    expect(xml).toContain("sql-injection/raw");
    // one failure + one skipped = two testcases, one failure tally
    expect(xml).toMatch(/tests="2"/);
    expect(xml).toMatch(/failures="1"/);
    expect(xml).toMatch(/skipped="1"/);
  });

  it("excludes false positives from the report entirely", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("fp-tp"), makeTriage("fp-tp", "tp"), "myrepo", "HEAD");
    upsertFinding(
      db,
      makeFinding("fp-fp", { filePath: "src/noise.ts" }),
      makeTriage("fp-fp", "fp"),
      "myrepo",
      "HEAD",
    );

    const xml = generateJunitReport(db, { repo: "myrepo", stats: {}, runId: "run-1" });
    db.close();

    expect(xml).toContain("fp-tp");
    expect(xml).not.toContain("src/noise.ts");
    expect(xml).toMatch(/tests="1"/);
  });

  it("escapes XML-unsafe characters in attributes and CDATA", () => {
    const db = initDb(dbPath);
    upsertFinding(
      db,
      makeFinding("fp-xml", { message: `quotes "x" & <tag>`, filePath: "src/<evil>.ts" }),
      makeTriage("fp-xml", "tp"),
      "myrepo",
      "HEAD",
    );

    const xml = generateJunitReport(db, { repo: "myrepo", stats: {}, runId: "run-1" });
    db.close();

    // Filename with `<` should be escaped in attributes.
    expect(xml).not.toMatch(/name="[^"]*<evil>/);
    expect(xml).toMatch(/&lt;evil&gt;/);
  });
});
