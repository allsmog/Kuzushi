import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import {
  initDb,
  upsertFinding,
  getActionableFindings,
  updateFindingMetadata,
} from "../src/store.js";
import type { TriageResult } from "../src/types.js";
import type { Finding, TaintPathStep, EngineProvenance, ProofState } from "../src/scanners/types.js";
import { summarizeTaintPath, formatTaintPathForPrompt, formatTaintPathForDisplay } from "../src/findings/taint-path.js";

const TMP_DIR = path.join(import.meta.dirname, ".tmp-evidence-test");
let dbPath: string;

const SAMPLE_TAINT_PATH: TaintPathStep[] = [
  { filePath: "src/routes/api.ts", line: 42, message: "user input from req.query.url", snippet: "const url = req.query.url;" },
  { filePath: "src/services/fetcher.ts", line: 15, message: "passed to HTTP client", snippet: "return fetch(url);" },
  { filePath: "src/services/fetcher.ts", line: 28, message: "response consumed without validation" },
];

const SAMPLE_PROVENANCE: EngineProvenance[] = [
  { kind: "taint-analysis", detail: "cross-function dataflow pass 3" },
  { kind: "codeql", detail: "js/ssrf-from-request" },
];

const SAMPLE_PROOF_STATE: ProofState = "execution_confirmed";

function makeFinding(fp: string): Finding {
  return {
    scanner: "agentic",
    fingerprint: fp,
    ruleId: "ssrf-detect",
    filePath: "src/routes/api.ts",
    startLine: 42,
    severity: "ERROR",
    message: "SSRF via user-controlled URL",
    scannerConfidence: "HIGH",
    subcategory: ["vuln"],
    likelihood: "HIGH",
    impact: "HIGH",
    cwe: ["CWE-918"],
    score: 85,
    taintPath: SAMPLE_TAINT_PATH,
    proofState: SAMPLE_PROOF_STATE,
    engineProvenance: SAMPLE_PROVENANCE,
  };
}

function makeResult(fp: string): TriageResult {
  return {
    fingerprint: fp,
    verdict: "tp",
    confidence: 0.92,
    rationale: "Confirmed SSRF via user-controlled URL to fetch()",
    verificationSteps: ["trace req.query.url to fetch() call"],
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

describe("structured evidence round-trip", () => {
  it("taintPath, proofState, and engineProvenance survive upsert → load", () => {
    const db = initDb(dbPath);
    const finding = makeFinding("fp-evidence-rt");
    upsertFinding(db, finding, makeResult("fp-evidence-rt"), "repo", "HEAD");

    const loaded = getActionableFindings(db, "repo", { includeFalsePositives: true });
    expect(loaded).toHaveLength(1);
    const f = loaded[0];

    // taintPath
    expect(f.taintPath).toHaveLength(3);
    expect(f.taintPath![0]).toEqual(expect.objectContaining({
      filePath: "src/routes/api.ts",
      line: 42,
      message: "user input from req.query.url",
    }));
    expect(f.taintPath![1].snippet).toBe("return fetch(url);");

    // proofState
    expect(f.proofState).toBe("execution_confirmed");

    // engineProvenance
    expect(f.engineProvenance).toHaveLength(2);
    expect(f.engineProvenance![0]).toEqual({ kind: "taint-analysis", detail: "cross-function dataflow pass 3" });
    expect(f.engineProvenance![1]).toEqual({ kind: "codeql", detail: "js/ssrf-from-request" });

    db.close();
  });

  it("null/undefined structured fields round-trip as undefined", () => {
    const db = initDb(dbPath);
    const finding: Finding = {
      scanner: "semgrep",
      fingerprint: "fp-no-evidence",
      ruleId: "test.rule",
      filePath: "src/test.ts",
      startLine: 10,
      severity: "WARNING",
      message: "test",
      scannerConfidence: "LOW",
      subcategory: ["vuln"],
      likelihood: "LOW",
      impact: "LOW",
      cwe: ["CWE-79"],
      score: 30,
      // no taintPath, proofState, engineProvenance
    };
    upsertFinding(db, finding, makeResult("fp-no-evidence"), "repo", "HEAD");

    const loaded = getActionableFindings(db, "repo", { includeFalsePositives: true });
    const f = loaded.find(r => r.fingerprint === "fp-no-evidence")!;
    expect(f.taintPath).toBeUndefined();
    expect(f.proofState).toBeUndefined();
    expect(f.engineProvenance).toBeUndefined();

    db.close();
  });

  it("findingMetadata survives updateFindingMetadata → load", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("fp-meta-rt"), makeResult("fp-meta-rt"), "repo", "HEAD");

    updateFindingMetadata(db, "fp-meta-rt", {
      latestDynamicRunId: "dyn-42",
      dynamicRunIds: ["dyn-42"],
      latestDynamicStatus: "confirmed",
      notes: ["auto-confirmed via dynamic analysis"],
    });

    const loaded = getActionableFindings(db, "repo", { includeFalsePositives: true });
    const f = loaded.find(r => r.fingerprint === "fp-meta-rt")!;
    expect(f.findingMetadata).toBeDefined();
    expect(f.findingMetadata!.latestDynamicRunId).toBe("dyn-42");
    expect(f.findingMetadata!.latestDynamicStatus).toBe("confirmed");
    expect(f.findingMetadata!.notes).toEqual(["auto-confirmed via dynamic analysis"]);

    db.close();
  });
});

describe("taint-path rendering utilities", () => {
  it("summarizeTaintPath produces arrow-delimited summary", () => {
    const summary = summarizeTaintPath(SAMPLE_TAINT_PATH);
    expect(summary).toBe("src/routes/api.ts:42 -> src/services/fetcher.ts:15 -> src/services/fetcher.ts:28");
  });

  it("summarizeTaintPath truncates beyond maxSteps", () => {
    const summary = summarizeTaintPath(SAMPLE_TAINT_PATH, 2);
    expect(summary).toBe("src/routes/api.ts:42 -> src/services/fetcher.ts:15 -> +1 more");
  });

  it("summarizeTaintPath returns undefined for empty path", () => {
    expect(summarizeTaintPath(undefined)).toBeUndefined();
    expect(summarizeTaintPath([])).toBeUndefined();
  });

  it("formatTaintPathForPrompt includes all steps with code snippets", () => {
    const prompt = formatTaintPathForPrompt(SAMPLE_TAINT_PATH);
    expect(prompt).toContain("## Full Taint Flow Path");
    expect(prompt).toContain("Step 1: src/routes/api.ts:42 - user input from req.query.url");
    expect(prompt).toContain("Code: const url = req.query.url;");
    expect(prompt).toContain("Step 2: src/services/fetcher.ts:15");
    expect(prompt).toContain("Step 3: src/services/fetcher.ts:28");
  });

  it("formatTaintPathForDisplay returns numbered list", () => {
    const lines = formatTaintPathForDisplay(SAMPLE_TAINT_PATH);
    expect(lines).toHaveLength(3);
    expect(lines[0]).toContain("1. src/routes/api.ts:42");
    expect(lines[1]).toContain("2. src/services/fetcher.ts:15");
  });
});
