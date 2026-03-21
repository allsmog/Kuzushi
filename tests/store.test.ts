import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdirSync, rmSync } from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import {
  createRun,
  deleteFindingsByFingerprints,
  getPocHarnessCounts,
  getLatestResumableRun,
  getRun,
  getStoredTriageResults,
  getTotalCost,
  getTotalPocHarnessCost,
  initDb,
  getTriagedFingerprints,
  getVerdictCounts,
  getActionableFindings,
  updateFindingMetadata,
  updatePocHarnessResult,
  updateRunCost,
  updateRunContext,
  updateRunFindings,
  updateRunStatus,
  upsertFinding,
} from "../src/store.js";
import type { KuzushiConfig, ScanOpts, TriageResult } from "../src/types.js";
import type { Finding } from "../src/scanners/types.js";
import { BATCH_TRIAGE_FALLBACK_RATIONALE } from "../src/triage.js";

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
    model: "anthropic:claude-sonnet-4-6",
    triageMaxTurns: 10,
    busBackend: "in-process",
    triageBatchSize: 15,
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

  it("migrates legacy findings table to include triage_cost_usd", () => {
    // Simulate a legacy database (no schema_version table) with an older
    // findings schema that is missing the triage_cost_usd column.
    const legacyDb = new Database(dbPath);
    legacyDb.pragma("journal_mode = WAL");
    legacyDb.prepare(`
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
    `).run();
    legacyDb.close();

    const migrated = initDb(dbPath);
    const columns = migrated.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    expect(columns.some((column) => column.name === "triage_cost_usd")).toBe(true);
    migrated.close();
  });

  it("migrates legacy findings table to include poc harness columns", () => {
    // Simulate a legacy database (no schema_version table) with an older
    // findings schema that has verification columns but no poc harness columns.
    const legacyDb = new Database(dbPath);
    legacyDb.pragma("journal_mode = WAL");
    legacyDb.prepare(`
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
        triage_cost_usd    REAL,
        verify_exploitable INTEGER,
        verify_poc_payload TEXT,
        verify_poc_description TEXT,
        verify_attack_vector TEXT,
        verify_preconditions TEXT,
        verify_confidence REAL,
        verify_cost_usd REAL,
        created_at         TEXT NOT NULL DEFAULT (datetime('now')),
        updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `).run();
    legacyDb.close();

    const migrated = initDb(dbPath);
    const columns = migrated.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
    expect(columns.some((column) => column.name === "poc_harness_path")).toBe(true);
    expect(columns.some((column) => column.name === "poc_harness_skipped")).toBe(true);
    expect(columns.some((column) => column.name === "poc_harness_cost_usd")).toBe(true);
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

  it("persists extended triage details and restores them", () => {
    const db = initDb(dbPath);
    const triage = makeResult("fp-ext", "tp");
    triage.source = {
      why: "trusted source",
      isFalsePositive: true,
      evidence: "constant assignment",
    };
    triage.sink = {
      why: "dangerous sink still reachable",
      isFalsePositive: false,
      evidence: "sink call in handler",
    };
    triage.isVulnerable = false;
    triage.exploitScenario = "not exploitable";
    triage.recommendedFix = "tighten source pattern";
    triage.ruleRefinementHint = "constrain source role";
    triage.triageSchemaVersion = "1.0.0";

    upsertFinding(db, makeFinding("fp-ext"), triage, "repo", "HEAD");

    const restored = getStoredTriageResults(db, ["fp-ext"]).get("fp-ext");
    expect(restored).toBeDefined();
    expect(restored?.source?.isFalsePositive).toBe(true);
    expect(restored?.sink?.isFalsePositive).toBe(false);
    expect(restored?.isVulnerable).toBe(false);
    expect(restored?.ruleRefinementHint).toBe("constrain source role");

    db.close();
  });

  it("persists finding provenance metadata", () => {
    const db = initDb(dbPath);
    const finding = makeFinding("fp-provenance");
    finding.adjustedScore = 42;
    finding.corroboratingSignals = [
      {
        scanner: "codeql",
        fingerprint: "fp-other",
        ruleId: "js/sql-injection",
        filePath: "src/test.ts",
        startLine: 10,
        cwe: ["CWE-89"],
        score: 91,
      },
    ];
    finding.suppressionReasons = [
      {
        id: "open-redirect",
        kind: "soft",
        description: "Low-impact redirect outside auth context",
        scorePenalty: 15,
      },
    ];

    upsertFinding(db, finding, makeResult("fp-provenance", "tp"), "repo", "HEAD");

    const actionable = getActionableFindings(db, "repo", { includeFalsePositives: true });
    expect(actionable).toHaveLength(1);
    expect(actionable[0].adjustedScore).toBe(42);
    expect(actionable[0].corroboratingSignals).toEqual([
      expect.objectContaining({ fingerprint: "fp-other", scanner: "codeql" }),
    ]);
    expect(actionable[0].suppressionReasons).toEqual([
      expect.objectContaining({ id: "open-redirect", kind: "soft" }),
    ]);

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

  it("excludes findings with the batch-drop fallback signature", () => {
    const db = initDb(dbPath);

    // Normal finding — should be included
    upsertFinding(db, makeFinding("normal"), makeResult("normal", "tp"), "repo", "HEAD");

    // Batch-drop fallback finding — should be excluded
    const fallback: TriageResult = {
      fingerprint: "dropped",
      verdict: "needs_review",
      confidence: 0,
      rationale: BATCH_TRIAGE_FALLBACK_RATIONALE,
      verificationSteps: [],
      fixPatch: null,
    };
    upsertFinding(db, makeFinding("dropped"), fallback, "repo", "HEAD");

    const fps = getTriagedFingerprints(db);
    expect(fps.has("normal")).toBe(true);
    expect(fps.has("dropped")).toBe(false);
    db.close();
  });
});

describe("deleteFindingsByFingerprints", () => {
  it("removes only selected findings for the target repo", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("keep"), makeResult("keep", "tp"), "repo-a", "HEAD");
    upsertFinding(db, makeFinding("drop"), makeResult("drop", "tp"), "repo-a", "HEAD");
    upsertFinding(db, makeFinding("other-repo"), makeResult("other-repo", "tp"), "repo-b", "HEAD");

    const deleted = deleteFindingsByFingerprints(db, "repo-a", ["drop"]);
    expect(deleted).toBe(1);

    const repoAFingerprints = getTriagedFingerprints(db);
    expect(repoAFingerprints.has("keep")).toBe(true);
    expect(repoAFingerprints.has("drop")).toBe(false);
    expect(repoAFingerprints.has("other-repo")).toBe(true);
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

describe("PoC harness persistence", () => {
  it("updates poc harness fields and aggregates counts/cost", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("poc-a"), makeResult("poc-a", "tp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("poc-b"), makeResult("poc-b", "tp"), "repo", "HEAD");

    updatePocHarnessResult(db, "poc-a", {
      fingerprint: "poc-a",
      scriptPath: "/tmp/repo/.kuzushi/poc/poc-a-cwe79.ts",
      language: "typescript",
      scriptContent: "console.log('PASS')",
      parsed: true,
      parseError: null,
      skipped: false,
      skipReason: null,
      costUsd: 0.07,
    });
    updatePocHarnessResult(db, "poc-b", {
      fingerprint: "poc-b",
      scriptPath: null,
      language: "typescript",
      scriptContent: null,
      parsed: false,
      parseError: null,
      skipped: true,
      skipReason: "Cannot isolate function",
      costUsd: 0.02,
    });

    const counts = getPocHarnessCounts(db, "repo");
    expect(counts.generated).toBe(1);
    expect(counts.skipped).toBe(1);
    expect(getTotalPocHarnessCost(db, "repo")).toBeCloseTo(0.09, 8);

    const rows = db.prepare(`
      SELECT
        poc_harness_path as pocHarnessPath,
        poc_harness_language as pocHarnessLanguage,
        poc_harness_parsed as pocHarnessParsed,
        poc_harness_skipped as pocHarnessSkipped
      FROM findings
      WHERE fingerprint = 'poc-a'
    `).get() as {
      pocHarnessPath: string | null;
      pocHarnessLanguage: string | null;
      pocHarnessParsed: number | null;
      pocHarnessSkipped: number | null;
    };

    expect(rows.pocHarnessPath).toContain(".kuzushi/poc");
    expect(rows.pocHarnessLanguage).toBe("typescript");
    expect(rows.pocHarnessParsed).toBe(1);
    expect(rows.pocHarnessSkipped).toBe(0);
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

  it("filters by fingerprints when provided", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("current-1"), makeResult("current-1", "tp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("current-2"), makeResult("current-2", "fp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("stale-1"), makeResult("stale-1", "tp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("stale-2"), makeResult("stale-2", "needs_review"), "repo", "HEAD");

    const filtered = getActionableFindings(db, "repo", {
      includeFalsePositives: true,
      fingerprints: ["current-1", "current-2"],
    });

    expect(filtered).toHaveLength(2);
    const fps = filtered.map((f) => f.fingerprint);
    expect(fps).toContain("current-1");
    expect(fps).toContain("current-2");
    expect(fps).not.toContain("stale-1");
    expect(fps).not.toContain("stale-2");
    db.close();
  });

  it("returns all findings when fingerprints is undefined", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("a"), makeResult("a", "tp"), "repo", "HEAD");
    upsertFinding(db, makeFinding("b"), makeResult("b", "tp"), "repo", "HEAD");

    const all = getActionableFindings(db, "repo", { fingerprints: undefined });
    expect(all).toHaveLength(2);
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

  it("treats poc-harnessing runs as resumable", () => {
    const db = initDb(dbPath);

    createRun(db, "run-poc", "repo", makeConfig(), makeScanOpts());
    updateRunStatus(db, "run-poc", "poc-harnessing");

    const latest = getLatestResumableRun(db, "repo");
    expect(latest?.runId).toBe("run-poc");
    expect(latest?.status).toBe("poc-harnessing");
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

  it("persists wrapped base and enriched context checkpoints", () => {
    const db = initDb(dbPath);
    const runId = "run-context-enriched";

    createRun(db, runId, "repo", makeConfig(), makeScanOpts());
    updateRunContext(db, runId, {
      base: {
        languages: ["TypeScript"],
        frameworks: ["Express"],
        authPatterns: ["JWT"],
        sanitizationLibs: ["helmet"],
        ormOrDb: ["Prisma"],
        entryPoints: ["src/pages/api/*"],
      },
      enrichment: {
        customMiddleware: [{ name: "auth", filePath: "src/middleware/auth.ts", purpose: "auth gate" }],
        customSanitizers: [],
        trustBoundaries: [],
        dataClassifications: [],
        architecturalNotes: ["Jobs handle uploaded files."],
      },
    });

    const run = getRun(db, runId);
    expect(run?.contextJson).toContain("\"base\"");
    expect(run?.contextJson).toContain("\"enrichment\"");
    expect(run?.contextJson).toContain("Jobs handle uploaded files.");
    db.close();
  });
});

describe("large fingerprint sets (SQLite bind limit)", () => {
  it("getStoredTriageResults handles >999 fingerprints", () => {
    const db = initDb(":memory:");
    const fingerprints: string[] = [];
    for (let i = 0; i < 1100; i++) {
      const fp = `fp-large-${String(i).padStart(5, "0")}`;
      fingerprints.push(fp);
      upsertFinding(db, makeFinding(fp), makeResult(fp, "tp"), "repo", "HEAD");
    }

    const results = getStoredTriageResults(db, fingerprints);
    expect(results.size).toBe(1100);
    expect(results.get("fp-large-00000")?.verdict).toBe("tp");
    expect(results.get("fp-large-01099")?.verdict).toBe("tp");
    db.close();
  });

  it("deleteFindingsByFingerprints handles >999 fingerprints", () => {
    const db = initDb(":memory:");
    const fingerprints: string[] = [];
    for (let i = 0; i < 1100; i++) {
      const fp = `fp-del-${String(i).padStart(5, "0")}`;
      fingerprints.push(fp);
      upsertFinding(db, makeFinding(fp), makeResult(fp), "repo", "HEAD");
    }

    const deleted = deleteFindingsByFingerprints(db, "repo", fingerprints);
    expect(deleted).toBe(1100);
    db.close();
  });
});

describe("updateFindingMetadata", () => {
  it("writes metadata and round-trips through getActionableFindings", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("fp-meta"), makeResult("fp-meta", "tp"), "repo", "HEAD");

    updateFindingMetadata(db, "fp-meta", {
      latestDynamicRunId: "dyn-001",
      dynamicRunIds: ["dyn-001"],
      notes: ["initial dynamic run"],
    });

    const findings = getActionableFindings(db, "repo", { includeFalsePositives: true });
    const match = findings.find(f => f.fingerprint === "fp-meta");
    expect(match).toBeDefined();
    expect(match!.findingMetadata).toBeDefined();
    expect(match!.findingMetadata!.latestDynamicRunId).toBe("dyn-001");
    expect(match!.findingMetadata!.dynamicRunIds).toEqual(["dyn-001"]);
    expect(match!.findingMetadata!.notes).toEqual(["initial dynamic run"]);
    db.close();
  });

  it("merges with existing metadata", () => {
    const db = initDb(dbPath);
    upsertFinding(db, makeFinding("fp-merge"), makeResult("fp-merge", "tp"), "repo", "HEAD");

    updateFindingMetadata(db, "fp-merge", {
      latestDynamicRunId: "dyn-001",
      dynamicRunIds: ["dyn-001"],
      notes: ["first note"],
    });

    updateFindingMetadata(db, "fp-merge", {
      latestPatchRunId: "patch-001",
      patchRunIds: ["patch-001"],
      dynamicRunIds: ["dyn-002"],
      notes: ["second note"],
    });

    const findings = getActionableFindings(db, "repo", { includeFalsePositives: true });
    const match = findings.find(f => f.fingerprint === "fp-merge");
    expect(match!.findingMetadata!.latestDynamicRunId).toBe("dyn-001");
    expect(match!.findingMetadata!.latestPatchRunId).toBe("patch-001");
    // Arrays should accumulate, not replace
    expect(match!.findingMetadata!.dynamicRunIds).toEqual(["dyn-001", "dyn-002"]);
    expect(match!.findingMetadata!.patchRunIds).toEqual(["patch-001"]);
    db.close();
  });
});
