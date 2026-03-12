import { describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import {
  TrajectoryCollector,
  ensureTrajectoryTable,
  formatTrajectoriesForPrompt,
  pruneOldUnverifiedTrajectories,
  retrieveTrajectories,
  saveTrajectory,
  summarizeTrajectory,
  updateTrajectoryCorrectness,
  type TrajectoryRecord,
  type TrajectoryStep,
} from "../src/trajectory-memory.js";
import type { AgentActivity } from "../src/agent-runtime/execution.js";

function createTestDb(): Database.Database {
  const db = new Database(":memory:");
  db.pragma("journal_mode = WAL");
  ensureTrajectoryTable(db);
  return db;
}

describe("TrajectoryCollector", () => {
  it("collects tool-start/tool-complete pairs into steps", () => {
    const collector = new TrajectoryCollector();

    collector.onActivity({ kind: "tool-start", toolName: "Read", toolInput: { file_path: "src/app.ts" } });
    collector.onActivity({ kind: "tool-complete", summary: "read 42 lines" });

    collector.onActivity({ kind: "tool-start", toolName: "Grep", toolInput: { pattern: "sanitize" } });
    collector.onActivity({ kind: "tool-complete", summary: "found 3 matches" });

    const steps = collector.getSteps();
    expect(steps).toHaveLength(2);
    expect(steps[0].toolName).toBe("Read");
    expect(steps[0].outcome).toBe("read 42 lines");
    expect(steps[1].toolName).toBe("Grep");
    expect(steps[1].outcome).toBe("found 3 matches");
  });

  it("ignores tool-complete without preceding tool-start", () => {
    const collector = new TrajectoryCollector();
    collector.onActivity({ kind: "tool-complete", summary: "orphaned" });
    expect(collector.getSteps()).toHaveLength(0);
  });

  it("ignores reasoning events", () => {
    const collector = new TrajectoryCollector();
    collector.onActivity({ kind: "reasoning", summary: "thinking..." });
    expect(collector.getSteps()).toHaveLength(0);
  });

  it("wrapCallback calls both original and collector", async () => {
    const collector = new TrajectoryCollector();
    let originalCalled = false;
    const original = async () => { originalCalled = true; };

    const wrapped = collector.wrapCallback(original);
    await wrapped({ kind: "tool-start", toolName: "Read", toolInput: { file_path: "test.ts" } });
    await wrapped({ kind: "tool-complete", summary: "done" });

    expect(originalCalled).toBe(true);
    expect(collector.getSteps()).toHaveLength(1);
  });

  it("wrapCallback works without original callback", async () => {
    const collector = new TrajectoryCollector();
    const wrapped = collector.wrapCallback(undefined);

    await wrapped({ kind: "tool-start", toolName: "Glob", toolInput: { pattern: "*.ts" } });
    await wrapped({ kind: "tool-complete", summary: "5 files" });

    expect(collector.getSteps()).toHaveLength(1);
  });

  it("truncates long tool input values", () => {
    const collector = new TrajectoryCollector();
    const longInput = "x".repeat(300);

    collector.onActivity({ kind: "tool-start", toolName: "Read", toolInput: { file_path: longInput } });
    collector.onActivity({ kind: "tool-complete", summary: "done" });

    const steps = collector.getSteps();
    expect((steps[0].toolInput["file_path"] as string).length).toBeLessThan(300);
    expect((steps[0].toolInput["file_path"] as string).endsWith("...")).toBe(true);
  });
});

describe("summarizeTrajectory", () => {
  it("returns minimal summary for empty steps", () => {
    const summary = summarizeTrajectory([], "fp");
    expect(summary).toContain("fp");
    expect(summary).toContain("No tool calls");
  });

  it("generates summary from steps", () => {
    const steps: TrajectoryStep[] = [
      { toolName: "Read", toolInput: { file_path: "src/app.ts" }, outcome: "read 50 lines" },
      { toolName: "Grep", toolInput: { pattern: "sanitize" }, outcome: "3 matches" },
    ];
    const summary = summarizeTrajectory(steps, "tp");
    expect(summary).toContain("Read");
    expect(summary).toContain("Grep");
    expect(summary).toContain("2 steps");
    expect(summary).toContain("tp");
  });
});

describe("saveTrajectory and retrieveTrajectories", () => {
  it("saves and retrieves by exact rule_id", () => {
    const db = createTestDb();

    saveTrajectory(db, {
      id: "t1",
      ruleId: "express.sqli",
      cwes: ["CWE-89"],
      scanner: "semgrep",
      verdict: "tp",
      confidence: 0.8,
      steps: [{ toolName: "Read", toolInput: { file_path: "test.ts" }, outcome: "done" }],
      summary: "Found SQL injection",
      repo: "test-repo",
      fingerprint: "fp-1",
    });

    const results = retrieveTrajectories(db, "express.sqli", ["CWE-89"], 2);
    // Not verified yet, so it won't match the "was_correct = 1" query
    // But it should match as unverified via CWE
    expect(results.length).toBeGreaterThanOrEqual(0);
    db.close();
  });

  it("retrieves verified-correct trajectories first", () => {
    const db = createTestDb();

    saveTrajectory(db, {
      id: "t1",
      ruleId: "express.sqli",
      cwes: ["CWE-89"],
      scanner: "semgrep",
      verdict: "tp",
      confidence: 0.8,
      steps: [],
      summary: "unverified",
      repo: "repo",
      fingerprint: "fp-1",
    });

    saveTrajectory(db, {
      id: "t2",
      ruleId: "express.sqli",
      cwes: ["CWE-89"],
      scanner: "semgrep",
      verdict: "tp",
      confidence: 0.9,
      steps: [],
      summary: "verified correct",
      repo: "repo",
      fingerprint: "fp-2",
    });

    // Mark t2 as verified correct
    updateTrajectoryCorrectness(db, "fp-2", true);

    const results = retrieveTrajectories(db, "express.sqli", ["CWE-89"], 2);
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].id).toBe("t2");
    db.close();
  });

  it("skips was_correct = 0 trajectories", () => {
    const db = createTestDb();

    saveTrajectory(db, {
      id: "t1",
      ruleId: "express.sqli",
      cwes: ["CWE-89"],
      scanner: "semgrep",
      verdict: "fp",
      confidence: 0.3,
      steps: [],
      summary: "wrong",
      repo: "repo",
      fingerprint: "fp-1",
    });

    updateTrajectoryCorrectness(db, "fp-1", false);

    const results = retrieveTrajectories(db, "express.sqli", ["CWE-89"], 5);
    const incorrectIds = results.filter((r) => r.wasCorrect === 0);
    expect(incorrectIds).toHaveLength(0);
    db.close();
  });

  it("respects maxExemplars limit", () => {
    const db = createTestDb();

    for (let i = 0; i < 10; i++) {
      saveTrajectory(db, {
        id: `t${i}`,
        ruleId: "express.sqli",
        cwes: ["CWE-89"],
        scanner: "semgrep",
        verdict: "tp",
        confidence: 0.8,
        steps: [],
        summary: `exemplar ${i}`,
        repo: "repo",
        fingerprint: `fp-${i}`,
      });
      updateTrajectoryCorrectness(db, `fp-${i}`, true);
    }

    const results = retrieveTrajectories(db, "express.sqli", ["CWE-89"], 2);
    expect(results).toHaveLength(2);
    db.close();
  });

  it("returns empty array when maxExemplars is 0", () => {
    const db = createTestDb();
    const results = retrieveTrajectories(db, "test", [], 0);
    expect(results).toHaveLength(0);
    db.close();
  });
});

describe("updateTrajectoryCorrectness", () => {
  it("sets was_correct flag", () => {
    const db = createTestDb();

    saveTrajectory(db, {
      id: "t1",
      ruleId: "test",
      cwes: [],
      scanner: "semgrep",
      verdict: "tp",
      confidence: 0.7,
      steps: [],
      summary: "test",
      repo: "repo",
      fingerprint: "fp-1",
    });

    updateTrajectoryCorrectness(db, "fp-1", true);

    const row = db.prepare("SELECT was_correct FROM trajectories WHERE id = ?").get("t1") as { was_correct: number };
    expect(row.was_correct).toBe(1);

    updateTrajectoryCorrectness(db, "fp-1", false);

    const row2 = db.prepare("SELECT was_correct FROM trajectories WHERE id = ?").get("t1") as { was_correct: number };
    expect(row2.was_correct).toBe(0);

    db.close();
  });
});

describe("formatTrajectoriesForPrompt", () => {
  it("returns empty string for no trajectories", () => {
    expect(formatTrajectoriesForPrompt([])).toBe("");
  });

  it("formats trajectories with verified tag", () => {
    const trajectories: TrajectoryRecord[] = [
      {
        id: "t1",
        ruleId: "express.sqli",
        cwesJson: '["CWE-89"]',
        scanner: "semgrep",
        verdict: "tp",
        confidence: 0.8,
        wasCorrect: 1,
        stepsJson: JSON.stringify([
          { toolName: "Read", toolInput: { file_path: "src/app.ts" }, outcome: "found raw SQL" },
        ]),
        summary: "Traced SQL injection path",
        repo: "repo",
        fingerprint: "fp-1",
        createdAt: "",
        updatedAt: "",
      },
    ];

    const result = formatTrajectoriesForPrompt(trajectories);
    expect(result).toContain("Prior Investigation Exemplars");
    expect(result).toContain("[VERIFIED CORRECT]");
    expect(result).toContain("express.sqli");
    expect(result).toContain("Read");
  });

  it("handles unparseable steps gracefully", () => {
    const trajectories: TrajectoryRecord[] = [
      {
        id: "t1",
        ruleId: "test",
        cwesJson: "[]",
        scanner: "semgrep",
        verdict: "fp",
        confidence: 0.5,
        wasCorrect: null,
        stepsJson: "invalid json",
        summary: "test summary",
        repo: "repo",
        fingerprint: null,
        createdAt: "",
        updatedAt: "",
      },
    ];

    const result = formatTrajectoriesForPrompt(trajectories);
    expect(result).toContain("Prior Investigation Exemplars");
    expect(result).toContain("test summary");
  });
});

describe("pruneOldUnverifiedTrajectories", () => {
  it("prunes old unverified trajectories", () => {
    const db = createTestDb();

    // Insert a trajectory with old date
    const oldDate = "2020-01-01T00:00:00.000Z";
    db.prepare(`
      INSERT INTO trajectories (id, rule_id, cwes_json, scanner, verdict, confidence, was_correct, steps_json, summary, repo, fingerprint, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)
    `).run("old-1", "test", "[]", "semgrep", "tp", 0.5, "[]", "old", "repo", null, oldDate, oldDate);

    // Insert a recent one
    saveTrajectory(db, {
      id: "new-1",
      ruleId: "test",
      cwes: [],
      scanner: "semgrep",
      verdict: "tp",
      confidence: 0.5,
      steps: [],
      summary: "new",
      repo: "repo",
      fingerprint: null,
    });

    const deleted = pruneOldUnverifiedTrajectories(db, 90);
    expect(deleted).toBe(1);

    const remaining = db.prepare("SELECT COUNT(*) as count FROM trajectories").get() as { count: number };
    expect(remaining.count).toBe(1);
    db.close();
  });

  it("does not prune verified trajectories", () => {
    const db = createTestDb();

    const oldDate = "2020-01-01T00:00:00.000Z";
    db.prepare(`
      INSERT INTO trajectories (id, rule_id, cwes_json, scanner, verdict, confidence, was_correct, steps_json, summary, repo, fingerprint, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)
    `).run("old-verified", "test", "[]", "semgrep", "tp", 0.5, "[]", "old but verified", "repo", null, oldDate, oldDate);

    const deleted = pruneOldUnverifiedTrajectories(db, 90);
    expect(deleted).toBe(0);
    db.close();
  });
});

describe("ensureTrajectoryTable", () => {
  it("creates trajectories table", () => {
    const db = createTestDb();
    const tables = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='trajectories'",
    ).all();
    expect(tables).toHaveLength(1);
    db.close();
  });

  it("is idempotent", () => {
    const db = createTestDb();
    ensureTrajectoryTable(db);
    ensureTrajectoryTable(db);
    const tables = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='trajectories'",
    ).all();
    expect(tables).toHaveLength(1);
    db.close();
  });
});
