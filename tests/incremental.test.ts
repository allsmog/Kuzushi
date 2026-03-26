import { describe, expect, it } from "vitest";
import Database from "better-sqlite3";
import { allMigrations, runMigrations } from "../src/migrations/index.js";
import {
  buildReverseDependencyMap,
  expandWithDependents,
  getLastSuccessfulHeadRef,
} from "../src/incremental.js";
import type { ImportGraphEdge } from "../src/analysis-support/types.js";

function createTestDb(): Database.Database {
  const db = new Database(":memory:");
  db.pragma("journal_mode = WAL");
  runMigrations(db, allMigrations);
  return db;
}

describe("buildReverseDependencyMap", () => {
  it("builds reverse map from import edges", () => {
    const edges: ImportGraphEdge[] = [
      { fromFilePath: "src/app.ts", toPath: "src/auth.ts" },
      { fromFilePath: "src/routes.ts", toPath: "src/auth.ts" },
      { fromFilePath: "src/app.ts", toPath: "src/db.ts" },
    ];

    const reverseMap = buildReverseDependencyMap(edges);

    expect(reverseMap.get("src/auth.ts")).toEqual(new Set(["src/app.ts", "src/routes.ts"]));
    expect(reverseMap.get("src/db.ts")).toEqual(new Set(["src/app.ts"]));
    expect(reverseMap.has("src/app.ts")).toBe(false); // app.ts is not imported by anyone
  });

  it("returns empty map for no edges", () => {
    expect(buildReverseDependencyMap([]).size).toBe(0);
  });
});

describe("expandWithDependents", () => {
  const edges: ImportGraphEdge[] = [
    { fromFilePath: "src/app.ts", toPath: "src/auth.ts" },
    { fromFilePath: "src/routes.ts", toPath: "src/auth.ts" },
    { fromFilePath: "src/middleware.ts", toPath: "src/db.ts" },
  ];

  it("expands changed files with their importers", () => {
    const result = expandWithDependents(["src/auth.ts"], edges);

    expect(result.expanded).toContain("src/auth.ts");
    expect(result.expanded).toContain("src/app.ts");
    expect(result.expanded).toContain("src/routes.ts");
    expect(result.depExpandedCount).toBe(2);
  });

  it("does not duplicate already-changed files", () => {
    const result = expandWithDependents(["src/auth.ts", "src/app.ts"], edges);

    const unique = new Set(result.expanded);
    expect(unique.size).toBe(result.expanded.length);
    expect(result.depExpandedCount).toBe(1); // only routes.ts is new
  });

  it("returns unchanged set when no dependents", () => {
    const result = expandWithDependents(["src/app.ts"], edges);

    expect(result.expanded).toEqual(["src/app.ts"]);
    expect(result.depExpandedCount).toBe(0);
  });

  it("handles empty changed files", () => {
    const result = expandWithDependents([], edges);

    expect(result.expanded).toHaveLength(0);
    expect(result.depExpandedCount).toBe(0);
  });
});

describe("getLastSuccessfulHeadRef", () => {
  it("returns null when no runs exist", () => {
    const db = createTestDb();
    expect(getLastSuccessfulHeadRef(db, "test-repo")).toBeNull();
  });

  it("returns head_ref from last completed run", () => {
    const db = createTestDb();
    db.prepare(`
      INSERT INTO pipeline_runs (run_id, repo, started_at, status, head_ref, completed_at, config_json, scan_opts_json)
      VALUES (?, ?, datetime('now', '-1 hour'), 'complete', ?, datetime('now'), '{}', '{}')
    `).run("run-1", "test-repo", "abc123");

    expect(getLastSuccessfulHeadRef(db, "test-repo")).toBe("abc123");
  });

  it("ignores failed runs", () => {
    const db = createTestDb();
    db.prepare(`
      INSERT INTO pipeline_runs (run_id, repo, started_at, status, head_ref, completed_at, config_json, scan_opts_json)
      VALUES (?, ?, datetime('now'), 'error', ?, datetime('now'), '{}', '{}')
    `).run("run-1", "test-repo", "abc123");

    expect(getLastSuccessfulHeadRef(db, "test-repo")).toBeNull();
  });

  it("returns most recent completed run", () => {
    const db = createTestDb();
    db.prepare(`
      INSERT INTO pipeline_runs (run_id, repo, started_at, status, head_ref, completed_at, config_json, scan_opts_json)
      VALUES (?, ?, datetime('now', '-2 hours'), 'complete', ?, datetime('now', '-2 hours'), '{}', '{}')
    `).run("run-1", "test-repo", "old-ref");

    db.prepare(`
      INSERT INTO pipeline_runs (run_id, repo, started_at, status, head_ref, completed_at, config_json, scan_opts_json)
      VALUES (?, ?, datetime('now', '-1 hour'), 'complete', ?, datetime('now', '-1 hour'), '{}', '{}')
    `).run("run-2", "test-repo", "new-ref");

    expect(getLastSuccessfulHeadRef(db, "test-repo")).toBe("new-ref");
  });
});
