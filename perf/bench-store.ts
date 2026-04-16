import type { BenchCase } from "./harness.js";
import Database from "better-sqlite3";
import { FindingUpsertQueue } from "../src/store.js";
import { runMigrations, allMigrations } from "../src/migrations/index.js";
import { makeFindings, makeTriageResults } from "./fixtures.js";

/** Spin up an in-memory SQLite with the real schema. */
function freshDb(): Database.Database {
  const db = new Database(":memory:");
  db.pragma("journal_mode = MEMORY");
  db.pragma("busy_timeout = 5000");
  runMigrations(db, allMigrations);
  return db;
}

export function benchStore(): BenchCase[] {
  const cases: BenchCase[] = [];

  // Threshold = 1 (current default) vs large threshold — shows the transaction
  // overhead this plan targets.
  for (const { label, threshold } of [
    { label: "threshold=1 (current default)", threshold: 1 },
    { label: "threshold=100", threshold: 100 },
  ]) {
    const count = 500;
    const findings = makeFindings(count);
    const triages = makeTriageResults(count);
    let db: Database.Database;
    let queue: FindingUpsertQueue;

    cases.push({
      name: `upsert ${count} findings ${label}`,
      setup: () => {
        db = freshDb();
        queue = new FindingUpsertQueue(db, threshold);
      },
      run: () => {
        for (let i = 0; i < count; i++) {
          queue.enqueue(findings[i], triages[i], "bench-repo", "HEAD");
        }
        queue.flush();
      },
      teardown: () => {
        db.close();
      },
    });
  }

  return cases;
}
