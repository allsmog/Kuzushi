import Database from "better-sqlite3";
import { allMigrations, runMigrations } from "../src/migrations/index.js";
import { FindingUpsertQueue } from "../src/store.js";
import { makeFindings, makeTriageResults } from "./fixtures.js";
import type { BenchCase } from "./harness.js";

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

  // threshold=1 forces one transaction per finding (old default).
  // The "default" variant uses whatever DEFAULT_FLUSH_THRESHOLD currently is,
  // so this bench tracks any future change automatically.
  const count = 500;
  const findings = makeFindings(count);
  const triages = makeTriageResults(count);
  const variants: Array<{ label: string; makeQueue: (db: Database.Database) => FindingUpsertQueue }> = [
    { label: "threshold=1 (worst case, per-finding commit)", makeQueue: (db) => new FindingUpsertQueue(db, 1) },
    { label: "default (batched)", makeQueue: (db) => new FindingUpsertQueue(db) },
    { label: "threshold=100", makeQueue: (db) => new FindingUpsertQueue(db, 100) },
  ];

  for (const { label, makeQueue } of variants) {
    let db: Database.Database;
    let queue: FindingUpsertQueue;

    cases.push({
      name: `upsert ${count} findings ${label}`,
      setup: () => {
        db = freshDb();
        queue = makeQueue(db);
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
