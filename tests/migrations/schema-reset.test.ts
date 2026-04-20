import { existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it } from "vitest";
import { initDb, SchemaStateError } from "../../src/store.js";

const tempDirs: string[] = [];

function tmpDb(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-reset-test-"));
  tempDirs.push(dir);
  return path.join(dir, "findings.sqlite3");
}

/** Populate a DB with a fake pre-v100 schema so initDb treats it as legacy. */
function seedLegacyDb(dbPath: string, legacyVersion: number): void {
  const db = new Database(dbPath);
  db.exec(`
    CREATE TABLE schema_version (
      version    INTEGER PRIMARY KEY,
      name       TEXT NOT NULL,
      applied_at TEXT NOT NULL
    );
    CREATE TABLE findings (
      fingerprint TEXT PRIMARY KEY,
      legacy_col  TEXT
    );
  `);
  db.prepare("INSERT INTO schema_version VALUES (?, 'legacy', datetime('now'))").run(legacyVersion);
  db.prepare(
    "INSERT INTO findings (fingerprint, legacy_col) VALUES ('fp-legacy', 'old-data')",
  ).run();
  db.close();
}

afterEach(() => {
  while (tempDirs.length > 0) {
    rmSync(tempDirs.pop()!, { recursive: true, force: true });
  }
});

describe("schema reset and incremental migrations", () => {
  it("applies all migrations to a fresh DB without producing a backup", () => {
    const dbPath = tmpDb();
    const db = initDb(dbPath);
    try {
      const rows = db.prepare("SELECT version FROM schema_version ORDER BY version").all();
      expect(rows).toEqual([
        { version: 100 },
        { version: 101 },
        { version: 102 },
        { version: 103 },
      ]);
      expect(readdirSync(path.dirname(dbPath)).filter((n) => n.includes(".bak-"))).toHaveLength(0);
    } finally {
      db.close();
    }
  });

  it("renames a legacy pre-v100 DB and applies all migrations to a fresh file", () => {
    const dbPath = tmpDb();
    seedLegacyDb(dbPath, 25);

    const resets: Array<{ oldVersion: number; backupPath: string }> = [];
    const now = new Date("2026-04-16T14:23:07Z");
    const db = initDb(dbPath, { now: () => now, onReset: (info) => resets.push(info) });
    try {
      expect(resets).toHaveLength(1);
      expect(resets[0]!.oldVersion).toBe(25);

      const backup = path.join(path.dirname(dbPath), "findings.sqlite3.bak-v25-20260416T142307");
      expect(existsSync(backup)).toBe(true);

      // New DB has v100+v101 and no legacy data.
      const versions = db.prepare("SELECT version FROM schema_version ORDER BY version").all();
      expect(versions).toEqual([
        { version: 100 },
        { version: 101 },
        { version: 102 },
        { version: 103 },
      ]);
      const legacyRow = db.prepare("SELECT COUNT(*) as n FROM findings").get() as { n: number };
      expect(legacyRow.n).toBe(0);
    } finally {
      db.close();
    }
  });

  it("upgrades a v100 DB in place to v101 without backup", () => {
    const dbPath = tmpDb();
    const first = initDb(dbPath);
    // Roll the DB back to "v100 only" to simulate a pre-v101 install.
    first.prepare("DELETE FROM schema_version WHERE version > 100").run();
    first.exec(`
      DROP TABLE IF EXISTS schedules;
      DROP TABLE IF EXISTS sessions;
      DROP TABLE IF EXISTS cred_logins;
      DROP TABLE IF EXISTS creds;
      DROP TABLE IF EXISTS notes;
      DROP TABLE IF EXISTS loot;
      DROP TABLE IF EXISTS vulns;
      DROP TABLE IF EXISTS services;
      DROP TABLE IF EXISTS hosts;
    `);
    first.close();

    const resets: unknown[] = [];
    const second = initDb(dbPath, { onReset: (i) => resets.push(i) });
    try {
      expect(resets).toHaveLength(0); // No backup — pure in-place upgrade.
      const versions = second.prepare("SELECT version FROM schema_version ORDER BY version").all();
      expect(versions).toEqual([
        { version: 100 },
        { version: 101 },
        { version: 102 },
        { version: 103 },
      ]);
      const hostsExists = second
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='hosts'")
        .get();
      expect(hostsExists).toBeTruthy();
    } finally {
      second.close();
    }
  });

  it("is a no-op on an already-current DB", () => {
    const dbPath = tmpDb();
    const first = initDb(dbPath);
    first.close();

    const resets: unknown[] = [];
    const second = initDb(dbPath, { onReset: (i) => resets.push(i) });
    try {
      expect(resets).toHaveLength(0);
      const versions = second.prepare("SELECT version FROM schema_version ORDER BY version").all();
      expect(versions).toEqual([
        { version: 100 },
        { version: 101 },
        { version: 102 },
        { version: 103 },
      ]);
    } finally {
      second.close();
    }
  });

  it("throws SchemaStateError on a future schema_version > current", () => {
    const dbPath = tmpDb();
    const db = new Database(dbPath);
    db.exec(`
      CREATE TABLE schema_version (version INTEGER PRIMARY KEY, name TEXT, applied_at TEXT);
      CREATE TABLE findings (fingerprint TEXT PRIMARY KEY);
    `);
    db.prepare("INSERT INTO schema_version VALUES (999, 'future', datetime('now'))").run();
    db.close();

    expect(() => initDb(dbPath)).toThrow(SchemaStateError);
  });

  it("resolves backup collisions with a numeric suffix", () => {
    const dbPath = tmpDb();
    seedLegacyDb(dbPath, 25);
    // Pre-place the primary backup path so the rename has to retry.
    const now = new Date("2026-04-16T14:23:07Z");
    const primary = `${dbPath}.bak-v25-20260416T142307`;
    writeFileSync(primary, "placeholder");

    const resets: Array<{ backupPath: string }> = [];
    const db = initDb(dbPath, { now: () => now, onReset: (i) => resets.push(i) });
    try {
      expect(resets).toHaveLength(1);
      expect(resets[0]!.backupPath).toBe(`${primary}-1`);
    } finally {
      db.close();
    }
  });

  it("enables foreign_keys on the resulting DB", () => {
    const dbPath = tmpDb();
    const db = initDb(dbPath);
    try {
      const row = db.prepare("PRAGMA foreign_keys").get() as { foreign_keys: number };
      expect(row.foreign_keys).toBe(1);
    } finally {
      db.close();
    }
  });
});
