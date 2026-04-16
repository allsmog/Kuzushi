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

describe("v100 schema reset", () => {
  it("applies v100 to a fresh DB without producing a backup", () => {
    const dbPath = tmpDb();
    const db = initDb(dbPath);
    try {
      const rows = db.prepare("SELECT version FROM schema_version").all();
      expect(rows).toEqual([{ version: 100 }]);
      expect(readdirSync(path.dirname(dbPath)).filter((n) => n.includes(".bak-"))).toHaveLength(0);
    } finally {
      db.close();
    }
  });

  it("renames a legacy pre-v100 DB and applies v100 to a fresh file", () => {
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

      // New DB has only v100 and no legacy data.
      const versions = db.prepare("SELECT version FROM schema_version").all();
      expect(versions).toEqual([{ version: 100 }]);
      const legacyRow = db.prepare("SELECT COUNT(*) as n FROM findings").get() as { n: number };
      expect(legacyRow.n).toBe(0);
    } finally {
      db.close();
    }
  });

  it("is a no-op on an already-v100 DB", () => {
    const dbPath = tmpDb();
    const first = initDb(dbPath);
    first.close();

    const resets: unknown[] = [];
    const second = initDb(dbPath, { onReset: (i) => resets.push(i) });
    try {
      expect(resets).toHaveLength(0);
      const versions = second.prepare("SELECT version FROM schema_version").all();
      expect(versions).toEqual([{ version: 100 }]);
    } finally {
      second.close();
    }
  });

  it("throws SchemaStateError on a future schema_version > 100", () => {
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
