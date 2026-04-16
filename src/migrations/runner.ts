import type Database from "better-sqlite3";
import type { Migration } from "./types.js";

/**
 * Ensure the `schema_version` bookkeeping table exists.
 */
function ensureSchemaVersionTable(db: Database.Database): void {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS schema_version (
      version    INTEGER PRIMARY KEY,
      name       TEXT NOT NULL,
      applied_at TEXT NOT NULL
    )
  `).run();
}

/**
 * Return the set of migration versions that have already been applied.
 */
function getAppliedVersions(db: Database.Database): Set<number> {
  const rows = db.prepare("SELECT version FROM schema_version").all() as Array<{ version: number }>;
  return new Set(rows.map((r) => r.version));
}

/**
 * Run all pending migrations against the given database.
 *
 * - Creates the `schema_version` tracking table if absent.
 * - Runs each unapplied migration inside its own transaction.
 *
 * Callers are responsible for reset-style logic (e.g. detecting and
 * backing up pre-v100 databases before this runs). See `initDb()` in
 * `src/store.ts`.
 *
 * @returns List of migrations that were newly applied during this call.
 */
export function runMigrations(
  db: Database.Database,
  migrations: Migration[],
): Array<{ version: number; name: string }> {
  ensureSchemaVersionTable(db);

  const sorted = [...migrations].sort((a, b) => a.version - b.version);
  const applied = getAppliedVersions(db);
  const newlyApplied: Array<{ version: number; name: string }> = [];

  for (const migration of sorted) {
    if (applied.has(migration.version)) {
      continue;
    }

    const runOne = db.transaction(() => {
      migration.up(db);
      db.prepare("INSERT INTO schema_version (version, name, applied_at) VALUES (?, ?, ?)").run(
        migration.version,
        migration.name,
        new Date().toISOString(),
      );
    });

    runOne();
    newlyApplied.push({ version: migration.version, name: migration.name });
  }

  return newlyApplied;
}
