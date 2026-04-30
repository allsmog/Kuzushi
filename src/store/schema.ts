import fs from "node:fs";
import path from "node:path";
import Database from "better-sqlite3";
import { allMigrations, runMigrations } from "../migrations/index.js";
import { ensureScannerCacheSchema } from "../scanner-cache.js";

const CURRENT_SCHEMA_VERSION = 108;
const POST_RESET_BASELINE_VERSION = 100;

export interface InitDbOpts {
  now?: () => Date;
  onReset?: (info: { oldVersion: number; backupPath: string }) => void;
}

type SchemaState =
  | { kind: "fresh" }
  | { kind: "already-current" }
  | { kind: "needs-upgrade"; version: number }
  | { kind: "legacy-pre-reset"; version: number }
  | { kind: "corrupt"; reason: string };

export class SchemaStateError extends Error {
  constructor(
    message: string,
    readonly dbPath: string,
  ) {
    super(message);
    this.name = "SchemaStateError";
  }
}

export function initDb(dbPath: string, opts?: InitDbOpts): Database.Database {
  let db = openWithPragmas(dbPath);

  const state = inspectSchemaState(db);
  if (state.kind === "corrupt") {
    db.close();
    throw new SchemaStateError(
      `DB at ${dbPath} is in an unexpected state: ${state.reason}`,
      dbPath,
    );
  }

  if (state.kind === "legacy-pre-reset") {
    db = resetLegacyDatabase(db, dbPath, state.version, opts);
  }

  runMigrations(db, allMigrations);
  try {
    ensureScannerCacheSchema(db);
  } catch (error) {
    console.warn(
      `[store] failed to ensure scanner_cache schema: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
  db.pragma("wal_checkpoint(TRUNCATE)");

  return db;
}

export function defaultDbPath(repoRoot: string): string {
  return path.join(repoRoot, ".kuzushi", "findings.sqlite3");
}

function resetLegacyDatabase(
  db: Database.Database,
  dbPath: string,
  version: number,
  opts: InitDbOpts | undefined,
): Database.Database {
  const lockPath = `${dbPath}.reset-lock`;
  acquireResetLock(lockPath);
  try {
    if (!legacyResetStillRequired(db)) return db;
    db.close();
    backupLegacyDatabase(dbPath, version, opts);
    return openWithPragmas(dbPath);
  } finally {
    releaseResetLock(lockPath);
  }
}

function legacyResetStillRequired(db: Database.Database): boolean {
  return inspectSchemaState(db).kind === "legacy-pre-reset";
}

function backupLegacyDatabase(dbPath: string, version: number, opts: InitDbOpts | undefined): void {
  const now = (opts?.now ?? (() => new Date()))();
  const backupPath = renameWithCollisionSuffix(dbPath, computeBackupPath(dbPath, version, now));
  (opts?.onReset ?? defaultResetLogger)({ oldVersion: version, backupPath });
}

function openWithPragmas(dbPath: string): Database.Database {
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  db.pragma("synchronous = NORMAL");
  db.pragma("foreign_keys = ON");
  // Performance knobs — safe under WAL, do not change durability.
  // cache_size negative = KiB; ~64 MB holds the hot findings working set.
  // mmap_size enables read-only mmap on platforms that support it; SQLite
  // falls back to pread elsewhere.
  db.pragma("temp_store = MEMORY");
  db.pragma("cache_size = -65536");
  db.pragma("mmap_size = 268435456");
  for (const target of [dbPath, `${dbPath}-wal`, `${dbPath}-shm`]) {
    try {
      fs.chmodSync(target, 0o600);
    } catch {
      /* best-effort: WAL/SHM may not exist yet or filesystem may not support POSIX perms */
    }
  }
  return db;
}

function tableExists(db: Database.Database, name: string): boolean {
  const row = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get(name);
  return !!row;
}

function inspectSchemaState(db: Database.Database): SchemaState {
  try {
    const hasSchemaVersion = tableExists(db, "schema_version");
    const hasFindings = tableExists(db, "findings");

    if (!hasSchemaVersion && !hasFindings) return { kind: "fresh" };

    const maxVersion = hasSchemaVersion ? readCurrentSchemaVersion(db) : 0;
    return schemaStateFromVersion(maxVersion);
  } catch (error) {
    return { kind: "corrupt", reason: String(error) };
  }
}

function readCurrentSchemaVersion(db: Database.Database): number {
  const row = db.prepare("SELECT MAX(version) AS v FROM schema_version").get() as
    | { v: number | null }
    | undefined;
  return row?.v ?? 0;
}

function schemaStateFromVersion(maxVersion: number): SchemaState {
  if (maxVersion > CURRENT_SCHEMA_VERSION) {
    return {
      kind: "corrupt",
      reason: `schema_version ${maxVersion} is ahead of this build (v${CURRENT_SCHEMA_VERSION}); downgrade is not supported`,
    };
  }
  if (maxVersion === CURRENT_SCHEMA_VERSION) return { kind: "already-current" };
  if (maxVersion >= POST_RESET_BASELINE_VERSION) {
    return { kind: "needs-upgrade", version: maxVersion };
  }
  return { kind: "legacy-pre-reset", version: maxVersion };
}

function computeBackupPath(dbPath: string, oldVersion: number, now: Date): string {
  const ts = now
    .toISOString()
    .replace(/[-:]/g, "")
    .replace(/\.\d+Z$/, "");
  return `${dbPath}.bak-v${oldVersion}-${ts}`;
}

function renameWithCollisionSuffix(src: string, dst: string, maxRetries = 10): string {
  for (let attemptIndex = 0; attemptIndex < maxRetries; attemptIndex += 1) {
    const attemptPath = attemptIndex === 0 ? dst : `${dst}-${attemptIndex}`;
    if (!fs.existsSync(attemptPath)) {
      fs.renameSync(src, attemptPath);
      return attemptPath;
    }
  }
  throw new Error(`Could not find a free backup path after ${maxRetries} attempts: ${dst}`);
}

function acquireResetLock(lockPath: string, timeoutMs = 30_000): void {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (tryAcquireResetLock(lockPath)) return;
    waitForResetLockRetry();
  }
  throw new Error(
    `Timed out waiting for schema-reset lock at ${lockPath}. Another kuzushi process may be upgrading the DB; if none is running, delete the lock file manually.`,
  );
}

function tryAcquireResetLock(lockPath: string): boolean {
  try {
    fs.writeFileSync(lockPath, String(process.pid), { flag: "wx" });
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") return false;
    throw error;
  }
}

function waitForResetLockRetry(): void {
  const waitMs = 200;
  const start = Date.now();
  while (Date.now() - start < waitMs) {}
}

function releaseResetLock(lockPath: string): void {
  try {
    fs.unlinkSync(lockPath);
  } catch {}
}

function defaultResetLogger(info: { oldVersion: number; backupPath: string }): void {
  console.warn(
    `kuzushi: schema reset v${info.oldVersion} -> v${CURRENT_SCHEMA_VERSION}; previous DB saved to ${info.backupPath}`,
  );
}
