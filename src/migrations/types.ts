import type Database from "better-sqlite3";

/** A single database migration. */
export interface Migration {
  /** Monotonically increasing version number. */
  version: number;
  /** Human-readable migration name. */
  name: string;
  /** Apply the migration (DDL / DML). Runs inside a transaction. */
  up: (db: Database.Database) => void;
}
