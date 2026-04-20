/**
 * SQLite-backed SchedulerStore. Reads + writes the `schedules` table
 * defined in migration 103.
 */

import type Database from "better-sqlite3";
import type { ScheduleEntry, SchedulerStore } from "./core.js";

interface Row {
  label: string;
  interval_spec: string;
  command: string;
  last_fired_at: number | null;
  next_fire_at: number;
}

export class SqliteScheduleStore implements SchedulerStore {
  constructor(private readonly db: Database.Database) {}

  list(): ScheduleEntry[] {
    const rows = this.db.prepare("SELECT * FROM schedules ORDER BY next_fire_at").all() as Row[];
    return rows.map(rowToEntry);
  }

  upsert(entry: ScheduleEntry): void {
    this.db
      .prepare(
        `INSERT INTO schedules (label, interval_spec, command, last_fired_at, next_fire_at)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(label) DO UPDATE SET
           interval_spec = excluded.interval_spec,
           command       = excluded.command,
           last_fired_at = excluded.last_fired_at,
           next_fire_at  = excluded.next_fire_at`,
      )
      .run(entry.label, entry.interval, entry.command, entry.lastFiredAt, entry.nextFireAt);
  }

  remove(label: string): boolean {
    const result = this.db.prepare("DELETE FROM schedules WHERE label = ?").run(label);
    return result.changes > 0;
  }
}

function rowToEntry(row: Row): ScheduleEntry {
  return {
    label: row.label,
    interval: row.interval_spec,
    command: row.command,
    lastFiredAt: row.last_fired_at ?? null,
    nextFireAt: row.next_fire_at,
  };
}
