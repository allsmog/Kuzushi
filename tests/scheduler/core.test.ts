/**
 * Scheduler — interval-based runner on top of JobManager.
 *
 * Uses the `now` injection knob to advance the clock deterministically
 * so tests don't actually sleep for intervals.
 */

import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { afterEach, describe, expect, it, vi } from "vitest";
import { JobManager } from "../../src/jobs/manager.js";
import { migration100 } from "../../src/migrations/100_schema_reset.js";
import { migration101 } from "../../src/migrations/101_workspace_entities.js";
import { migration102 } from "../../src/migrations/102_session_aliases.js";
import { migration103 } from "../../src/migrations/103_schedules.js";
import { migration104 } from "../../src/migrations/104_workspace_integrity_guards.js";
import { parseIntervalMs, Scheduler } from "../../src/scheduler/core.js";
import { SqliteScheduleStore } from "../../src/scheduler/store.js";

const tempDirs: string[] = [];

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

describe("parseIntervalMs", () => {
  it.each([
    ["5s", 5_000],
    ["10m", 600_000],
    ["2h", 7_200_000],
    ["1d", 86_400_000],
  ])("parses %s to %d ms", (spec, expected) => {
    expect(parseIntervalMs(spec)).toBe(expected);
  });

  it.each(["", "0m", "-1h", "abc", "5x"])("rejects %s", (bad) => {
    expect(parseIntervalMs(bad)).toBeNull();
  });
});

describe("Scheduler", () => {
  function mk(): { scheduler: Scheduler; jobs: JobManager; runCommand: ReturnType<typeof vi.fn> } {
    const jobs = new JobManager();
    const runCommand = vi.fn(async (_cmd: string) => "done");
    const scheduler = new Scheduler({ jobs, runCommand });
    return { scheduler, jobs, runCommand };
  }

  it("add registers and arms a schedule", () => {
    const { scheduler } = mk();
    scheduler.add("daily-scan", "1h", "recipes run quick-scan");
    expect(scheduler.list()).toHaveLength(1);
    expect(scheduler.armedCount()).toBe(1);
    scheduler.stop();
  });

  it("remove clears timers + schedule", () => {
    const { scheduler } = mk();
    scheduler.add("x", "1h", "help");
    expect(scheduler.remove("x")).toBe(true);
    expect(scheduler.list()).toHaveLength(0);
    expect(scheduler.armedCount()).toBe(0);
    expect(scheduler.remove("x")).toBe(false);
  });

  it("rejects invalid intervals", () => {
    const { scheduler } = mk();
    expect(() => scheduler.add("bad", "5x", "help")).toThrow("Invalid interval");
  });

  it("fires handlers via JobManager", async () => {
    const jobs = new JobManager();
    const runCommand = vi.fn(async () => "ran");
    const scheduler = new Scheduler({
      jobs,
      runCommand,
      now: () => 1_000,
    });
    // Register with a 0.05s interval so the timer fires quickly.
    scheduler.add("fast", "1s", "help");
    // Advance the clock: the scheduler's next-fire is +1000ms from now.
    // We can't actually make setTimeout elapse in test; instead, force
    // the fire path by manually invoking the timer via private access.
    // Simpler: use a very short interval with real setTimeout.
    scheduler.remove("fast");
    await new Promise<void>((resolve) => {
      // Register a 50ms-ish fire by replacing the scheduler with a real one.
      const tinyScheduler = new Scheduler({ jobs, runCommand });
      const added = (
        tinyScheduler as unknown as { add(l: string, i: string, c: string): { nextFireAt: number } }
      ).add("tiny", "1s", "help");
      // Mutate nextFireAt to "now" so the next arm fires immediately.
      added.nextFireAt = Date.now() - 1;
      // Force an arm cycle.
      (tinyScheduler as unknown as { arm(e: unknown): void }).arm?.(added);
      setTimeout(async () => {
        // Wait for the job to finish.
        while (jobs.list().length === 0) await new Promise((r) => setImmediate(r));
        tinyScheduler.stop();
        resolve();
      }, 30);
    });
    expect(jobs.list().length).toBeGreaterThanOrEqual(1);
    expect(runCommand).toHaveBeenCalledWith("help");
    expect(jobs.list()[0]?.label).toMatch(/^schedule:/);
  });

  it("persists + reloads via SqliteScheduleStore", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "kz-sched-"));
    tempDirs.push(dir);
    const db = new Database(path.join(dir, "x.sqlite3"));
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    migration100.up(db);
    migration101.up(db);
    migration102.up(db);
    migration103.up(db);
    migration104.up(db);
    const store = new SqliteScheduleStore(db);

    const jobs = new JobManager();
    const runCommand = vi.fn(async () => "ok");
    const s1 = new Scheduler({ jobs, store, runCommand });
    s1.add("persisted", "2h", "recipes run nightly");
    s1.stop();

    const s2 = new Scheduler({ jobs, store, runCommand });
    const rows = s2.list();
    expect(rows).toHaveLength(1);
    expect(rows[0]?.label).toBe("persisted");
    expect(rows[0]?.interval).toBe("2h");
    expect(rows[0]?.command).toBe("recipes run nightly");

    expect(store.remove("persisted")).toBe(true);
    expect(store.list()).toHaveLength(0);
  });

  it("rejects invalid persisted schedules below Scheduler.add", () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "kz-sched-"));
    tempDirs.push(dir);
    const db = new Database(path.join(dir, "x.sqlite3"));
    db.pragma("journal_mode = WAL");
    db.pragma("foreign_keys = ON");
    migration100.up(db);
    migration101.up(db);
    migration102.up(db);
    migration103.up(db);
    migration104.up(db);
    const store = new SqliteScheduleStore(db);

    expect(() =>
      store.upsert({
        label: "bad",
        interval: "0m",
        command: "help",
        lastFiredAt: null,
        nextFireAt: Date.now(),
      }),
    ).toThrow(/invalid persisted schedule/);

    expect(() =>
      store.upsert({
        label: "bad-time",
        interval: "5m",
        command: "help",
        lastFiredAt: null,
        nextFireAt: -1,
      }),
    ).toThrow(/invalid persisted schedule/);
  });
});
