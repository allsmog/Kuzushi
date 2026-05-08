/**
 * Scheduler — interval-based job dispatcher layered on JobManager.
 *
 * Inspired by cron, but intentionally simpler: each schedule specifies a
 * fixed interval (e.g. "5m", "1h", "24h"), not a cron expression. On each
 * tick the handler fires as a background job via `JobManager.start()`, so
 * long-running recipes never block the scheduler loop.
 *
 * Schedules persist to a new workspace table (migration 103) so an
 * active schedule survives a shell restart.
 */

import type { JobManager } from "../jobs/manager.js";

export interface ScheduleEntry {
  /** Human-friendly label. Must be unique. */
  label: string;
  /** Interval string — "Ns" / "Nm" / "Nh" / "Nd". */
  interval: string;
  /**
   * Operator-facing command the scheduler replays on each tick (e.g.
   * `"recipes run quick-scan"`). Stored verbatim; execution is the caller's
   * responsibility so the Scheduler stays free of shell coupling.
   */
  command: string;
  /** Epoch ms of last fire, or null if never fired. */
  lastFiredAt: number | null;
  /** Epoch ms of next scheduled fire. */
  nextFireAt: number;
}

export interface SchedulerStore {
  list(): ScheduleEntry[];
  upsert(entry: ScheduleEntry): void;
  remove(label: string): boolean;
}

export interface SchedulerOptions {
  jobs: JobManager;
  store?: SchedulerStore;
  /**
   * Handler that executes the replayed command. Typically wraps
   * `driver.handle(entry.command)`. Returns a promise that resolves
   * when the command finishes (errors are caught internally).
   */
  runCommand: (command: string) => Promise<string | void>;
  /**
   * Optional clock for deterministic tests. Defaults to `Date.now`.
   */
  now?: () => number;
}

export class Scheduler {
  private readonly schedules = new Map<string, ScheduleEntry>();
  private readonly timers = new Map<string, NodeJS.Timeout>();
  private readonly now: () => number;

  constructor(private readonly opts: SchedulerOptions) {
    this.now = opts.now ?? Date.now;
    if (opts.store) {
      for (const entry of opts.store.list()) {
        this.schedules.set(entry.label, entry);
      }
    }
  }

  /** Start all loaded schedules. Idempotent. */
  start(): void {
    for (const entry of this.schedules.values()) {
      this.arm(entry);
    }
  }

  /** Cancel every armed timer. Schedules remain in memory + storage. */
  stop(): void {
    for (const timer of this.timers.values()) clearTimeout(timer);
    this.timers.clear();
  }

  /** Register a new schedule. Replaces any prior schedule with the same label. */
  add(label: string, interval: string, command: string): ScheduleEntry {
    const ms = parseIntervalMs(interval);
    if (ms === null) throw new Error(`Invalid interval: ${interval}`);
    const existing = this.schedules.get(label);
    if (existing) {
      const timer = this.timers.get(label);
      if (timer) clearTimeout(timer);
      this.timers.delete(label);
    }
    const entry: ScheduleEntry = {
      label,
      interval,
      command,
      lastFiredAt: null,
      nextFireAt: this.now() + ms,
    };
    this.schedules.set(label, entry);
    this.opts.store?.upsert(entry);
    this.arm(entry);
    return entry;
  }

  /** Remove a schedule by label. Returns true if one existed. */
  remove(label: string): boolean {
    const timer = this.timers.get(label);
    if (timer) clearTimeout(timer);
    this.timers.delete(label);
    const existed = this.schedules.delete(label);
    this.opts.store?.remove(label);
    return existed;
  }

  /** Snapshot of all registered schedules. */
  list(): ScheduleEntry[] {
    return [...this.schedules.values()].sort((a, b) => a.nextFireAt - b.nextFireAt);
  }

  /** Number of armed timers (test helper). */
  armedCount(): number {
    return this.timers.size;
  }

  private arm(entry: ScheduleEntry): void {
    const ms = parseIntervalMs(entry.interval);
    if (ms === null) return;
    const delay = Math.max(0, entry.nextFireAt - this.now());
    const timer = setTimeout(async () => {
      await this.fire(entry);
    }, delay);
    // Node timers expose unref so the process can exit cleanly.
    if (typeof timer.unref === "function") timer.unref();
    this.timers.set(entry.label, timer);
  }

  private async fire(entry: ScheduleEntry): Promise<void> {
    this.opts.jobs.start({ label: `schedule:${entry.label}`, kind: "recipe" }, async (jobCtx) => {
      jobCtx.log(`[*] schedule fired: ${entry.label} (${entry.command})`);
      try {
        const out = await this.opts.runCommand(entry.command);
        if (typeof out === "string") jobCtx.log(out);
        return typeof out === "string" ? out : undefined;
      } catch (err) {
        jobCtx.log(
          `[-] schedule '${entry.label}' failed: ${err instanceof Error ? err.message : err}`,
        );
        throw err;
      }
    });
    const ms = parseIntervalMs(entry.interval) ?? 60_000;
    entry.lastFiredAt = this.now();
    entry.nextFireAt = this.now() + ms;
    this.opts.store?.upsert(entry);
    this.arm(entry);
  }
}

/**
 * Parse `"5s"`, `"10m"`, `"2h"`, `"1d"` into milliseconds. Returns null
 * on unknown input.
 */
export function parseIntervalMs(spec: string): number | null {
  const m = /^(\d+)\s*(s|m|h|d)$/i.exec(spec.trim());
  if (!m) return null;
  const n = Number.parseInt(m[1] ?? "", 10);
  if (!Number.isFinite(n) || n <= 0) return null;
  const unit = (m[2] ?? "").toLowerCase();
  switch (unit) {
    case "s":
      return n * 1000;
    case "m":
      return n * 60 * 1000;
    case "h":
      return n * 60 * 60 * 1000;
    case "d":
      return n * 24 * 60 * 60 * 1000;
    default:
      return null;
  }
}
