/**
 * JobManager — background task registry for the shell.
 *
 * Inspired by msfconsole's `jobs` / `jobs -l` / `jobs -k` (see
 * `lib/msf/core/job_manager.rb` in the vendored metasploit-framework clone).
 *
 * Usage from the dispatcher:
 *
 *   const id = mgr.start({ label: "sast:scan", kind: "tool" }, async (ctx) => {
 *     return await core.executeTool(...);
 *   });
 *
 *   mgr.list();                  // all active jobs
 *   mgr.get(id);                 // one job
 *   mgr.tail(id, (line) => ...); // follow buffered output
 *   mgr.kill(id);                // abort (via AbortSignal)
 *   mgr.clearCompleted();        // prune done/failed/cancelled rows
 *
 * Buffered output is capped per-job to keep memory bounded. The manager emits
 * lifecycle events (`started`, `completed`, `failed`, `cancelled`) so the
 * prompt status provider + desktop notifier can react without polling.
 */

import { EventEmitter } from "node:events";

import { toErrorMessage } from "../utils.js";
export type JobState = "running" | "completed" | "failed" | "cancelled";

export interface JobRecord {
  id: string;
  label: string;
  kind: "tool" | "recipe" | "resource" | "custom";
  state: JobState;
  startedAt: number;
  endedAt?: number;
  /** Last-N lines of output emitted via the buffered sink. */
  output: string[];
  /** Summary line when the job ended (from ToolResult.output typically). */
  result?: string;
  /** Error message when state === "failed". */
  error?: string;
}

export interface JobRunContext {
  signal: AbortSignal;
  /** Buffered output sink — call to log a line that `jobs -i <id>` tails. */
  log: (line: string) => void;
}

export interface StartJobOpts {
  label: string;
  kind?: JobRecord["kind"];
  /** Max lines of output to retain per job. Default 500. */
  maxOutputLines?: number;
}

export interface JobEvents {
  started: (job: JobRecord) => void;
  completed: (job: JobRecord) => void;
  failed: (job: JobRecord) => void;
  cancelled: (job: JobRecord) => void;
  /** Any line appended to a running job's output buffer. */
  log: (jobId: string, line: string) => void;
}

export class JobManager extends EventEmitter {
  private readonly jobs = new Map<string, JobRecord>();
  private readonly controllers = new Map<string, AbortController>();
  private readonly tailers = new Map<string, Set<(line: string) => void>>();
  private counter = 0;

  /** Start a new background job. Returns the job id. */
  start(opts: StartJobOpts, fn: (ctx: JobRunContext) => Promise<string | void>): string {
    const id = this.nextId();
    const maxLines = opts.maxOutputLines ?? 500;
    const record: JobRecord = {
      id,
      label: opts.label,
      kind: opts.kind ?? "tool",
      state: "running",
      startedAt: Date.now(),
      output: [],
    };
    const controller = new AbortController();
    this.jobs.set(id, record);
    this.controllers.set(id, controller);
    this.emit("started", record);

    const log = (line: string) => {
      record.output.push(line);
      if (record.output.length > maxLines) record.output.shift();
      this.emit("log", id, line);
      const tailers = this.tailers.get(id);
      if (tailers) for (const cb of tailers) cb(line);
    };

    void (async () => {
      try {
        const result = await fn({ signal: controller.signal, log });
        if (controller.signal.aborted) {
          // fn may have returned despite abort — honor the signal.
          record.state = "cancelled";
          record.endedAt = Date.now();
          this.emit("cancelled", record);
          return;
        }
        record.state = "completed";
        record.endedAt = Date.now();
        if (typeof result === "string") record.result = result;
        this.emit("completed", record);
      } catch (err) {
        if (controller.signal.aborted) {
          record.state = "cancelled";
          record.endedAt = Date.now();
          this.emit("cancelled", record);
          return;
        }
        record.state = "failed";
        record.endedAt = Date.now();
        record.error = toErrorMessage(err);
        this.emit("failed", record);
      }
    })();

    return id;
  }

  /** Abort a job. Returns true if it was running. */
  kill(id: string): boolean {
    const controller = this.controllers.get(id);
    const record = this.jobs.get(id);
    if (!controller || !record || record.state !== "running") return false;
    controller.abort(new Error(`Job ${id} cancelled by operator`));
    return true;
  }

  /** Subscribe to output lines from a specific job. Returns an unsubscriber. */
  tail(id: string, cb: (line: string) => void): () => void {
    let set = this.tailers.get(id);
    if (!set) {
      set = new Set();
      this.tailers.set(id, set);
    }
    set.add(cb);
    return () => {
      set?.delete(cb);
      if (set && set.size === 0) this.tailers.delete(id);
    };
  }

  /** Lookup a job by id. */
  get(id: string): JobRecord | undefined {
    return this.jobs.get(id);
  }

  /** All jobs (active + terminal) ordered by start time, most recent first. */
  list(): JobRecord[] {
    return [...this.jobs.values()].sort((a, b) => b.startedAt - a.startedAt);
  }

  /** Active (running) jobs only. */
  active(): JobRecord[] {
    return this.list().filter((j) => j.state === "running");
  }

  /** Count of currently-running jobs. Convenience for the prompt status line. */
  activeCount(): number {
    return this.active().length;
  }

  /** Prune terminal jobs (completed / failed / cancelled). Returns how many were removed. */
  clearCompleted(): number {
    let removed = 0;
    for (const [id, record] of this.jobs) {
      if (record.state !== "running") {
        this.jobs.delete(id);
        this.controllers.delete(id);
        this.tailers.delete(id);
        removed++;
      }
    }
    return removed;
  }

  /** Abort every running job. Useful on shell exit. */
  async shutdown(): Promise<void> {
    for (const [id] of this.controllers) this.kill(id);
    // Wait one microtask tick so cancelled events flush.
    await new Promise((resolve) => setImmediate(resolve));
  }

  private nextId(): string {
    this.counter++;
    return String(this.counter);
  }
}
