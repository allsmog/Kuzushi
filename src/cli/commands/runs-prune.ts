/**
 * `kuzushi runs prune` — retention policy for past run artefacts.
 *
 * Two retention strategies (operator picks one):
 *   --older-than <duration>   '7d', '12h', '30m', '90s'
 *   --keep-last <n>           preserve N most recent runs (per repo)
 *
 * Removes both:
 *   - the run dir under `<repoRoot>/.kuzushi/runs/<runId>/`
 *   - the matching `pipeline_runs` row in `findings.sqlite3`
 *
 * Defaults to skipping in-flight runs (status in
 * scanning|running|triaging|verifying) so an operator's `prune --older-than 1h`
 * never wipes an active scan. Pass `--include-active` to opt out.
 *
 * `--dry-run` lists candidates without deleting.
 */

import { existsSync, rmSync } from "node:fs";
import path from "node:path";
import type { PipelineRunRecord } from "../../store.js";
import { defaultDbPath, deleteRun, initDb, listRuns } from "../../store.js";
import { CliUsageError } from "../errors.js";
import { resolveRepo } from "../shared.js";

export interface RunsPruneOpts {
  repo: string;
  olderThan?: string;
  keepLast?: number;
  dryRun?: boolean;
  includeActive?: boolean;
  status?: string;
}

const DURATION_RE = /^(\d+)\s*(s|m|h|d|w)$/i;

const ACTIVE_STATUSES: ReadonlySet<string> = new Set([
  "scanning",
  "running",
  "triaging",
  "verifying",
  "pending",
]);

/**
 * Parse a retention duration like `7d`, `12h`. Returns the duration in
 * milliseconds. Throws CliUsageError on malformed input.
 */
export function parseDuration(input: string): number {
  const trimmed = input.trim().toLowerCase();
  const match = DURATION_RE.exec(trimmed);
  if (!match) {
    throw new CliUsageError(
      `Invalid duration "${input}". Expected formats: 90s, 30m, 12h, 7d, 4w.`,
    );
  }
  const value = Number.parseInt(match[1]!, 10);
  const unit = match[2]!.toLowerCase();
  const factor =
    unit === "s"
      ? 1_000
      : unit === "m"
        ? 60_000
        : unit === "h"
          ? 3_600_000
          : unit === "d"
            ? 86_400_000
            : 86_400_000 * 7; // 'w'
  return value * factor;
}

/**
 * Pure planner — given a list of runs and the prune options, return the
 * runs that should be deleted. Exported for tests.
 */
export function planPrune(
  runs: ReadonlyArray<PipelineRunRecord>,
  opts: { olderThanMs?: number; keepLast?: number; includeActive?: boolean; now?: number },
): PipelineRunRecord[] {
  const now = opts.now ?? Date.now();
  const includeActive = opts.includeActive === true;

  // Filter out active runs unless --include-active.
  const eligible = runs.filter((r) => {
    if (includeActive) return true;
    const status = (r.status ?? "").toLowerCase();
    return !ACTIVE_STATUSES.has(status);
  });

  let candidates: PipelineRunRecord[] = [];

  if (opts.olderThanMs != null) {
    const cutoff = now - opts.olderThanMs;
    candidates = eligible.filter((r) => {
      const reference = r.completedAt ?? r.startedAt;
      if (!reference) return false;
      const ms = Date.parse(reference);
      if (!Number.isFinite(ms)) return false;
      return ms < cutoff;
    });
  } else if (opts.keepLast != null) {
    // Group by repo, sort by startedAt desc, keep first N, prune rest.
    const byRepo = new Map<string, PipelineRunRecord[]>();
    for (const run of eligible) {
      const list = byRepo.get(run.repo) ?? [];
      list.push(run);
      byRepo.set(run.repo, list);
    }
    for (const list of byRepo.values()) {
      list.sort((a, b) => {
        const av = Date.parse(a.startedAt ?? "");
        const bv = Date.parse(b.startedAt ?? "");
        return (Number.isFinite(bv) ? bv : 0) - (Number.isFinite(av) ? av : 0);
      });
      candidates.push(...list.slice(opts.keepLast));
    }
  }

  return candidates;
}

export interface PruneResult {
  candidates: PipelineRunRecord[];
  deletedRows: number;
  deletedDirs: number;
  errors: Array<{ runId: string; reason: string }>;
}

export function executePrune(
  runs: ReadonlyArray<PipelineRunRecord>,
  opts: { olderThanMs?: number; keepLast?: number; includeActive?: boolean; dryRun?: boolean },
  io: {
    deleteRow: (runId: string) => boolean;
    runDirOf: (run: PipelineRunRecord) => string;
    rmDir: (dir: string) => void;
  },
): PruneResult {
  const candidates = planPrune(runs, opts);
  const result: PruneResult = {
    candidates,
    deletedRows: 0,
    deletedDirs: 0,
    errors: [],
  };
  if (opts.dryRun) return result;
  for (const run of candidates) {
    try {
      if (io.deleteRow(run.runId)) result.deletedRows += 1;
    } catch (err) {
      result.errors.push({ runId: run.runId, reason: (err as Error).message });
    }
    try {
      const dir = io.runDirOf(run);
      io.rmDir(dir);
      result.deletedDirs += 1;
    } catch (err) {
      result.errors.push({ runId: run.runId, reason: (err as Error).message });
    }
  }
  return result;
}

export function runRunsPrune(opts: RunsPruneOpts): void {
  if (!opts.olderThan && opts.keepLast == null) {
    throw new CliUsageError("Specify exactly one of --older-than <duration> or --keep-last <n>.");
  }
  if (opts.olderThan && opts.keepLast != null) {
    throw new CliUsageError("Pass only one of --older-than or --keep-last, not both.");
  }
  if (opts.keepLast != null && (!Number.isFinite(opts.keepLast) || opts.keepLast < 0)) {
    throw new CliUsageError("--keep-last must be a non-negative integer.");
  }

  const olderThanMs = opts.olderThan ? parseDuration(opts.olderThan) : undefined;

  const { root } = resolveRepo(opts.repo);
  const dbPath = defaultDbPath(root);
  if (!existsSync(dbPath)) {
    console.log(`No runs database at ${dbPath}; nothing to prune.`);
    return;
  }
  const db = initDb(dbPath);
  try {
    const runs = listRuns(db, {
      limit: 10_000,
      ...(opts.status ? { status: opts.status } : {}),
    });

    const result = executePrune(
      runs,
      {
        ...(olderThanMs != null ? { olderThanMs } : {}),
        ...(opts.keepLast != null ? { keepLast: opts.keepLast } : {}),
        includeActive: opts.includeActive === true,
        dryRun: opts.dryRun === true,
      },
      {
        deleteRow: (runId) => deleteRun(db, runId),
        runDirOf: (run) => path.join(run.repo, ".kuzushi", "runs", run.runId),
        rmDir: (dir) => {
          if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
        },
      },
    );

    if (result.candidates.length === 0) {
      console.log("No runs match the retention criteria.");
      return;
    }

    const action = opts.dryRun ? "Would prune" : "Pruned";
    console.log(`${action} ${result.candidates.length} run(s):`);
    for (const run of result.candidates) {
      const started = run.startedAt ?? "?";
      console.log(`  ${run.runId.padEnd(40)} ${(run.status ?? "?").padEnd(12)} ${started}`);
    }
    if (!opts.dryRun) {
      console.log(`\nDeleted ${result.deletedRows} DB row(s), ${result.deletedDirs} dir(s).`);
      if (result.errors.length > 0) {
        console.log(`${result.errors.length} error(s):`);
        for (const e of result.errors) {
          console.log(`  ${e.runId}: ${e.reason}`);
        }
      }
    }
  } finally {
    db.close();
  }
}
