/**
 * `kuzushi scan inspect [--run-id <id>]` — pretty-print findings for
 * a given run (or latest run) directly from SQLite. Lets operators
 * eyeball results without writing a one-off SQL script and without
 * waiting for triage to complete.
 *
 * Field-test issue #43.
 */

import type Database from "better-sqlite3";
import { defaultDbPath, initDb } from "../../store.js";

export interface InspectOptions {
  runId?: string;
  repo?: string;
  severity?: string;
  task?: string;
  /** Cap the number of rows printed. Default 50. */
  limit?: number;
  /** Output as JSON instead of human-readable table. */
  json?: boolean;
  db?: string;
}

interface FindingRow {
  fingerprint: string;
  task_id: string;
  rule_id: string;
  file_path: string;
  start_line: number;
  severity: string;
  message: string;
  verdict: string;
  adjusted_score: number | null;
}

function pickLatestRunId(db: Database.Database): string | undefined {
  const row = db
    .prepare("SELECT run_id FROM pipeline_runs ORDER BY started_at DESC LIMIT 1")
    .get() as { run_id?: string } | undefined;
  return row?.run_id;
}

function loadFindings(
  db: Database.Database,
  opts: { severity?: string; task?: string; limit: number },
): FindingRow[] {
  const where: string[] = [];
  const params: unknown[] = [];
  if (opts.severity) {
    where.push("severity = ?");
    params.push(opts.severity);
  }
  if (opts.task) {
    where.push("task_id = ?");
    params.push(opts.task);
  }
  const whereClause = where.length > 0 ? `WHERE ${where.join(" AND ")}` : "";
  const sql = `
    SELECT fingerprint, task_id, rule_id, file_path, start_line, severity,
           substr(message, 1, 200) as message, verdict, adjusted_score
    FROM findings
    ${whereClause}
    ORDER BY adjusted_score DESC NULLS LAST, severity DESC
    LIMIT ?
  `;
  return db.prepare(sql).all(...params, opts.limit) as FindingRow[];
}

export async function runInspectCommand(opts: InspectOptions): Promise<void> {
  const repoRoot = opts.repo ?? process.cwd();
  const dbPath = opts.db ?? defaultDbPath(repoRoot);
  const db = initDb(dbPath);
  try {
    const runId = opts.runId ?? pickLatestRunId(db);
    if (!runId) {
      console.error(`No runs found in ${dbPath}.`);
      process.exitCode = 1;
      return;
    }
    const limit = opts.limit ?? 50;
    const findings = loadFindings(db, {
      severity: opts.severity,
      task: opts.task,
      limit,
    });

    if (opts.json) {
      console.log(JSON.stringify({ runId, count: findings.length, findings }, null, 2));
      return;
    }

    console.log(`Run: ${runId}`);
    console.log(`Findings (top ${limit}, by score desc):`);
    if (findings.length === 0) {
      console.log("  (none)");
      return;
    }

    for (const f of findings) {
      const rule = (f.rule_id ?? "").split(".").pop() || f.rule_id || "?";
      const path = (f.file_path ?? "").replace(`${repoRoot}/`, "");
      const verdictTag = f.verdict && f.verdict !== "needs_review" ? ` [${f.verdict}]` : "";
      const scoreTag = f.adjusted_score != null ? ` (score=${f.adjusted_score.toFixed(2)})` : "";
      console.log(`  [${f.severity}] ${rule}${verdictTag}${scoreTag}`);
      console.log(`    ${path}:${f.start_line ?? "?"}`);
      const msg = (f.message ?? "").replace(/\s+/g, " ").trim();
      if (msg) console.log(`    ${msg.slice(0, 160)}`);
    }

    console.log(
      `\nFiltered: severity=${opts.severity ?? "any"}, task=${opts.task ?? "any"}, limit=${limit}`,
    );
  } finally {
    db.close();
  }
}
