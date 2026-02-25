import Database from "better-sqlite3";
import path from "node:path";
import type {
  KuzushiConfig,
  RepoContext,
  ScanOpts,
  TriageResult,
  VerificationResult,
  Verdict,
} from "./types.js";
import type { Finding, ScannerId } from "./scanners/types.js";

export type PipelineRunStatus = "scanning" | "triaging" | "verifying" | "complete" | "error";

export interface PipelineRunRecord {
  runId: string;
  repo: string;
  startedAt: string;
  status: PipelineRunStatus;
  configJson: string;
  scanOptsJson: string;
  findingsJson: string | null;
  contextJson: string | null;
  totalCostUsd: number;
  completedAt: string | null;
  updatedAt: string;
}

/** Initialize the SQLite database with the findings schema. */
export function initDb(dbPath: string): Database.Database {
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  db.exec(`
    CREATE TABLE IF NOT EXISTS findings (
      fingerprint        TEXT PRIMARY KEY,
      scanner            TEXT NOT NULL DEFAULT 'semgrep',
      repo               TEXT NOT NULL,
      ref                TEXT NOT NULL,
      rule_id            TEXT NOT NULL,
      file_path          TEXT NOT NULL,
      start_line         INTEGER NOT NULL,
      severity           TEXT NOT NULL,
      message            TEXT NOT NULL,
      verdict            TEXT NOT NULL CHECK (verdict IN ('tp','fp','needs_review')),
      confidence         REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
      rationale          TEXT NOT NULL,
      verification_steps TEXT NOT NULL,
      fix_patch          TEXT,
      triage_cost_usd    REAL,
      verify_exploitable INTEGER,
      verify_poc_payload TEXT,
      verify_poc_description TEXT,
      verify_attack_vector TEXT,
      verify_preconditions TEXT,
      verify_confidence REAL,
      verify_cost_usd REAL,
      created_at         TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_repo_ref ON findings(repo, ref);
    CREATE INDEX IF NOT EXISTS idx_scanner  ON findings(scanner);
    CREATE INDEX IF NOT EXISTS idx_rule_id  ON findings(rule_id);

    CREATE TABLE IF NOT EXISTS pipeline_runs (
      run_id         TEXT PRIMARY KEY,
      repo           TEXT NOT NULL,
      started_at     TEXT NOT NULL,
      status         TEXT NOT NULL CHECK (status IN ('scanning','triaging','verifying','complete','error')),
      config_json    TEXT NOT NULL,
      scan_opts_json TEXT NOT NULL,
      findings_json  TEXT,
      context_json   TEXT,
      total_cost_usd REAL NOT NULL DEFAULT 0,
      completed_at   TEXT,
      updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_pipeline_runs_repo_status ON pipeline_runs(repo, status);
    CREATE INDEX IF NOT EXISTS idx_pipeline_runs_started_at ON pipeline_runs(started_at DESC);
  `);

  ensureScannerColumn(db);
  ensureTriageCostColumn(db);
  ensureVerificationColumns(db);
  ensurePipelineRunsVerifyingStatus(db);
  ensurePipelineRunContextColumn(db);

  return db;
}

/** Default DB path: .kuzushi/findings.sqlite3 in the scanned repo root. */
export function defaultDbPath(repoRoot: string): string {
  return path.join(repoRoot, ".kuzushi", "findings.sqlite3");
}

/** Upsert a triage result into the database. */
export function upsertFinding(
  db: Database.Database,
  finding: Finding,
  triage: TriageResult,
  repo: string,
  ref: string,
): void {
  const stmt = db.prepare(`
    INSERT INTO findings (
      fingerprint, scanner, repo, ref, rule_id, file_path, start_line,
      severity, message, verdict, confidence,
      rationale, verification_steps, fix_patch, triage_cost_usd
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(fingerprint) DO UPDATE SET
      scanner=excluded.scanner,
      verdict=excluded.verdict,
      confidence=excluded.confidence,
      rationale=excluded.rationale,
      verification_steps=excluded.verification_steps,
      fix_patch=excluded.fix_patch,
      triage_cost_usd=excluded.triage_cost_usd,
      updated_at=datetime('now')
  `);

  stmt.run(
    triage.fingerprint,
    finding.scanner,
    repo,
    ref,
    finding.ruleId,
    finding.filePath,
    finding.startLine,
    finding.severity,
    finding.message,
    triage.verdict,
    triage.confidence,
    triage.rationale,
    JSON.stringify(triage.verificationSteps),
    triage.fixPatch,
    triage.triageCostUsd ?? null,
  );
}

/** Get set of already-triaged fingerprints from the database. */
export function getTriagedFingerprints(db: Database.Database): Set<string> {
  const rows = db.prepare("SELECT fingerprint FROM findings").all() as Array<{
    fingerprint: string;
  }>;
  return new Set(rows.map((r) => r.fingerprint));
}

/** Get set of already-verified fingerprints from the database. */
export function getVerifiedFingerprints(db: Database.Database): Set<string> {
  const rows = db.prepare(
    "SELECT fingerprint FROM findings WHERE verify_exploitable IS NOT NULL",
  ).all() as Array<{ fingerprint: string }>;

  return new Set(rows.map((row) => row.fingerprint));
}

/** Load persisted triage results for a set of fingerprints. */
export function getStoredTriageResults(
  db: Database.Database,
  fingerprints: string[],
): Map<string, TriageResult> {
  const uniqueFingerprints = [...new Set(fingerprints.filter(Boolean))];
  if (uniqueFingerprints.length === 0) {
    return new Map<string, TriageResult>();
  }

  const placeholders = uniqueFingerprints.map(() => "?").join(", ");
  const rows = db.prepare(`
    SELECT
      fingerprint,
      verdict,
      confidence,
      rationale,
      verification_steps as verificationSteps,
      fix_patch as fixPatch,
      triage_cost_usd as triageCostUsd
    FROM findings
    WHERE fingerprint IN (${placeholders})
  `).all(...uniqueFingerprints) as Array<{
    fingerprint: string;
    verdict: Verdict;
    confidence: number;
    rationale: string;
    verificationSteps: string;
    fixPatch: string | null;
    triageCostUsd: number | null;
  }>;

  const results = new Map<string, TriageResult>();
  for (const row of rows) {
    let verificationSteps: string[] = [];
    try {
      const parsed = JSON.parse(row.verificationSteps);
      if (Array.isArray(parsed)) {
        verificationSteps = parsed.map((step) => String(step)).filter(Boolean);
      }
    } catch {
      verificationSteps = [];
    }

    results.set(row.fingerprint, {
      fingerprint: row.fingerprint,
      verdict: row.verdict,
      confidence: row.confidence,
      rationale: row.rationale,
      verificationSteps,
      fixPatch: row.fixPatch,
      triageCostUsd: row.triageCostUsd ?? undefined,
    });
  }

  return results;
}

/** Get summary counts by verdict. */
export function getVerdictCounts(
  db: Database.Database,
  repo?: string,
): Record<Verdict, number> {
  const counts: Record<Verdict, number> = { tp: 0, fp: 0, needs_review: 0 };

  const query = repo
    ? "SELECT verdict, COUNT(*) as count FROM findings WHERE repo = ? GROUP BY verdict"
    : "SELECT verdict, COUNT(*) as count FROM findings GROUP BY verdict";

  const rows = (
    repo
      ? db.prepare(query).all(repo)
      : db.prepare(query).all()
  ) as Array<{ verdict: string; count: number }>;

  for (const row of rows) {
    if (row.verdict in counts) {
      counts[row.verdict as Verdict] = row.count;
    }
  }

  return counts;
}

/** Get total triage cost in USD from persisted findings. */
export function getTotalCost(db: Database.Database, repo?: string): number {
  const query = repo
    ? "SELECT COALESCE(SUM(COALESCE(triage_cost_usd, 0)), 0) as total FROM findings WHERE repo = ?"
    : "SELECT COALESCE(SUM(COALESCE(triage_cost_usd, 0)), 0) as total FROM findings";

  const row = (
    repo
      ? db.prepare(query).get(repo)
      : db.prepare(query).get()
  ) as { total?: number } | undefined;

  return row?.total ?? 0;
}

/** Get total verification cost in USD from persisted findings. */
export function getTotalVerificationCost(db: Database.Database, repo?: string): number {
  const query = repo
    ? "SELECT COALESCE(SUM(COALESCE(verify_cost_usd, 0)), 0) as total FROM findings WHERE repo = ?"
    : "SELECT COALESCE(SUM(COALESCE(verify_cost_usd, 0)), 0) as total FROM findings";

  const row = (
    repo
      ? db.prepare(query).get(repo)
      : db.prepare(query).get()
  ) as { total?: number } | undefined;

  return row?.total ?? 0;
}

/** Get verification counts grouped by exploitability outcome. */
export function getVerificationCounts(
  db: Database.Database,
  repo?: string,
): { exploitable: number; notExploitable: number } {
  const query = repo
    ? `SELECT verify_exploitable as verifyExploitable, COUNT(*) as count
       FROM findings
       WHERE repo = ? AND verify_exploitable IS NOT NULL
       GROUP BY verify_exploitable`
    : `SELECT verify_exploitable as verifyExploitable, COUNT(*) as count
       FROM findings
       WHERE verify_exploitable IS NOT NULL
       GROUP BY verify_exploitable`;

  const rows = (
    repo
      ? db.prepare(query).all(repo)
      : db.prepare(query).all()
  ) as Array<{ verifyExploitable: number; count: number }>;

  let exploitable = 0;
  let notExploitable = 0;
  for (const row of rows) {
    if (row.verifyExploitable === 1) {
      exploitable += row.count;
    } else if (row.verifyExploitable === 0) {
      notExploitable += row.count;
    }
  }

  return { exploitable, notExploitable };
}

/** Get triaged findings, ordered by verdict priority and confidence. */
export function getActionableFindings(
  db: Database.Database,
  repo?: string,
  options: {
    includeFalsePositives?: boolean;
  } = {},
): Array<{
  scanner: ScannerId;
  fingerprint: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  severity: string;
  message: string;
  verdict: Verdict;
  confidence: number;
  rationale: string;
  fixPatch: string | null;
  verifyExploitable: number | null;
  verifyPocPayload: string | null;
  verifyPocDescription: string | null;
  verifyAttackVector: string | null;
  verifyPreconditions: string | null;
  verifyConfidence: number | null;
  verifyCostUsd: number | null;
}> {
  const filters: string[] = [];
  if (!options.includeFalsePositives) {
    filters.push("verdict != 'fp'");
  }
  if (repo) {
    filters.push("repo = ?");
  }
  const where = filters.length > 0 ? `WHERE ${filters.join(" AND ")}` : "";

  const query = `
    SELECT scanner, fingerprint, rule_id as ruleId, file_path as filePath, start_line as startLine,
           severity, message, verdict, confidence, rationale,
           fix_patch as fixPatch,
           verify_exploitable as verifyExploitable,
           verify_poc_payload as verifyPocPayload,
           verify_poc_description as verifyPocDescription,
           verify_attack_vector as verifyAttackVector,
           verify_preconditions as verifyPreconditions,
           verify_confidence as verifyConfidence,
           verify_cost_usd as verifyCostUsd
    FROM findings ${where}
    ORDER BY
      CASE verdict WHEN 'tp' THEN 0 WHEN 'needs_review' THEN 1 ELSE 2 END,
      confidence DESC
  `;

  const rows = repo
    ? db.prepare(query).all(repo)
    : db.prepare(query).all();

  return rows as Array<{
    scanner: ScannerId;
    fingerprint: string;
    ruleId: string;
    filePath: string;
    startLine: number;
    severity: string;
    message: string;
    verdict: Verdict;
    confidence: number;
    rationale: string;
    fixPatch: string | null;
    verifyExploitable: number | null;
    verifyPocPayload: string | null;
    verifyPocDescription: string | null;
    verifyAttackVector: string | null;
    verifyPreconditions: string | null;
    verifyConfidence: number | null;
    verifyCostUsd: number | null;
  }>;
}

function ensureScannerColumn(db: Database.Database): void {
  const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
  const hasScanner = columns.some((column) => column.name === "scanner");
  if (!hasScanner) {
    db.exec("ALTER TABLE findings ADD COLUMN scanner TEXT NOT NULL DEFAULT 'semgrep'");
  }
}

function ensureTriageCostColumn(db: Database.Database): void {
  const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
  const hasTriageCost = columns.some((column) => column.name === "triage_cost_usd");
  if (!hasTriageCost) {
    db.exec("ALTER TABLE findings ADD COLUMN triage_cost_usd REAL");
  }
}

function ensureVerificationColumns(db: Database.Database): void {
  const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
  const columnNames = new Set(columns.map((column) => column.name));

  if (!columnNames.has("verify_exploitable")) {
    db.exec("ALTER TABLE findings ADD COLUMN verify_exploitable INTEGER");
  }
  if (!columnNames.has("verify_poc_payload")) {
    db.exec("ALTER TABLE findings ADD COLUMN verify_poc_payload TEXT");
  }
  if (!columnNames.has("verify_poc_description")) {
    db.exec("ALTER TABLE findings ADD COLUMN verify_poc_description TEXT");
  }
  if (!columnNames.has("verify_attack_vector")) {
    db.exec("ALTER TABLE findings ADD COLUMN verify_attack_vector TEXT");
  }
  if (!columnNames.has("verify_preconditions")) {
    db.exec("ALTER TABLE findings ADD COLUMN verify_preconditions TEXT");
  }
  if (!columnNames.has("verify_confidence")) {
    db.exec("ALTER TABLE findings ADD COLUMN verify_confidence REAL");
  }
  if (!columnNames.has("verify_cost_usd")) {
    db.exec("ALTER TABLE findings ADD COLUMN verify_cost_usd REAL");
  }
}

function ensurePipelineRunsVerifyingStatus(db: Database.Database): void {
  const tableSql = db.prepare(
    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_runs'",
  ).get() as { sql?: string } | undefined;

  if (!tableSql?.sql) {
    return;
  }

  if (tableSql.sql.includes("'verifying'")) {
    return;
  }

  db.exec(`
    BEGIN;

    CREATE TABLE IF NOT EXISTS pipeline_runs_v2 (
      run_id         TEXT PRIMARY KEY,
      repo           TEXT NOT NULL,
      started_at     TEXT NOT NULL,
      status         TEXT NOT NULL CHECK (status IN ('scanning','triaging','verifying','complete','error')),
      config_json    TEXT NOT NULL,
      scan_opts_json TEXT NOT NULL,
      findings_json  TEXT,
      context_json   TEXT,
      total_cost_usd REAL NOT NULL DEFAULT 0,
      completed_at   TEXT,
      updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
    );

    INSERT INTO pipeline_runs_v2 (
      run_id, repo, started_at, status, config_json, scan_opts_json,
      findings_json, context_json, total_cost_usd, completed_at, updated_at
    )
    SELECT
      run_id, repo, started_at, status, config_json, scan_opts_json,
      findings_json, NULL, total_cost_usd, completed_at, updated_at
    FROM pipeline_runs;

    DROP TABLE pipeline_runs;
    ALTER TABLE pipeline_runs_v2 RENAME TO pipeline_runs;

    CREATE INDEX IF NOT EXISTS idx_pipeline_runs_repo_status ON pipeline_runs(repo, status);
    CREATE INDEX IF NOT EXISTS idx_pipeline_runs_started_at ON pipeline_runs(started_at DESC);

    COMMIT;
  `);
}

function ensurePipelineRunContextColumn(db: Database.Database): void {
  const columns = db.prepare("PRAGMA table_info(pipeline_runs)").all() as Array<{ name: string }>;
  const hasContext = columns.some((column) => column.name === "context_json");
  if (!hasContext) {
    db.exec("ALTER TABLE pipeline_runs ADD COLUMN context_json TEXT");
  }
}

/** Create a new persisted pipeline run checkpoint. */
export function createRun(
  db: Database.Database,
  runId: string,
  repo: string,
  config: KuzushiConfig,
  scanOpts: ScanOpts,
): void {
  const stmt = db.prepare(`
    INSERT INTO pipeline_runs (
      run_id, repo, started_at, status, config_json, scan_opts_json
    ) VALUES (?, ?, ?, 'scanning', ?, ?)
  `);

  stmt.run(
    runId,
    repo,
    new Date().toISOString(),
    JSON.stringify(config),
    JSON.stringify(scanOpts),
  );
}

/** Update run status, optionally setting additional persisted fields. */
export function updateRunStatus(
  db: Database.Database,
  runId: string,
  status: PipelineRunStatus,
  extra: {
    findingsJson?: string | null;
    completedAt?: string | null;
  } = {},
): void {
  const fields: string[] = ["status = @status", "updated_at = datetime('now')"];
  const params: Record<string, unknown> = {
    runId,
    status,
  };

  if (extra.findingsJson !== undefined) {
    fields.push("findings_json = @findingsJson");
    params["findingsJson"] = extra.findingsJson;
  }

  if (extra.completedAt !== undefined) {
    fields.push("completed_at = @completedAt");
    params["completedAt"] = extra.completedAt;
  }

  if (extra.completedAt === undefined && status === "complete") {
    fields.push("completed_at = @completedAt");
    params["completedAt"] = new Date().toISOString();
  }

  const query = `
    UPDATE pipeline_runs
    SET ${fields.join(", ")}
    WHERE run_id = @runId
  `;

  db.prepare(query).run(params);
}

/** Persist ranked findings checkpoint after scan completes. */
export function updateRunFindings(
  db: Database.Database,
  runId: string,
  findings: Finding[],
): void {
  db.prepare(`
    UPDATE pipeline_runs
    SET findings_json = ?, updated_at = datetime('now')
    WHERE run_id = ?
  `).run(JSON.stringify(findings), runId);
}

/** Persist gathered repository context for resume support. */
export function updateRunContext(
  db: Database.Database,
  runId: string,
  repoContext: RepoContext,
): void {
  db.prepare(`
    UPDATE pipeline_runs
    SET context_json = ?, updated_at = datetime('now')
    WHERE run_id = ?
  `).run(JSON.stringify(repoContext), runId);
}

/** Increment persisted run cost in USD. */
export function updateRunCost(
  db: Database.Database,
  runId: string,
  costUsd: number,
): void {
  if (!Number.isFinite(costUsd)) {
    return;
  }

  db.prepare(`
    UPDATE pipeline_runs
    SET total_cost_usd = total_cost_usd + ?, updated_at = datetime('now')
    WHERE run_id = ?
  `).run(costUsd, runId);
}

/** Persist verification result fields for an existing finding row. */
export function updateVerificationResult(
  db: Database.Database,
  fingerprint: string,
  result: VerificationResult,
): void {
  db.prepare(`
    UPDATE findings
    SET
      verify_exploitable = ?,
      verify_poc_payload = ?,
      verify_poc_description = ?,
      verify_attack_vector = ?,
      verify_preconditions = ?,
      verify_confidence = ?,
      verify_cost_usd = ?,
      updated_at = datetime('now')
    WHERE fingerprint = ?
  `).run(
    result.exploitable ? 1 : 0,
    result.pocPayload,
    result.pocDescription,
    result.attackVector,
    JSON.stringify(result.preconditions),
    result.confidence,
    result.verifyCostUsd ?? null,
    fingerprint,
  );
}

/** Persist verification cost for a finding even when verification errors. */
export function updateVerificationCost(
  db: Database.Database,
  fingerprint: string,
  costUsd: number,
): void {
  if (!Number.isFinite(costUsd) || costUsd < 0) {
    return;
  }

  db.prepare(`
    UPDATE findings
    SET
      verify_cost_usd = ?,
      updated_at = datetime('now')
    WHERE fingerprint = ?
  `).run(costUsd, fingerprint);
}

/** Get latest resumable run for repo, if any. */
export function getLatestResumableRun(
  db: Database.Database,
  repo: string,
): PipelineRunRecord | undefined {
  const row = db.prepare(`
    SELECT
      run_id as runId,
      repo,
      started_at as startedAt,
      status,
      config_json as configJson,
      scan_opts_json as scanOptsJson,
      findings_json as findingsJson,
      context_json as contextJson,
      total_cost_usd as totalCostUsd,
      completed_at as completedAt,
      updated_at as updatedAt
    FROM pipeline_runs
    WHERE repo = ? AND status IN ('triaging', 'verifying')
    ORDER BY started_at DESC, rowid DESC
    LIMIT 1
  `).get(repo) as PipelineRunRecord | undefined;

  return row;
}

/** Get persisted run checkpoint by run id. */
export function getRun(
  db: Database.Database,
  runId: string,
): PipelineRunRecord | undefined {
  const row = db.prepare(`
    SELECT
      run_id as runId,
      repo,
      started_at as startedAt,
      status,
      config_json as configJson,
      scan_opts_json as scanOptsJson,
      findings_json as findingsJson,
      context_json as contextJson,
      total_cost_usd as totalCostUsd,
      completed_at as completedAt,
      updated_at as updatedAt
    FROM pipeline_runs
    WHERE run_id = ?
    LIMIT 1
  `).get(runId) as PipelineRunRecord | undefined;

  return row;
}
