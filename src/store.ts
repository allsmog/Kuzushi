import Database from "better-sqlite3";
import path from "node:path";
import type {
  KuzushiConfig,
  PocHarnessResult,
  RepoContext,
  ScanOpts,
  TriageResult,
  VerificationResult,
  Verdict,
} from "./types.js";
import type { Finding, ScannerId } from "./scanners/types.js";
import { BATCH_TRIAGE_FALLBACK_RATIONALE } from "./triage.js";
import { ensureCalibrationSchema } from "./confidence-calibration.js";
import { ensureTrajectoryTable } from "./trajectory-memory.js";

export type PipelineRunStatus =
  | "scanning"
  | "triaging"
  | "verifying"
  | "poc-harnessing"
  | "complete"
  | "error";

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
      triage_details_json TEXT,
      verify_exploitable INTEGER,
      verify_poc_payload TEXT,
      verify_poc_description TEXT,
      verify_attack_vector TEXT,
      verify_preconditions TEXT,
      verify_confidence REAL,
      verify_cost_usd REAL,
      poc_harness_path TEXT,
      poc_harness_language TEXT,
      poc_harness_parsed INTEGER,
      poc_harness_parse_error TEXT,
      poc_harness_skipped INTEGER,
      poc_harness_skip_reason TEXT,
      poc_harness_cost_usd REAL,
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
      status         TEXT NOT NULL CHECK (status IN ('scanning','triaging','verifying','poc-harnessing','complete','error')),
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
  ensureTriageDetailsColumn(db);
  ensureVerificationColumns(db);
  ensurePocHarnessColumns(db);
  ensurePocExecutionColumns(db);
  ensurePipelineRunsStatusValues(db);
  ensurePipelineRunContextColumn(db);
  ensureCalibrationSchema(db);
  ensureTrajectoryTable(db);

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
      rationale, verification_steps, fix_patch, triage_cost_usd, triage_details_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(fingerprint) DO UPDATE SET
      scanner=excluded.scanner,
      verdict=excluded.verdict,
      confidence=excluded.confidence,
      rationale=excluded.rationale,
      verification_steps=excluded.verification_steps,
      fix_patch=excluded.fix_patch,
      triage_cost_usd=excluded.triage_cost_usd,
      triage_details_json=excluded.triage_details_json,
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
    JSON.stringify({
      source: triage.source ?? null,
      sink: triage.sink ?? null,
      is_vulnerable: triage.isVulnerable ?? null,
      exploit_scenario: triage.exploitScenario ?? null,
      recommended_fix: triage.recommendedFix ?? null,
      rule_refinement_hint: triage.ruleRefinementHint ?? null,
      triage_schema_version: triage.triageSchemaVersion ?? null,
    }),
  );
}

/** Get set of already-triaged fingerprints from the database.
 *  Excludes findings with the batch-drop fallback signature (confidence=0,
 *  fallback rationale) so they get re-queued on subsequent runs. */
export function getTriagedFingerprints(db: Database.Database): Set<string> {
  const rows = db.prepare(
    "SELECT fingerprint FROM findings WHERE NOT (confidence = 0 AND rationale = ?)",
  ).all(BATCH_TRIAGE_FALLBACK_RATIONALE) as Array<{
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

/** Get set of fingerprints with completed PoC harness generation. */
export function getPocHarnessedFingerprints(db: Database.Database): Set<string> {
  const rows = db.prepare(
    `SELECT fingerprint FROM findings
     WHERE poc_harness_path IS NOT NULL OR poc_harness_skipped IS NOT NULL`,
  ).all() as Array<{ fingerprint: string }>;

  return new Set(rows.map((row) => row.fingerprint));
}

/** SQLite max bind parameters per query — stay under the 999 default. */
const SQLITE_BIND_LIMIT = 900;

/** Load persisted triage results for a set of fingerprints. */
export function getStoredTriageResults(
  db: Database.Database,
  fingerprints: string[],
): Map<string, TriageResult> {
  const uniqueFingerprints = [...new Set(fingerprints.filter(Boolean))];
  if (uniqueFingerprints.length === 0) {
    return new Map<string, TriageResult>();
  }

  const allRows: Array<{
    fingerprint: string;
    verdict: Verdict;
    confidence: number;
    rationale: string;
    verificationSteps: string;
    fixPatch: string | null;
    triageCostUsd: number | null;
    triageDetailsJson: string | null;
  }> = [];

  for (let i = 0; i < uniqueFingerprints.length; i += SQLITE_BIND_LIMIT) {
    const chunk = uniqueFingerprints.slice(i, i + SQLITE_BIND_LIMIT);
    const placeholders = chunk.map(() => "?").join(", ");
    const rows = db.prepare(`
      SELECT
        fingerprint,
        verdict,
        confidence,
        rationale,
        verification_steps as verificationSteps,
        fix_patch as fixPatch,
        triage_cost_usd as triageCostUsd,
        triage_details_json as triageDetailsJson
      FROM findings
      WHERE fingerprint IN (${placeholders})
    `).all(...chunk) as typeof allRows;
    allRows.push(...rows);
  }

  const results = new Map<string, TriageResult>();
  for (const row of allRows) {
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
      ...parseTriageDetails(row.triageDetailsJson),
      triageCostUsd: row.triageCostUsd ?? undefined,
    });
  }

  return results;
}

function parseTriageDetails(raw: string | null): Partial<TriageResult> {
  if (!raw) {
    return {};
  }

  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    const source = parsePathAssessment(parsed["source"]);
    const sink = parsePathAssessment(parsed["sink"]);
    return {
      source,
      sink,
      isVulnerable: typeof parsed["is_vulnerable"] === "boolean" ? parsed["is_vulnerable"] : undefined,
      exploitScenario: asOptionalString(parsed["exploit_scenario"]),
      recommendedFix: asOptionalString(parsed["recommended_fix"]),
      ruleRefinementHint: asOptionalString(parsed["rule_refinement_hint"]),
      triageSchemaVersion: asOptionalString(parsed["triage_schema_version"]),
    };
  } catch {
    return {};
  }
}

function parsePathAssessment(value: unknown): TriageResult["source"] | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const asRecord = value as Record<string, unknown>;
  const why = asOptionalString(asRecord["why"]);
  const evidence = asOptionalString(asRecord["evidence"]);
  const isFalsePositive = asRecord["isFalsePositive"] === true || asRecord["is_false_positive"] === true;
  if (!why && !evidence) {
    return undefined;
  }
  return {
    why: why ?? "",
    evidence: evidence ?? "",
    isFalsePositive,
  };
}

function asOptionalString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed || undefined;
}

/** Load persisted verification results for a set of fingerprints. */
export function getStoredVerificationResults(
  db: Database.Database,
  fingerprints: string[],
): Map<string, VerificationResult> {
  const uniqueFingerprints = [...new Set(fingerprints.filter(Boolean))];
  if (uniqueFingerprints.length === 0) {
    return new Map<string, VerificationResult>();
  }

  type VerifyRow = {
    fingerprint: string;
    verifyExploitable: number;
    verifyPocPayload: string | null;
    verifyPocDescription: string | null;
    verifyAttackVector: string | null;
    verifyPreconditions: string | null;
    verifyConfidence: number | null;
    verifyCostUsd: number | null;
  };

  const allRows: VerifyRow[] = [];
  for (let i = 0; i < uniqueFingerprints.length; i += SQLITE_BIND_LIMIT) {
    const chunk = uniqueFingerprints.slice(i, i + SQLITE_BIND_LIMIT);
    const placeholders = chunk.map(() => "?").join(", ");
    const rows = db.prepare(`
      SELECT
        fingerprint,
        verify_exploitable as verifyExploitable,
        verify_poc_payload as verifyPocPayload,
        verify_poc_description as verifyPocDescription,
        verify_attack_vector as verifyAttackVector,
        verify_preconditions as verifyPreconditions,
        verify_confidence as verifyConfidence,
        verify_cost_usd as verifyCostUsd
      FROM findings
      WHERE fingerprint IN (${placeholders}) AND verify_exploitable IS NOT NULL
    `).all(...chunk) as VerifyRow[];
    allRows.push(...rows);
  }

  const results = new Map<string, VerificationResult>();
  for (const row of allRows) {
    let preconditions: string[] = [];
    if (row.verifyPreconditions) {
      try {
        const parsed = JSON.parse(row.verifyPreconditions);
        if (Array.isArray(parsed)) {
          preconditions = parsed.map((item) => String(item).trim()).filter(Boolean);
        }
      } catch {
        preconditions = [];
      }
    }

    results.set(row.fingerprint, {
      fingerprint: row.fingerprint,
      exploitable: row.verifyExploitable === 1,
      pocPayload: row.verifyPocPayload,
      pocDescription: row.verifyPocDescription ?? "",
      attackVector: row.verifyAttackVector,
      preconditions,
      confidence: row.verifyConfidence ?? 0,
      verifyCostUsd: row.verifyCostUsd ?? undefined,
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

/** Get total PoC harness generation cost in USD from persisted findings. */
export function getTotalPocHarnessCost(db: Database.Database, repo?: string): number {
  const query = repo
    ? "SELECT COALESCE(SUM(COALESCE(poc_harness_cost_usd, 0)), 0) as total FROM findings WHERE repo = ?"
    : "SELECT COALESCE(SUM(COALESCE(poc_harness_cost_usd, 0)), 0) as total FROM findings";

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

/** Get PoC harness generation counts. */
export function getPocHarnessCounts(
  db: Database.Database,
  repo?: string,
): { generated: number; skipped: number } {
  const query = repo
    ? `SELECT
         SUM(CASE WHEN poc_harness_skipped = 1 THEN 1 ELSE 0 END) as skipped,
         SUM(CASE WHEN poc_harness_path IS NOT NULL AND COALESCE(poc_harness_skipped, 0) = 0 THEN 1 ELSE 0 END) as generated
       FROM findings
       WHERE repo = ?`
    : `SELECT
         SUM(CASE WHEN poc_harness_skipped = 1 THEN 1 ELSE 0 END) as skipped,
         SUM(CASE WHEN poc_harness_path IS NOT NULL AND COALESCE(poc_harness_skipped, 0) = 0 THEN 1 ELSE 0 END) as generated
       FROM findings`;

  const row = (
    repo
      ? db.prepare(query).get(repo)
      : db.prepare(query).get()
  ) as { generated?: number; skipped?: number } | undefined;

  return {
    generated: row?.generated ?? 0,
    skipped: row?.skipped ?? 0,
  };
}

/** Get triaged findings, ordered by verdict priority and confidence. */
export function getActionableFindings(
  db: Database.Database,
  repo?: string,
  options: {
    includeFalsePositives?: boolean;
    fingerprints?: string[];
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
  pocHarnessPath: string | null;
  pocHarnessLanguage: string | null;
  pocHarnessParsed: number | null;
  pocHarnessParseError: string | null;
  pocHarnessSkipped: number | null;
  pocHarnessSkipReason: string | null;
  pocHarnessCostUsd: number | null;
}> {
  const filters: string[] = [];
  const params: unknown[] = [];
  if (!options.includeFalsePositives) {
    filters.push("verdict != 'fp'");
  }
  if (repo) {
    filters.push("repo = ?");
    params.push(repo);
  }
  if (options.fingerprints && options.fingerprints.length > 0 && options.fingerprints.length <= SQLITE_BIND_LIMIT - params.length) {
    const placeholders = options.fingerprints.map(() => "?").join(", ");
    filters.push(`fingerprint IN (${placeholders})`);
    params.push(...options.fingerprints);
  } else if (options.fingerprints && options.fingerprints.length > 0) {
    // For large fingerprint sets, use a temp table to avoid SQLite bind limit
    db.prepare("CREATE TEMP TABLE IF NOT EXISTS _fp_filter (fingerprint TEXT PRIMARY KEY)").run();
    db.prepare("DELETE FROM _fp_filter").run();
    const insert = db.prepare("INSERT OR IGNORE INTO _fp_filter (fingerprint) VALUES (?)");
    for (const fp of options.fingerprints) {
      insert.run(fp);
    }
    filters.push("fingerprint IN (SELECT fingerprint FROM _fp_filter)");
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
           verify_cost_usd as verifyCostUsd,
           poc_harness_path as pocHarnessPath,
           poc_harness_language as pocHarnessLanguage,
           poc_harness_parsed as pocHarnessParsed,
           poc_harness_parse_error as pocHarnessParseError,
           poc_harness_skipped as pocHarnessSkipped,
           poc_harness_skip_reason as pocHarnessSkipReason,
           poc_harness_cost_usd as pocHarnessCostUsd
    FROM findings ${where}
    ORDER BY
      CASE verdict WHEN 'tp' THEN 0 WHEN 'needs_review' THEN 1 ELSE 2 END,
      confidence DESC
  `;

  const rows = db.prepare(query).all(...params);

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
    pocHarnessPath: string | null;
    pocHarnessLanguage: string | null;
    pocHarnessParsed: number | null;
    pocHarnessParseError: string | null;
    pocHarnessSkipped: number | null;
    pocHarnessSkipReason: string | null;
    pocHarnessCostUsd: number | null;
  }>;
}

export function getTriagedFindingsForRepo(
  db: Database.Database,
  repo: string,
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
  verificationSteps: string[];
  fixPatch: string | null;
  triageDetails: Record<string, unknown> | null;
}> {
  const rows = db.prepare(`
    SELECT
      scanner,
      fingerprint,
      rule_id as ruleId,
      file_path as filePath,
      start_line as startLine,
      severity,
      message,
      verdict,
      confidence,
      rationale,
      verification_steps as verificationSteps,
      fix_patch as fixPatch,
      triage_details_json as triageDetailsJson
    FROM findings
    WHERE repo = ?
    ORDER BY updated_at DESC, confidence DESC
  `).all(repo) as Array<{
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
    verificationSteps: string;
    fixPatch: string | null;
    triageDetailsJson: string | null;
  }>;

  return rows.map((row) => {
    let verificationSteps: string[] = [];
    try {
      const parsed = JSON.parse(row.verificationSteps);
      if (Array.isArray(parsed)) {
        verificationSteps = parsed.map((value) => String(value));
      }
    } catch {
      verificationSteps = [];
    }

    let triageDetails: Record<string, unknown> | null = null;
    if (row.triageDetailsJson) {
      try {
        const parsed = JSON.parse(row.triageDetailsJson);
        if (parsed && typeof parsed === "object") {
          triageDetails = parsed as Record<string, unknown>;
        }
      } catch {
        triageDetails = null;
      }
    }

    return {
      scanner: row.scanner,
      fingerprint: row.fingerprint,
      ruleId: row.ruleId,
      filePath: row.filePath,
      startLine: row.startLine,
      severity: row.severity,
      message: row.message,
      verdict: row.verdict,
      confidence: row.confidence,
      rationale: row.rationale,
      verificationSteps,
      fixPatch: row.fixPatch,
      triageDetails,
    };
  });
}

/** Delete findings by fingerprint for a specific repo. Returns number of deleted rows. */
export function deleteFindingsByFingerprints(
  db: Database.Database,
  repo: string,
  fingerprints: string[],
): number {
  const uniqueFingerprints = [...new Set(fingerprints.filter(Boolean))];
  if (uniqueFingerprints.length === 0) {
    return 0;
  }

  let totalChanges = 0;
  for (let i = 0; i < uniqueFingerprints.length; i += SQLITE_BIND_LIMIT - 1) {
    const chunk = uniqueFingerprints.slice(i, i + SQLITE_BIND_LIMIT - 1);
    const placeholders = chunk.map(() => "?").join(", ");
    const result = db
      .prepare(`DELETE FROM findings WHERE repo = ? AND fingerprint IN (${placeholders})`)
      .run(repo, ...chunk);
    totalChanges += result.changes;
  }

  return totalChanges;
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

function ensureTriageDetailsColumn(db: Database.Database): void {
  const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
  const hasTriageDetails = columns.some((column) => column.name === "triage_details_json");
  if (!hasTriageDetails) {
    db.exec("ALTER TABLE findings ADD COLUMN triage_details_json TEXT");
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

function ensurePocHarnessColumns(db: Database.Database): void {
  const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
  const columnNames = new Set(columns.map((column) => column.name));

  if (!columnNames.has("poc_harness_path")) {
    db.exec("ALTER TABLE findings ADD COLUMN poc_harness_path TEXT");
  }
  if (!columnNames.has("poc_harness_language")) {
    db.exec("ALTER TABLE findings ADD COLUMN poc_harness_language TEXT");
  }
  if (!columnNames.has("poc_harness_parsed")) {
    db.exec("ALTER TABLE findings ADD COLUMN poc_harness_parsed INTEGER");
  }
  if (!columnNames.has("poc_harness_parse_error")) {
    db.exec("ALTER TABLE findings ADD COLUMN poc_harness_parse_error TEXT");
  }
  if (!columnNames.has("poc_harness_skipped")) {
    db.exec("ALTER TABLE findings ADD COLUMN poc_harness_skipped INTEGER");
  }
  if (!columnNames.has("poc_harness_skip_reason")) {
    db.exec("ALTER TABLE findings ADD COLUMN poc_harness_skip_reason TEXT");
  }
  if (!columnNames.has("poc_harness_cost_usd")) {
    db.exec("ALTER TABLE findings ADD COLUMN poc_harness_cost_usd REAL");
  }
}

function ensurePocExecutionColumns(db: Database.Database): void {
  const columns = db.prepare("PRAGMA table_info(findings)").all() as Array<{ name: string }>;
  const names = new Set(columns.map((column) => column.name));

  const migrations: Array<[string, string]> = [
    ["poc_run_exit_code", "INTEGER"],
    ["poc_run_stdout", "TEXT"],
    ["poc_run_stderr", "TEXT"],
    ["poc_run_verdict", "TEXT"],
    ["poc_run_duration_ms", "REAL"],
  ];
  for (const [col, typ] of migrations) {
    if (!names.has(col)) {
      db.prepare(`ALTER TABLE findings ADD COLUMN ${col} ${typ}`).run();
    }
  }
}

function ensurePipelineRunsStatusValues(db: Database.Database): void {
  const tableSql = db.prepare(
    "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'pipeline_runs'",
  ).get() as { sql?: string } | undefined;

  if (!tableSql?.sql) {
    return;
  }

  if (tableSql.sql.includes("'verifying'") && tableSql.sql.includes("'poc-harnessing'")) {
    return;
  }

  const contextSelect = tableSql.sql.includes("context_json") ? "context_json" : "NULL";

  const migrate = db.transaction(() => {
    db.prepare(`
      CREATE TABLE IF NOT EXISTS pipeline_runs_v2 (
        run_id         TEXT PRIMARY KEY,
        repo           TEXT NOT NULL,
        started_at     TEXT NOT NULL,
        status         TEXT NOT NULL CHECK (status IN ('scanning','triaging','verifying','poc-harnessing','complete','error')),
        config_json    TEXT NOT NULL,
        scan_opts_json TEXT NOT NULL,
        findings_json  TEXT,
        context_json   TEXT,
        total_cost_usd REAL NOT NULL DEFAULT 0,
        completed_at   TEXT,
        updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
      )
    `).run();

    db.prepare(`
      INSERT INTO pipeline_runs_v2 (
        run_id, repo, started_at, status, config_json, scan_opts_json,
        findings_json, context_json, total_cost_usd, completed_at, updated_at
      )
      SELECT
        run_id, repo, started_at, status, config_json, scan_opts_json,
        findings_json, ${contextSelect}, total_cost_usd, completed_at, updated_at
      FROM pipeline_runs
    `).run();

    db.prepare("DROP TABLE pipeline_runs").run();
    db.prepare("ALTER TABLE pipeline_runs_v2 RENAME TO pipeline_runs").run();
    db.prepare("CREATE INDEX IF NOT EXISTS idx_pipeline_runs_repo_status ON pipeline_runs(repo, status)").run();
    db.prepare("CREATE INDEX IF NOT EXISTS idx_pipeline_runs_started_at ON pipeline_runs(started_at DESC)").run();
  });

  migrate();
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

/** Persist PoC harness generation result fields for an existing finding row. */
export function updatePocHarnessResult(
  db: Database.Database,
  fingerprint: string,
  result: PocHarnessResult,
): void {
  db.prepare(`
    UPDATE findings
    SET
      poc_harness_path = ?,
      poc_harness_language = ?,
      poc_harness_parsed = ?,
      poc_harness_parse_error = ?,
      poc_harness_skipped = ?,
      poc_harness_skip_reason = ?,
      poc_harness_cost_usd = ?,
      updated_at = datetime('now')
    WHERE fingerprint = ?
  `).run(
    result.scriptPath,
    result.language,
    result.parsed ? 1 : 0,
    result.parseError,
    result.skipped ? 1 : 0,
    result.skipReason,
    result.costUsd ?? null,
    fingerprint,
  );
}

/** Persist PoC harness generation cost for a finding even when generation errors. */
export function updatePocHarnessCost(
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
      poc_harness_cost_usd = ?,
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
    WHERE repo = ? AND status IN ('scanning', 'triaging', 'verifying', 'poc-harnessing')
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
