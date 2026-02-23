import Database from "better-sqlite3";
import path from "node:path";
import type { RawFinding, TriageResult, Verdict } from "./types.js";

/** Initialize the SQLite database with the findings schema. */
export function initDb(dbPath: string): Database.Database {
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  db.exec(`
    CREATE TABLE IF NOT EXISTS findings (
      fingerprint        TEXT PRIMARY KEY,
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
      created_at         TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at         TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE INDEX IF NOT EXISTS idx_repo_ref ON findings(repo, ref);
    CREATE INDEX IF NOT EXISTS idx_rule_id  ON findings(rule_id);
  `);

  return db;
}

/** Default DB path: .kuzushi/findings.sqlite3 in the scanned repo root. */
export function defaultDbPath(repoRoot: string): string {
  return path.join(repoRoot, ".kuzushi", "findings.sqlite3");
}

/** Upsert a triage result into the database. */
export function upsertFinding(
  db: Database.Database,
  finding: RawFinding,
  triage: TriageResult,
  repo: string,
  ref: string,
): void {
  const stmt = db.prepare(`
    INSERT INTO findings (
      fingerprint, repo, ref, rule_id, file_path, start_line,
      severity, message, verdict, confidence,
      rationale, verification_steps, fix_patch
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(fingerprint) DO UPDATE SET
      verdict=excluded.verdict,
      confidence=excluded.confidence,
      rationale=excluded.rationale,
      verification_steps=excluded.verification_steps,
      fix_patch=excluded.fix_patch,
      updated_at=datetime('now')
  `);

  stmt.run(
    triage.fingerprint,
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
  );
}

/** Get set of already-triaged fingerprints from the database. */
export function getTriagedFingerprints(db: Database.Database): Set<string> {
  const rows = db.prepare("SELECT fingerprint FROM findings").all() as Array<{
    fingerprint: string;
  }>;
  return new Set(rows.map((r) => r.fingerprint));
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

/** Get findings that need human review, ordered by confidence. */
export function getActionableFindings(
  db: Database.Database,
  repo?: string,
): Array<{
  fingerprint: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  severity: string;
  verdict: Verdict;
  confidence: number;
  rationale: string;
}> {
  const where = repo
    ? "WHERE verdict != 'fp' AND repo = ?"
    : "WHERE verdict != 'fp'";

  const query = `
    SELECT fingerprint, rule_id as ruleId, file_path as filePath, start_line as startLine,
           severity, verdict, confidence, rationale
    FROM findings ${where}
    ORDER BY
      CASE verdict WHEN 'tp' THEN 0 WHEN 'needs_review' THEN 1 ELSE 2 END,
      confidence DESC
  `;

  const rows = repo
    ? db.prepare(query).all(repo)
    : db.prepare(query).all();

  return rows as Array<{
    fingerprint: string;
    ruleId: string;
    filePath: string;
    startLine: number;
    severity: string;
    verdict: Verdict;
    confidence: number;
    rationale: string;
  }>;
}
