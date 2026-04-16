import path from "node:path";
import Database from "better-sqlite3";
import { allMigrations, runMigrations } from "./migrations/index.js";
import type {
  CorroboratingSignal,
  EngineProvenance,
  Finding,
  ProofState,
  SuppressionReason,
  TaintPathStep,
  TaskId,
} from "./scanners/types.js";
import { FindingSchema } from "./schemas.js";
import type { RunMetrics } from "./scoring/run-metrics.js";
import { BATCH_TRIAGE_FALLBACK_RATIONALE } from "./triage.js";
import type {
  AttackPathAnalysis,
  CodeCitation,
  DynamicAnalysisStatus,
  FindingMetadata,
  KuzushiConfig,
  PatchStatus,
  PocHarnessResult,
  ScanOpts,
  SecurityControl,
  TriageResult,
  Verdict,
  VerificationResult,
} from "./types.js";
import { safeJsonParse, safeJsonStringify } from "./utils/safe-json.js";

export type PipelineRunStatus =
  | "scanning"
  | "triaging"
  | "verifying"
  | "poc-harnessing"
  | "dynamic-analyzing"
  | "complete"
  | "error";

interface PipelineRunRecord {
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
  metricsJson: string | null;
  assertionsJson: string | null;
  promptHash: string | null;
}

export interface StoredFindingRecord {
  taskId: TaskId;
  fingerprint: string;
  repo: string;
  ref: string;
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
  verifyExploitable: number | null;
  verifyPocPayload: string | null;
  verifyPocDescription: string | null;
  verifyAttackVector: string | null;
  verifyPreconditions: string[];
  verifyConfidence: number | null;
  verifyCostUsd: number | null;
  pocHarnessPath: string | null;
  pocHarnessLanguage: string | null;
  pocHarnessParsed: number | null;
  pocHarnessParseError: string | null;
  pocHarnessSkipped: number | null;
  pocHarnessSkipReason: string | null;
  pocHarnessCostUsd: number | null;
  pocRunExitCode: number | null;
  pocRunStdout: string | null;
  pocRunStderr: string | null;
  pocRunVerdict: "PASS" | "FAIL" | "ERROR" | "TIMEOUT" | null;
  pocRunDurationMs: number | null;
  adjustedScore: number | null;
  taintPath: TaintPathStep[] | undefined;
  proofState: ProofState | undefined;
  engineProvenance: EngineProvenance[] | undefined;
  findingMetadata: FindingMetadata | undefined;
  corroboratingSignals: CorroboratingSignal[];
  suppressionReasons: SuppressionReason[];
  codeCitations: CodeCitation[] | undefined;
  attackPath: AttackPathAnalysis | undefined;
  assumptions: string[] | undefined;
  controls: SecurityControl[] | undefined;
  blindspots: string[] | undefined;
  sourceThreatIds: string[] | undefined;
  blame?: { sha: string; author: string; date: string; summary: string };
  introducedIn?: string;
}

const PROOF_STATE_PRECEDENCE: Record<ProofState, number> = {
  symbolic_only: 0,
  inconclusive: 1,
  execution_attempted: 2,
  execution_rejected: 3,
  execution_confirmed: 4,
};

/** Initialize the SQLite database with the findings schema. */
export function initDb(dbPath: string): Database.Database {
  const db = new Database(dbPath);
  db.pragma("journal_mode = WAL");
  db.pragma("busy_timeout = 5000");
  // synchronous=NORMAL is safe under WAL (durability preserved on crash;
  // only window is a power loss in the seconds between checkpoints) and
  // eliminates a fsync per transaction.
  db.pragma("synchronous = NORMAL");

  runMigrations(db, allMigrations);

  // Force a WAL checkpoint so the main DB file is fully written before the
  // scan starts.  This prevents data loss if the process crashes before
  // SQLite's automatic checkpoint threshold is reached.
  db.pragma("wal_checkpoint(TRUNCATE)");

  return db;
}

/** Default DB path: .kuzushi/findings.sqlite3 in the scanned repo root. */
export function defaultDbPath(repoRoot: string): string {
  return path.join(repoRoot, ".kuzushi", "findings.sqlite3");
}

const UPSERT_FINDING_SQL = `
    INSERT INTO findings (
      fingerprint, task_id, repo, ref, rule_id, file_path, start_line,
      severity, message, adjusted_score, corroboration_json, suppression_json, verdict, confidence,
      rationale, verification_steps, fix_patch, triage_cost_usd, triage_details_json,
      composite_confidence, confidence_signals_json, taint_path_json, proof_state, engine_provenance_json,
      finding_metadata_json
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(fingerprint) DO UPDATE SET
      task_id=excluded.task_id,
      repo=excluded.repo,
      ref=excluded.ref,
      rule_id=excluded.rule_id,
      file_path=excluded.file_path,
      start_line=excluded.start_line,
      severity=excluded.severity,
      message=excluded.message,
      adjusted_score=excluded.adjusted_score,
      corroboration_json=excluded.corroboration_json,
      suppression_json=excluded.suppression_json,
      verdict=excluded.verdict,
      confidence=excluded.confidence,
      rationale=excluded.rationale,
      verification_steps=excluded.verification_steps,
      fix_patch=excluded.fix_patch,
      triage_cost_usd=excluded.triage_cost_usd,
      triage_details_json=excluded.triage_details_json,
      composite_confidence=excluded.composite_confidence,
      confidence_signals_json=excluded.confidence_signals_json,
      taint_path_json=excluded.taint_path_json,
      proof_state=excluded.proof_state,
      engine_provenance_json=excluded.engine_provenance_json,
      finding_metadata_json=COALESCE(excluded.finding_metadata_json, findings.finding_metadata_json),
      updated_at=datetime('now')
  `;

function upsertFindingParams(
  finding: Finding,
  triage: TriageResult,
  repo: string,
  ref: string,
): unknown[] {
  return [
    triage.fingerprint,
    finding.taskId,
    repo,
    ref,
    finding.ruleId,
    finding.filePath,
    finding.startLine,
    finding.severity,
    finding.message,
    finding.adjustedScore ?? finding.score,
    finding.corroboratingSignals ? safeJsonStringify(finding.corroboratingSignals) : null,
    finding.suppressionReasons ? safeJsonStringify(finding.suppressionReasons) : null,
    triage.verdict,
    triage.confidence,
    triage.rationale,
    safeJsonStringify(triage.verificationSteps),
    triage.fixPatch,
    triage.triageCostUsd ?? null,
    safeJsonStringify({
      title: triage.title ?? null,
      attack_narrative: triage.attackNarrative ?? null,
      display_severity: triage.displaySeverity ?? null,
      source: triage.source ?? null,
      sink: triage.sink ?? null,
      is_vulnerable: triage.isVulnerable ?? null,
      exploit_scenario: triage.exploitScenario ?? null,
      recommended_fix: triage.recommendedFix ?? null,
      rule_refinement_hint: triage.ruleRefinementHint ?? null,
      triage_schema_version: triage.triageSchemaVersion ?? null,
      code_citations: triage.codeCitations ?? null,
      attack_path: triage.attackPath
        ? {
            chain: triage.attackPath.chain,
            narrative: triage.attackPath.narrative,
            likelihood_reasoning: triage.attackPath.likelihoodReasoning,
            impact_reasoning: triage.attackPath.impactReasoning,
          }
        : null,
      assumptions: triage.assumptions ?? null,
      controls: triage.controls ?? null,
      blindspots: triage.blindspots ?? null,
      source_threat_ids: triage.sourceThreatIds ?? null,
    }),
    triage.compositeConfidence ?? null,
    null, // confidence_signals_json — populated by updateFindingCompositeConfidence if needed
    finding.taintPath ? safeJsonStringify(finding.taintPath) : null,
    finding.proofState ?? null,
    finding.engineProvenance ? safeJsonStringify(finding.engineProvenance) : null,
    null, // finding_metadata_json — populated by updateFindingMetadata; COALESCE preserves existing
  ];
}

/** Upsert a triage result into the database. */
export function upsertFinding(
  db: Database.Database,
  finding: Finding,
  triage: TriageResult,
  repo: string,
  ref: string,
): void {
  const stmt = db.prepare(UPSERT_FINDING_SQL);
  stmt.run(...upsertFindingParams(finding, triage, repo, ref));
}

/** Default flush threshold for {@link FindingUpsertQueue}.
 *  Raised from 1 → 50: the store worker already flushes at every natural
 *  phase boundary (triage:complete, verification:result, poc-harness:result,
 *  and error paths), so batching 50 upserts per transaction replaces N
 *  single-row commits with ceil(N/50) multi-row transactions. On the
 *  `upsert 500 findings` perf bench this drops median from ~80 ms to <10 ms. */
const DEFAULT_FLUSH_THRESHOLD = 50;

/**
 * Batched upsert queue — collects individual upsert calls and flushes them
 * inside a single SQLite transaction when the threshold is reached or on
 * explicit {@link flush}.  Drop-in replacement for per-event `upsertFinding()`
 * calls in the store worker.
 */
export class FindingUpsertQueue {
  private pending: Array<{ finding: Finding; triage: TriageResult; repo: string; ref: string }> =
    [];
  private readonly flushThreshold: number;
  private readonly db: Database.Database;

  constructor(db: Database.Database, flushThreshold = DEFAULT_FLUSH_THRESHOLD) {
    this.db = db;
    this.flushThreshold = flushThreshold;
  }

  /** Enqueue a single upsert. Auto-flushes when the threshold is reached. */
  enqueue(finding: Finding, triage: TriageResult, repo: string, ref: string): void {
    this.pending.push({ finding, triage, repo, ref });
    if (this.pending.length >= this.flushThreshold) {
      this.flush();
    }
  }

  /** Flush all pending upserts in a single transaction. */
  flush(): void {
    if (this.pending.length === 0) return;
    const batch = this.pending.splice(0);
    const stmt = this.db.prepare(UPSERT_FINDING_SQL);
    const runAll = this.db.transaction(() => {
      for (const item of batch) {
        stmt.run(...upsertFindingParams(item.finding, item.triage, item.repo, item.ref));
      }
    });
    runAll();
  }

  /** Number of pending (unflushed) upserts. */
  get size(): number {
    return this.pending.length;
  }
}

/** Get set of already-triaged fingerprints from the database.
 *  Excludes findings with the batch-drop fallback signature (confidence=0,
 *  fallback rationale) so they get re-queued on subsequent runs. */
export function getTriagedFingerprints(db: Database.Database): Set<string> {
  const rows = db
    .prepare("SELECT fingerprint FROM findings WHERE NOT (confidence = 0 AND rationale = ?)")
    .all(BATCH_TRIAGE_FALLBACK_RATIONALE) as Array<{
    fingerprint: string;
  }>;
  return new Set(rows.map((r) => r.fingerprint));
}

/** Get set of already-verified fingerprints from the database. */
export function getVerifiedFingerprints(db: Database.Database): Set<string> {
  const rows = db
    .prepare("SELECT fingerprint FROM findings WHERE verify_exploitable IS NOT NULL")
    .all() as Array<{ fingerprint: string }>;

  return new Set(rows.map((row) => row.fingerprint));
}

/** Get set of fingerprints with completed PoC harness generation. */
export function getPocHarnessedFingerprints(db: Database.Database): Set<string> {
  const rows = db
    .prepare(
      `SELECT fingerprint FROM findings
     WHERE poc_harness_path IS NOT NULL OR poc_harness_skipped IS NOT NULL`,
    )
    .all() as Array<{ fingerprint: string }>;

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

  // Cache prepared statements by placeholder count. Typical calls hit two
  // sizes at most (full chunks + one remainder), so prepare cost amortizes.
  const stmtByChunkSize = new Map<number, Database.Statement>();
  const prepareForChunk = (size: number) => {
    let stmt = stmtByChunkSize.get(size);
    if (!stmt) {
      const placeholders = new Array(size).fill("?").join(", ");
      stmt = db.prepare(`
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
    `);
      stmtByChunkSize.set(size, stmt);
    }
    return stmt;
  };

  for (let i = 0; i < uniqueFingerprints.length; i += SQLITE_BIND_LIMIT) {
    const chunk = uniqueFingerprints.slice(i, i + SQLITE_BIND_LIMIT);
    const rows = prepareForChunk(chunk.length).all(...chunk) as typeof allRows;
    allRows.push(...rows);
  }

  const results = new Map<string, TriageResult>();
  for (const row of allRows) {
    const parsedSteps = safeJsonParse<unknown>(row.verificationSteps, []);
    const verificationSteps = Array.isArray(parsedSteps)
      ? parsedSteps.map((step) => String(step)).filter(Boolean)
      : [];

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

  const parsed = safeJsonParse<unknown>(raw, null);
  if (!parsed || typeof parsed !== "object") {
    return {};
  }

  const record = parsed as Record<string, unknown>;
  const source = parsePathAssessment(record["source"]);
  const sink = parsePathAssessment(record["sink"]);
  return {
    source,
    sink,
    isVulnerable:
      typeof record["is_vulnerable"] === "boolean" ? record["is_vulnerable"] : undefined,
    exploitScenario: asOptionalString(record["exploit_scenario"]),
    recommendedFix: asOptionalString(record["recommended_fix"]),
    ruleRefinementHint: asOptionalString(record["rule_refinement_hint"]),
    triageSchemaVersion: asOptionalString(record["triage_schema_version"]),
    codeCitations: parseCodeCitationsFromDetails(record["code_citations"]),
    attackPath: parseAttackPathFromDetails(record["attack_path"]),
    assumptions: parseStringArrayFromDetails(record["assumptions"]),
    controls: parseControlsFromDetails(record["controls"]),
    blindspots: parseStringArrayFromDetails(record["blindspots"]),
    sourceThreatIds: parseStringArrayFromDetails(record["source_threat_ids"]),
  };
}

function parseCodeCitationsFromDetails(value: unknown): CodeCitation[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const citations: CodeCitation[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") continue;
    const rec = item as Record<string, unknown>;
    const filePath =
      typeof rec["file_path"] === "string"
        ? rec["file_path"]
        : typeof rec["filePath"] === "string"
          ? rec["filePath"]
          : "";
    const startLine = Number(rec["start_line"] ?? rec["startLine"]);
    const endLine = Number(rec["end_line"] ?? rec["endLine"]);
    const snippet = typeof rec["snippet"] === "string" ? rec["snippet"] : "";
    const description = typeof rec["description"] === "string" ? rec["description"] : "";
    if (!filePath || !Number.isFinite(startLine) || !description) continue;
    citations.push({
      filePath,
      startLine,
      endLine: Number.isFinite(endLine) ? endLine : startLine,
      snippet,
      description,
    });
  }
  return citations.length > 0 ? citations : undefined;
}

function parseAttackPathFromDetails(value: unknown): AttackPathAnalysis | undefined {
  if (!value || typeof value !== "object") return undefined;
  const rec = value as Record<string, unknown>;
  const chain = Array.isArray(rec["chain"])
    ? rec["chain"].map((s: unknown) => String(s).trim()).filter(Boolean)
    : [];
  const narrative = typeof rec["narrative"] === "string" ? rec["narrative"].trim() : "";
  const likelihoodReasoning =
    typeof (rec["likelihood_reasoning"] ?? rec["likelihoodReasoning"]) === "string"
      ? String(rec["likelihood_reasoning"] ?? rec["likelihoodReasoning"]).trim()
      : "";
  const impactReasoning =
    typeof (rec["impact_reasoning"] ?? rec["impactReasoning"]) === "string"
      ? String(rec["impact_reasoning"] ?? rec["impactReasoning"]).trim()
      : "";
  if (chain.length === 0 && !narrative) return undefined;
  return { chain, narrative, likelihoodReasoning, impactReasoning };
}

function parseControlsFromDetails(value: unknown): SecurityControl[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const controls: SecurityControl[] = [];
  for (const item of value) {
    if (!item || typeof item !== "object") continue;
    const rec = item as Record<string, unknown>;
    const name = typeof rec["name"] === "string" ? rec["name"].trim() : "";
    const description = typeof rec["description"] === "string" ? rec["description"].trim() : "";
    const filePath =
      typeof (rec["file_path"] ?? rec["filePath"]) === "string"
        ? String(rec["file_path"] ?? rec["filePath"]).trim()
        : undefined;
    if (!name || !description) continue;
    controls.push({ name, description, filePath: filePath || undefined });
  }
  return controls.length > 0 ? controls : undefined;
}

function parseStringArrayFromDetails(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  const result = value.map((s: unknown) => String(s).trim()).filter(Boolean);
  return result.length > 0 ? result : undefined;
}

function parsePathAssessment(value: unknown): TriageResult["source"] | undefined {
  if (!value || typeof value !== "object") {
    return undefined;
  }
  const asRecord = value as Record<string, unknown>;
  const why = asOptionalString(asRecord["why"]);
  const evidence = asOptionalString(asRecord["evidence"]);
  const isFalsePositive =
    asRecord["isFalsePositive"] === true || asRecord["is_false_positive"] === true;
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

function asFiniteNumber(value: unknown): number | undefined {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return undefined;
  }
  return value;
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
  const stmtByChunkSize = new Map<number, Database.Statement>();
  const prepareForChunk = (size: number) => {
    let stmt = stmtByChunkSize.get(size);
    if (!stmt) {
      const placeholders = new Array(size).fill("?").join(", ");
      stmt = db.prepare(`
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
    `);
      stmtByChunkSize.set(size, stmt);
    }
    return stmt;
  };

  for (let i = 0; i < uniqueFingerprints.length; i += SQLITE_BIND_LIMIT) {
    const chunk = uniqueFingerprints.slice(i, i + SQLITE_BIND_LIMIT);
    const rows = prepareForChunk(chunk.length).all(...chunk) as VerifyRow[];
    allRows.push(...rows);
  }

  const results = new Map<string, VerificationResult>();
  for (const row of allRows) {
    let preconditions: string[] = [];
    if (row.verifyPreconditions) {
      const parsed = safeJsonParse<unknown>(row.verifyPreconditions, []);
      if (Array.isArray(parsed)) {
        preconditions = parsed.map((item) => String(item).trim()).filter(Boolean);
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
export function getVerdictCounts(db: Database.Database, repo?: string): Record<Verdict, number> {
  const counts: Record<Verdict, number> = { tp: 0, fp: 0, needs_review: 0, by_design: 0 };

  const query = repo
    ? "SELECT verdict, COUNT(*) as count FROM findings WHERE repo = ? GROUP BY verdict"
    : "SELECT verdict, COUNT(*) as count FROM findings GROUP BY verdict";

  const rows = (repo ? db.prepare(query).all(repo) : db.prepare(query).all()) as Array<{
    verdict: string;
    count: number;
  }>;

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

  const row = (repo ? db.prepare(query).get(repo) : db.prepare(query).get()) as
    | { total?: number }
    | undefined;

  return row?.total ?? 0;
}

/** Get total verification cost in USD from persisted findings. */
function _getTotalVerificationCost(db: Database.Database, repo?: string): number {
  const query = repo
    ? "SELECT COALESCE(SUM(COALESCE(verify_cost_usd, 0)), 0) as total FROM findings WHERE repo = ?"
    : "SELECT COALESCE(SUM(COALESCE(verify_cost_usd, 0)), 0) as total FROM findings";

  const row = (repo ? db.prepare(query).get(repo) : db.prepare(query).get()) as
    | { total?: number }
    | undefined;

  return row?.total ?? 0;
}

/** Get total PoC harness generation cost in USD from persisted findings. */
export function getTotalPocHarnessCost(db: Database.Database, repo?: string): number {
  const query = repo
    ? "SELECT COALESCE(SUM(COALESCE(poc_harness_cost_usd, 0)), 0) as total FROM findings WHERE repo = ?"
    : "SELECT COALESCE(SUM(COALESCE(poc_harness_cost_usd, 0)), 0) as total FROM findings";

  const row = (repo ? db.prepare(query).get(repo) : db.prepare(query).get()) as
    | { total?: number }
    | undefined;

  return row?.total ?? 0;
}

/** Get verification counts grouped by exploitability outcome. */
function _getVerificationCounts(
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

  const rows = (repo ? db.prepare(query).all(repo) : db.prepare(query).all()) as Array<{
    verifyExploitable: number;
    count: number;
  }>;

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

  const row = (repo ? db.prepare(query).get(repo) : db.prepare(query).get()) as
    | { generated?: number; skipped?: number }
    | undefined;

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
): StoredFindingRecord[] {
  const filters: string[] = [];
  const params: unknown[] = [];
  if (!options.includeFalsePositives) {
    filters.push("verdict != 'fp'");
  }
  if (repo) {
    filters.push("repo = ?");
    params.push(repo);
  }
  if (
    options.fingerprints &&
    options.fingerprints.length > 0 &&
    options.fingerprints.length <= SQLITE_BIND_LIMIT - params.length
  ) {
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
    SELECT task_id as taskId, fingerprint, repo, ref, rule_id as ruleId, file_path as filePath, start_line as startLine,
           severity, message, verdict, confidence, rationale,
           verification_steps as verificationSteps,
           triage_details_json as triageDetailsJson,
           adjusted_score as adjustedScore,
           taint_path_json as taintPathJson,
           proof_state as proofState,
           engine_provenance_json as engineProvenanceJson,
           finding_metadata_json as findingMetadataJson,
           corroboration_json as corroborationJson,
           suppression_json as suppressionJson,
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
           poc_harness_cost_usd as pocHarnessCostUsd,
           poc_run_exit_code as pocRunExitCode,
           poc_run_stdout as pocRunStdout,
           poc_run_stderr as pocRunStderr,
           poc_run_verdict as pocRunVerdict,
           poc_run_duration_ms as pocRunDurationMs
    FROM findings ${where}
    ORDER BY
      CASE verdict WHEN 'tp' THEN 0 WHEN 'needs_review' THEN 1 ELSE 2 END,
      confidence DESC
  `;

  const rows = db.prepare(query).all(...params) as Array<{
    taskId: TaskId;
    fingerprint: string;
    repo: string;
    ref: string;
    ruleId: string;
    filePath: string;
    startLine: number;
    severity: string;
    message: string;
    verdict: Verdict;
    confidence: number;
    rationale: string;
    verificationSteps: string;
    triageDetailsJson: string | null;
    adjustedScore: number | null;
    taintPathJson: string | null;
    proofState: string | null;
    engineProvenanceJson: string | null;
    findingMetadataJson: string | null;
    corroborationJson: string | null;
    suppressionJson: string | null;
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
    pocRunExitCode: number | null;
    pocRunStdout: string | null;
    pocRunStderr: string | null;
    pocRunVerdict: "PASS" | "FAIL" | "ERROR" | "TIMEOUT" | null;
    pocRunDurationMs: number | null;
  }>;

  return rows.map((row) => {
    const detailsRecord = parseTriageDetailsRecord(row.triageDetailsJson);
    return {
      taskId: row.taskId,
      fingerprint: row.fingerprint,
      repo: row.repo,
      ref: row.ref,
      ruleId: row.ruleId,
      filePath: row.filePath,
      startLine: row.startLine,
      severity: row.severity,
      message: row.message,
      verdict: row.verdict,
      confidence: row.confidence,
      rationale: row.rationale,
      verificationSteps: parseVerificationSteps(row.verificationSteps),
      triageDetails: detailsRecord,
      adjustedScore: row.adjustedScore,
      taintPath: parseTaintPath(row.taintPathJson),
      proofState: parseProofState(row.proofState),
      engineProvenance: parseEngineProvenance(row.engineProvenanceJson),
      findingMetadata: parseFindingMetadata(row.findingMetadataJson),
      corroboratingSignals: parseCorroboratingSignals(row.corroborationJson),
      suppressionReasons: parseSuppressionReasons(row.suppressionJson),
      fixPatch: row.fixPatch,
      verifyExploitable: row.verifyExploitable,
      verifyPocPayload: row.verifyPocPayload,
      verifyPocDescription: row.verifyPocDescription,
      verifyAttackVector: row.verifyAttackVector,
      verifyPreconditions: parsePreconditions(row.verifyPreconditions),
      verifyConfidence: row.verifyConfidence,
      verifyCostUsd: row.verifyCostUsd,
      pocHarnessPath: row.pocHarnessPath,
      pocHarnessLanguage: row.pocHarnessLanguage,
      pocHarnessParsed: row.pocHarnessParsed,
      pocHarnessParseError: row.pocHarnessParseError,
      pocHarnessSkipped: row.pocHarnessSkipped,
      pocHarnessSkipReason: row.pocHarnessSkipReason,
      pocHarnessCostUsd: row.pocHarnessCostUsd,
      pocRunExitCode: row.pocRunExitCode,
      pocRunStdout: row.pocRunStdout,
      pocRunStderr: row.pocRunStderr,
      pocRunVerdict: row.pocRunVerdict,
      pocRunDurationMs: row.pocRunDurationMs,
      codeCitations: detailsRecord
        ? parseCodeCitationsFromDetails(detailsRecord["code_citations"])
        : undefined,
      attackPath: detailsRecord
        ? parseAttackPathFromDetails(detailsRecord["attack_path"])
        : undefined,
      assumptions: detailsRecord
        ? parseStringArrayFromDetails(detailsRecord["assumptions"])
        : undefined,
      controls: detailsRecord ? parseControlsFromDetails(detailsRecord["controls"]) : undefined,
      blindspots: detailsRecord
        ? parseStringArrayFromDetails(detailsRecord["blindspots"])
        : undefined,
      sourceThreatIds: detailsRecord
        ? parseStringArrayFromDetails(detailsRecord["source_threat_ids"])
        : undefined,
      blame: parseFindingMetadata(row.findingMetadataJson)?.blame,
      introducedIn:
        parseFindingMetadata(row.findingMetadataJson)?.introducedIn ??
        parseFindingMetadata(row.findingMetadataJson)?.blame?.sha,
    };
  });
}

export function getTriagedFindingsForRepo(
  db: Database.Database,
  repo: string,
): Array<{
  taskId: TaskId;
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
  const rows = db
    .prepare(`
    SELECT
      task_id as taskId,
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
  `)
    .all(repo) as Array<{
    taskId: TaskId;
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
    const parsedSteps = safeJsonParse<unknown>(row.verificationSteps, []);
    const verificationSteps = Array.isArray(parsedSteps)
      ? parsedSteps.map((value) => String(value))
      : [];

    let triageDetails: Record<string, unknown> | null = null;
    if (row.triageDetailsJson) {
      const parsed = safeJsonParse<unknown>(row.triageDetailsJson, null);
      if (parsed && typeof parsed === "object") {
        triageDetails = parsed as Record<string, unknown>;
      }
    }

    return {
      taskId: row.taskId,
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

export function getStoredFinding(
  db: Database.Database,
  fingerprint: string,
): StoredFindingRecord | undefined {
  const rows = getActionableFindings(db, undefined, {
    includeFalsePositives: true,
    fingerprints: [fingerprint],
  });
  return rows[0];
}

/**
 * Update a finding's verdict (used by interactive review mode).
 * Only changes the verdict and confidence — preserves all other fields.
 */
export function updateFindingVerdict(
  db: Database.Database,
  fingerprint: string,
  verdict: "tp" | "fp" | "needs_review" | "by_design",
  confidence = 1.0,
): void {
  db.prepare("UPDATE findings SET verdict = ?, confidence = ? WHERE fingerprint = ?").run(
    verdict,
    confidence,
    fingerprint,
  );
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

/** Delete all findings for a repo. Returns number of deleted rows. */
export function deleteFindingsForRepo(db: Database.Database, repo: string): number {
  return db.prepare("DELETE FROM findings WHERE repo = ?").run(repo).changes;
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
    safeJsonStringify(config),
    safeJsonStringify(scanOpts),
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
export function updateRunFindings(db: Database.Database, runId: string, findings: Finding[]): void {
  db.prepare(`
    UPDATE pipeline_runs
    SET findings_json = ?, updated_at = datetime('now')
    WHERE run_id = ?
  `).run(safeJsonStringify(findings), runId);
}

/** Persist gathered repository context for resume support. */
export function updateRunContext(db: Database.Database, runId: string, repoContext: unknown): void {
  db.prepare(`
    UPDATE pipeline_runs
    SET context_json = ?, updated_at = datetime('now')
    WHERE run_id = ?
  `).run(safeJsonStringify(repoContext ?? null), runId);
}

function parseCorroboratingSignals(raw: string | null): CorroboratingSignal[] {
  const parsed = safeJsonParse<unknown>(raw ?? "", []);
  if (!Array.isArray(parsed)) {
    return [];
  }

  const signals: CorroboratingSignal[] = [];
  for (const item of parsed) {
    if (!item || typeof item !== "object") {
      continue;
    }
    const record = item as Record<string, unknown>;
    const taskId = asOptionalString(record["taskId"]);
    const fingerprint = asOptionalString(record["fingerprint"]);
    const ruleId = asOptionalString(record["ruleId"]);
    const filePath = asOptionalString(record["filePath"]);
    const startLine = asFiniteNumber(record["startLine"]);
    const score = asFiniteNumber(record["score"]);
    if (!taskId || !fingerprint || !ruleId || !filePath || startLine == null || score == null) {
      continue;
    }
    const cwe = Array.isArray(record["cwe"])
      ? record["cwe"].map((value) => String(value).trim()).filter(Boolean)
      : [];
    signals.push({
      taskId,
      fingerprint,
      ruleId,
      filePath,
      startLine,
      cwe,
      score,
    });
  }
  return signals;
}

function parseTaintPath(raw: string | null): TaintPathStep[] | undefined {
  const parsed = safeJsonParse<unknown>(raw ?? "", null);
  if (!Array.isArray(parsed)) {
    return undefined;
  }

  const taintPath: TaintPathStep[] = [];
  for (const item of parsed) {
    if (!item || typeof item !== "object") {
      continue;
    }
    const record = item as Record<string, unknown>;
    const filePath = asOptionalString(record["filePath"]);
    const line = asFiniteNumber(record["line"]);
    if (!filePath || line == null) {
      continue;
    }
    taintPath.push({
      filePath,
      line,
      message: asOptionalString(record["message"]) ?? undefined,
      snippet: asOptionalString(record["snippet"]) ?? undefined,
    });
  }

  return taintPath.length > 0 ? taintPath : undefined;
}

function parseVerificationSteps(raw: string | null): string[] {
  const parsed = safeJsonParse<unknown>(raw ?? "", []);
  if (!Array.isArray(parsed)) {
    return [];
  }

  return parsed.map((value) => String(value).trim()).filter(Boolean);
}

function parseTriageDetailsRecord(raw: string | null): Record<string, unknown> | null {
  const parsed = safeJsonParse<unknown>(raw ?? "", null);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }
  return parsed as Record<string, unknown>;
}

function parseProofState(raw: string | null): ProofState | undefined {
  switch (raw) {
    case "symbolic_only":
    case "execution_attempted":
    case "execution_confirmed":
    case "execution_rejected":
    case "inconclusive":
      return raw;
    default:
      return undefined;
  }
}

function parseEngineProvenance(raw: string | null): EngineProvenance[] | undefined {
  const parsed = safeJsonParse<unknown>(raw ?? "", null);
  if (!Array.isArray(parsed)) {
    return undefined;
  }

  const engineProvenance: EngineProvenance[] = [];
  for (const item of parsed) {
    if (!item || typeof item !== "object") {
      continue;
    }
    const record = item as Record<string, unknown>;
    const kind = asOptionalString(record["kind"]);
    const detail = asOptionalString(record["detail"]) ?? "";
    if (
      kind === "semgrep" ||
      kind === "codeql" ||
      kind === "taint-analysis" ||
      kind === "agentic" ||
      kind === "dynamic"
    ) {
      engineProvenance.push({ kind, detail });
    }
  }

  return engineProvenance.length > 0 ? engineProvenance : undefined;
}

function parsePreconditions(raw: string | null): string[] {
  if (!raw) return [];
  const parsed = safeJsonParse<unknown>(raw, null);
  if (!Array.isArray(parsed)) return [];
  return parsed.map((s) => String(s)).filter(Boolean);
}

function parseFindingMetadata(raw: string | null): FindingMetadata | undefined {
  const parsed = safeJsonParse<unknown>(raw ?? "", null);
  if (!parsed || typeof parsed !== "object") {
    return undefined;
  }

  const record = parsed as Record<string, unknown>;
  const metadata: FindingMetadata = {};
  const latestDynamicRunId = asOptionalString(record["latestDynamicRunId"]);
  const latestPatchRunId = asOptionalString(record["latestPatchRunId"]);
  const latestDynamicStatus = parseDynamicAnalysisStatus(
    asOptionalString(record["latestDynamicStatus"]) ?? null,
  );
  const dynamicRunIds = Array.isArray(record["dynamicRunIds"])
    ? record["dynamicRunIds"].map((value) => String(value).trim()).filter(Boolean)
    : [];
  const patchRunIds = Array.isArray(record["patchRunIds"])
    ? record["patchRunIds"].map((value) => String(value).trim()).filter(Boolean)
    : [];
  const notes = Array.isArray(record["notes"])
    ? record["notes"].map((value) => String(value).trim()).filter(Boolean)
    : [];

  if (latestDynamicRunId) metadata.latestDynamicRunId = latestDynamicRunId;
  if (dynamicRunIds.length > 0) metadata.dynamicRunIds = dynamicRunIds;
  if (latestPatchRunId) metadata.latestPatchRunId = latestPatchRunId;
  if (patchRunIds.length > 0) metadata.patchRunIds = patchRunIds;
  if (latestDynamicStatus) metadata.latestDynamicStatus = latestDynamicStatus;
  if (notes.length > 0) metadata.notes = notes;

  // Git blame attribution
  const blameRaw = record["blame"];
  if (blameRaw && typeof blameRaw === "object" && !Array.isArray(blameRaw)) {
    const b = blameRaw as Record<string, unknown>;
    const sha = asOptionalString(b["sha"]);
    const author = asOptionalString(b["author"]);
    const date = asOptionalString(b["date"]);
    const summary = asOptionalString(b["summary"]);
    if (sha && author) {
      metadata.blame = { sha, author, date: date ?? "", summary: summary ?? "" };
    }
  }
  const introducedIn = asOptionalString(record["introducedIn"]);
  if (introducedIn) metadata.introducedIn = introducedIn;

  return Object.keys(metadata).length > 0 ? metadata : undefined;
}

function parseDynamicAnalysisStatus(raw: string | null): DynamicAnalysisStatus | undefined {
  switch (raw) {
    case "confirmed":
    case "interesting":
    case "rejected":
    case "error":
      return raw;
    default:
      return undefined;
  }
}

function _parsePatchStatus(raw: string | null): PatchStatus | undefined {
  switch (raw) {
    case "APPLY_FAILED":
    case "BUILD_FAILED":
    case "STILL_VULNERABLE":
    case "TESTS_FAILED":
    case "SOUND":
    case "UNKNOWN":
      return raw;
    default:
      return undefined;
  }
}

function parseSuppressionReasons(raw: string | null): SuppressionReason[] {
  const parsed = safeJsonParse<unknown>(raw ?? "", []);
  if (!Array.isArray(parsed)) {
    return [];
  }

  const reasons: SuppressionReason[] = [];
  for (const item of parsed) {
    if (!item || typeof item !== "object") {
      continue;
    }
    const record = item as Record<string, unknown>;
    const id = asOptionalString(record["id"]);
    const description = asOptionalString(record["description"]);
    const kind =
      record["kind"] === "hard" || record["kind"] === "soft" ? record["kind"] : undefined;
    if (!id || !description || !kind) {
      continue;
    }
    reasons.push({
      id,
      description,
      kind,
      scorePenalty: asFiniteNumber(record["scorePenalty"]) ?? undefined,
    });
  }
  return reasons;
}

/** Increment persisted run cost in USD. */
export function updateRunCost(db: Database.Database, runId: string, costUsd: number): void {
  if (!Number.isFinite(costUsd)) {
    return;
  }

  db.prepare(`
    UPDATE pipeline_runs
    SET total_cost_usd = total_cost_usd + ?, updated_at = datetime('now')
    WHERE run_id = ?
  `).run(costUsd, runId);
}

/** Persist composite confidence result on a finding row. */
function _updateFindingCompositeConfidence(
  db: Database.Database,
  fingerprint: string,
  compositeConfidence: number,
  signalsJson: string,
): void {
  db.prepare(`
    UPDATE findings
    SET composite_confidence = ?, confidence_signals_json = ?, updated_at = datetime('now')
    WHERE fingerprint = ?
  `).run(compositeConfidence, signalsJson, fingerprint);
}

/** Persist run metrics JSON for a pipeline run. */
export function updateRunMetrics(db: Database.Database, runId: string, metrics: RunMetrics): void {
  db.prepare(`
    UPDATE pipeline_runs
    SET metrics_json = ?, updated_at = datetime('now')
    WHERE run_id = ?
  `).run(safeJsonStringify(metrics), runId);
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
    safeJsonStringify(result.preconditions),
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
      poc_run_exit_code = ?,
      poc_run_stdout = ?,
      poc_run_stderr = ?,
      poc_run_verdict = ?,
      poc_run_duration_ms = ?,
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
    result.pocExecExitCode ?? null,
    result.pocExecStdout ?? null,
    result.pocExecStderr ?? null,
    result.pocExecVerdict ?? null,
    result.pocExecDurationMs ?? null,
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

/** Persist proof-state updates from verification or dynamic execution. */
export function updateFindingProofState(
  db: Database.Database,
  fingerprint: string,
  proofState: ProofState,
): void {
  const row = db
    .prepare(`
    SELECT proof_state as proofState
    FROM findings
    WHERE fingerprint = ?
    LIMIT 1
  `)
    .get(fingerprint) as { proofState: string | null } | undefined;

  const current = parseProofState(row?.proofState ?? null);
  if (current && PROOF_STATE_PRECEDENCE[proofState] <= PROOF_STATE_PRECEDENCE[current]) {
    return;
  }

  db.prepare(`
    UPDATE findings
    SET proof_state = ?, updated_at = datetime('now')
    WHERE fingerprint = ?
  `).run(proofState, fingerprint);
}

/** Update finding metadata (dynamic analysis, patch, notes). Merges with existing metadata. */
export function updateFindingMetadata(
  db: Database.Database,
  fingerprint: string,
  metadata: Partial<FindingMetadata>,
): void {
  const row = db
    .prepare("SELECT finding_metadata_json FROM findings WHERE fingerprint = ?")
    .get(fingerprint) as { finding_metadata_json?: string | null } | undefined;

  const existing: FindingMetadata = row?.finding_metadata_json
    ? ((safeJsonParse(row.finding_metadata_json) as FindingMetadata) ?? {})
    : {};

  const merged: FindingMetadata = {
    ...existing,
    ...metadata,
    // Accumulate array fields instead of replacing
    dynamicRunIds: [
      ...new Set([...(existing.dynamicRunIds ?? []), ...(metadata.dynamicRunIds ?? [])]),
    ],
    patchRunIds: [...new Set([...(existing.patchRunIds ?? []), ...(metadata.patchRunIds ?? [])])],
    notes: [...(existing.notes ?? []), ...(metadata.notes ?? [])],
  };

  // Remove empty arrays to keep the JSON clean
  if (merged.dynamicRunIds?.length === 0) delete merged.dynamicRunIds;
  if (merged.patchRunIds?.length === 0) delete merged.patchRunIds;
  if (merged.notes?.length === 0) delete merged.notes;

  db.prepare(`
    UPDATE findings
    SET finding_metadata_json = ?, updated_at = datetime('now')
    WHERE fingerprint = ?
  `).run(safeJsonStringify(merged), fingerprint);
}

/** Get latest resumable run for repo, if any. */
export function getLatestResumableRun(
  db: Database.Database,
  repo: string,
): PipelineRunRecord | undefined {
  const row = db
    .prepare(`
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
      updated_at as updatedAt,
      metrics_json as metricsJson,
      assertions_json as assertionsJson,
      prompt_hash as promptHash
    FROM pipeline_runs
    WHERE repo = ? AND status IN ('scanning', 'triaging', 'verifying', 'poc-harnessing', 'dynamic-analyzing')
    ORDER BY started_at DESC, rowid DESC
    LIMIT 1
  `)
    .get(repo) as PipelineRunRecord | undefined;

  return row;
}

/**
 * List all resumable module runs for a monorepo.
 * Returns one run per module (the latest resumable run for each repo name
 * that starts with the given prefix).
 */
export function getResumableModuleRuns(
  db: Database.Database,
  monorepoPrefix: string,
): PipelineRunRecord[] {
  const rows = db
    .prepare(`
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
      updated_at as updatedAt,
      metrics_json as metricsJson,
      assertions_json as assertionsJson,
      prompt_hash as promptHash
    FROM pipeline_runs
    WHERE repo LIKE ? || '/%'
      AND status IN ('scanning', 'triaging', 'verifying', 'poc-harnessing', 'dynamic-analyzing', 'complete')
    ORDER BY started_at DESC, rowid DESC
  `)
    .all(monorepoPrefix) as PipelineRunRecord[];

  // Dedupe: keep only the latest run per repo (module)
  const byRepo = new Map<string, PipelineRunRecord>();
  for (const row of rows) {
    if (!byRepo.has(row.repo)) {
      byRepo.set(row.repo, row);
    }
  }
  return [...byRepo.values()];
}

/** Get persisted run checkpoint by run id. */
export function getRun(db: Database.Database, runId: string): PipelineRunRecord | undefined {
  const row = db
    .prepare(`
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
      updated_at as updatedAt,
      metrics_json as metricsJson,
      assertions_json as assertionsJson,
      prompt_hash as promptHash
    FROM pipeline_runs
    WHERE run_id = ?
    LIMIT 1
  `)
    .get(runId) as PipelineRunRecord | undefined;

  return row;
}

/** Load the latest completed pipeline run's serialized findings for a repo path. */
export function getLatestCompletedRunFindings(db: Database.Database, repo: string): Finding[] {
  const row = db
    .prepare(`
    SELECT findings_json as findingsJson
    FROM pipeline_runs
    WHERE repo = ? AND status = 'complete' AND findings_json IS NOT NULL
    ORDER BY COALESCE(completed_at, started_at) DESC, started_at DESC, rowid DESC
    LIMIT 1
  `)
    .get(repo) as { findingsJson?: string | null } | undefined;

  if (!row?.findingsJson) {
    return [];
  }

  const parsed = safeJsonParse<unknown>(row.findingsJson, []);
  if (!Array.isArray(parsed)) {
    return [];
  }

  const findings: Finding[] = [];
  for (const item of parsed) {
    const validated = FindingSchema.safeParse(item);
    if (!validated.success) {
      continue;
    }
    findings.push(validated.data);
  }

  return findings;
}

/** Save assertion results for a finding in a specific run. */
export function saveAssertionResults(
  db: Database.Database,
  runId: string,
  fingerprint: string,
  assertions: Array<{
    name: string;
    passed: boolean;
    score: number;
    weight: number;
    reason: string;
  }>,
): void {
  const stmt = db.prepare(`
    INSERT INTO finding_assertions (run_id, fingerprint, assertion_name, passed, score, weight, reason)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);
  const insertAll = db.transaction(() => {
    for (const a of assertions) {
      stmt.run(runId, fingerprint, a.name, a.passed ? 1 : 0, a.score, a.weight, a.reason);
    }
  });
  insertAll();
}

/** Get assertion results for a specific run. */
function _getRunAssertions(
  db: Database.Database,
  runId: string,
): Array<{
  fingerprint: string;
  assertionName: string;
  passed: boolean;
  score: number;
  weight: number;
  reason: string;
}> {
  const rows = db
    .prepare(`
    SELECT fingerprint, assertion_name as assertionName, passed, score, weight, reason
    FROM finding_assertions
    WHERE run_id = ?
  `)
    .all(runId) as Array<{
    fingerprint: string;
    assertionName: string;
    passed: number;
    score: number;
    weight: number;
    reason: string;
  }>;

  return rows.map((row) => ({
    ...row,
    passed: row.passed === 1,
  }));
}

/** Update prompt hash for a pipeline run. */
function _updatePromptHash(db: Database.Database, runId: string, promptHash: string): void {
  db.prepare(`
    UPDATE pipeline_runs SET prompt_hash = ?, updated_at = datetime('now') WHERE run_id = ?
  `).run(promptHash, runId);
}

/** Update assertions JSON summary for a pipeline run. */
function _updateRunAssertions(db: Database.Database, runId: string, assertionsJson: string): void {
  db.prepare(`
    UPDATE pipeline_runs SET assertions_json = ?, updated_at = datetime('now') WHERE run_id = ?
  `).run(assertionsJson, runId);
}

/**
 * Mark pipeline runs stuck in non-terminal states as "aborted".
 * Cleans up orphaned runs from killed processes or crashes.
 */
export function markStaleRunsAborted(db: Database.Database, repo: string): number {
  const result = db
    .prepare(`
    UPDATE pipeline_runs
    SET status = 'aborted', completed_at = datetime('now'), updated_at = datetime('now')
    WHERE repo = ? AND status IN ('scanning', 'triaging', 'verifying', 'poc-harnessing', 'dynamic-analyzing')
  `)
    .run(repo);
  return result.changes;
}

/**
 * Get previously-triaged TP findings in the specified files.
 * Used by regression detection to check if a diff re-introduces a fixed vulnerability.
 */
export function getFixedFindingsForFiles(
  db: Database.Database,
  filePaths: string[],
): Array<{
  fingerprint: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  message: string;
  verdict: string;
}> {
  if (filePaths.length === 0) return [];

  const placeholders = filePaths.map(() => "?").join(", ");
  const rows = db
    .prepare(`
    SELECT fingerprint, rule_id, file_path, start_line, message, verdict
    FROM findings
    WHERE file_path IN (${placeholders})
      AND verdict = 'tp'
    ORDER BY updated_at DESC
  `)
    .all(...filePaths) as Array<{
    fingerprint: string;
    rule_id: string;
    file_path: string;
    start_line: number;
    message: string;
    verdict: string;
  }>;

  return rows.map((row) => ({
    fingerprint: row.fingerprint,
    ruleId: row.rule_id,
    filePath: row.file_path,
    startLine: row.start_line,
    message: row.message,
    verdict: row.verdict,
  }));
}

export * from "./store/crypto-behavioral.js";
export * from "./store/dynamic-analysis.js";
export * from "./store/patch-results.js";
