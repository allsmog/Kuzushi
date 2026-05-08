/**
 * Memory-bounded buffer abstraction over scan findings.
 *
 * The orchestrator's `state.scanFindings` is a buffer of raw findings
 * accumulated across an entire pipeline run. For very large monorepo
 * scans (10k+ raw findings) that buffer dominates the heap, and call
 * sites that just need a count or fingerprint set would otherwise walk
 * the full collection.
 *
 * Two implementations live here:
 *   - {@link InMemoryScanFindingsStore} — default. A `Finding[]` wrapper.
 *   - {@link SqliteScanFindingsStore} — persisted via better-sqlite3,
 *     cursor-paged via `stmt.iterate()`. Backed by the `scan_findings`
 *     table from migration v108.
 *
 * Selection happens via {@link createScanFindingsStore} keyed off
 * `KuzushiConfig.scanFindingsBackend`. The SQLite path is opt-in until
 * validated under real monorepo loads.
 */

import type Database from "better-sqlite3";
import type { Finding } from "../../scanners/types.js";

/**
 * Narrow set of operations the orchestrator performs on `state.scanFindings`.
 * Anything that can be expressed in terms of these primitives (count, push,
 * replace, fingerprint listing, iteration) survives the SQLite migration
 * without code change at the call site.
 */
export interface ScanFindingsStore {
  /** Append a single finding to the buffer (ordered by insert time). */
  add(finding: Finding): void;
  /** Append many findings in one call (no array materialization required for SQLite impl). */
  addAll(findings: Iterable<Finding>): void;
  /** Total finding count without materializing the full collection. */
  count(): number;
  /**
   * Replace the entire buffer contents. Mirrors the orchestrator's
   * `state.scanFindings = newArray` assignment after cluster/dedup/filter.
   */
  replace(findings: Iterable<Finding>): void;
  /** Drop all findings — used at the start of resumption / stage-skip paths. */
  clear(): void;
  /**
   * Iterate findings in insertion order. Cheap for InMemory; cursor-paged
   * for the future SQLite implementation. Iteration must remain valid even
   * if {@link add} is called for *future* findings (consumers commonly
   * iterate during dispatch).
   */
  iterate(): IterableIterator<Finding>;
  /** Fingerprint-only projection — used by alreadyTriaged / dispatch loops. */
  fingerprints(): string[];
  /**
   * Materialize the buffer as an in-memory `Finding[]`. Reserved for
   * legacy call sites that pass the array to clusterFindings / SARIF /
   * report builders. The migration PR will incrementally remove these
   * call sites in favor of streaming consumers.
   */
  toArray(): Finding[];
}

/**
 * Default in-memory implementation. Behaviorally identical to a
 * `Finding[]` — wraps `push`, `length`, and `for..of`.
 */
export class InMemoryScanFindingsStore implements ScanFindingsStore {
  private items: Finding[] = [];

  constructor(initial?: Iterable<Finding>) {
    if (initial) {
      this.items = [...initial];
    }
  }

  add(finding: Finding): void {
    this.items.push(finding);
  }

  addAll(findings: Iterable<Finding>): void {
    for (const f of findings) this.items.push(f);
  }

  count(): number {
    return this.items.length;
  }

  replace(findings: Iterable<Finding>): void {
    this.items = [...findings];
  }

  clear(): void {
    this.items = [];
  }

  iterate(): IterableIterator<Finding> {
    return this.items[Symbol.iterator]();
  }

  fingerprints(): string[] {
    return this.items.map((f) => f.fingerprint);
  }

  toArray(): Finding[] {
    return [...this.items];
  }
}

/**
 * SQLite-backed implementation. Each store instance is scoped to a single
 * `runId`; rows for that run live in the `scan_findings` table seeded by
 * migration v108. Iteration uses better-sqlite3's `stmt.iterate()` so very
 * large finding sets don't materialize as arrays.
 *
 * Ordering is preserved by a per-run `ordinal` counter. `replace()` rewrites
 * the whole run in a single transaction; `clear()` drops every row for the
 * run.
 */
export class SqliteScanFindingsStore implements ScanFindingsStore {
  private nextOrdinal: number;
  private readonly insertStmt: Database.Statement;
  private readonly deleteStmt: Database.Statement;
  private readonly countStmt: Database.Statement;
  private readonly iterateStmt: Database.Statement;
  private readonly fingerprintsStmt: Database.Statement;
  private readonly insertMany: Database.Transaction<(rows: Finding[]) => void>;
  private readonly replaceTxn: Database.Transaction<(rows: Finding[]) => void>;

  constructor(
    private readonly db: Database.Database,
    private readonly runId: string,
  ) {
    this.insertStmt = db.prepare(
      `INSERT INTO scan_findings (run_id, ordinal, finding_json) VALUES (?, ?, ?)`,
    );
    this.deleteStmt = db.prepare(`DELETE FROM scan_findings WHERE run_id = ?`);
    this.countStmt = db.prepare(`SELECT COUNT(*) AS n FROM scan_findings WHERE run_id = ?`);
    this.iterateStmt = db.prepare(
      `SELECT finding_json FROM scan_findings WHERE run_id = ? ORDER BY ordinal ASC`,
    );
    this.fingerprintsStmt = db.prepare(
      `SELECT finding_json FROM scan_findings WHERE run_id = ? ORDER BY ordinal ASC`,
    );

    // Resume case: if rows already exist for this runId (resume from
    // checkpoint), continue numbering past the last ordinal so iteration
    // order matches insert order across the lifetime of the run.
    const maxRow = db
      .prepare<[string]>(`SELECT MAX(ordinal) AS maxOrdinal FROM scan_findings WHERE run_id = ?`)
      .get(this.runId) as { maxOrdinal: number | null } | undefined;
    this.nextOrdinal = (maxRow?.maxOrdinal ?? -1) + 1;

    this.insertMany = db.transaction((rows: Finding[]) => {
      for (const finding of rows) {
        this.insertStmt.run(this.runId, this.nextOrdinal, JSON.stringify(finding));
        this.nextOrdinal += 1;
      }
    });

    this.replaceTxn = db.transaction((rows: Finding[]) => {
      this.deleteStmt.run(this.runId);
      this.nextOrdinal = 0;
      for (const finding of rows) {
        this.insertStmt.run(this.runId, this.nextOrdinal, JSON.stringify(finding));
        this.nextOrdinal += 1;
      }
    });
  }

  add(finding: Finding): void {
    this.insertStmt.run(this.runId, this.nextOrdinal, JSON.stringify(finding));
    this.nextOrdinal += 1;
  }

  addAll(findings: Iterable<Finding>): void {
    this.insertMany([...findings]);
  }

  count(): number {
    const row = this.countStmt.get(this.runId) as { n: number };
    return row.n;
  }

  replace(findings: Iterable<Finding>): void {
    this.replaceTxn([...findings]);
  }

  clear(): void {
    this.deleteStmt.run(this.runId);
    this.nextOrdinal = 0;
  }

  *iterate(): IterableIterator<Finding> {
    for (const row of this.iterateStmt.iterate(this.runId) as IterableIterator<{
      finding_json: string;
    }>) {
      yield JSON.parse(row.finding_json) as Finding;
    }
  }

  fingerprints(): string[] {
    const out: string[] = [];
    for (const row of this.fingerprintsStmt.iterate(this.runId) as IterableIterator<{
      finding_json: string;
    }>) {
      const parsed = JSON.parse(row.finding_json) as { fingerprint?: unknown };
      if (typeof parsed.fingerprint === "string") {
        out.push(parsed.fingerprint);
      }
    }
    return out;
  }

  toArray(): Finding[] {
    return [...this.iterate()];
  }
}

/** Backend identifier exposed via `KuzushiConfig.scanFindingsBackend`. */
export type ScanFindingsBackend = "memory" | "sqlite";

export interface CreateScanFindingsStoreOptions {
  /** Backend selector. Defaults to `"memory"`. */
  backend?: ScanFindingsBackend;
  /** Required when `backend === "sqlite"`. */
  db?: Database.Database;
  /** Required when `backend === "sqlite"`. */
  runId?: string;
}

/**
 * Resolve a {@link ScanFindingsStore} for the orchestrator. Centralizing
 * the selection lets the orchestrator stay agnostic to the backend choice
 * and gives tests a single seam to flip.
 *
 * Falls back to in-memory if `backend === "sqlite"` but `db`/`runId` are
 * missing — defensive so a misconfigured environment doesn't crash a run.
 */
export function createScanFindingsStore(
  options: CreateScanFindingsStoreOptions = {},
): ScanFindingsStore {
  if (options.backend === "sqlite" && options.db && options.runId) {
    return new SqliteScanFindingsStore(options.db, options.runId);
  }
  return new InMemoryScanFindingsStore();
}
