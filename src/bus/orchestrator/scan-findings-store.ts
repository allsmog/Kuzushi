/**
 * Memory-bounded buffer abstraction over scan findings.
 *
 * Today the orchestrator's `state.scanFindings` is a plain `Finding[]`
 * accumulated in memory across an entire pipeline run. For very large
 * monorepo scans (10k+ raw findings) that array dominates the heap, and
 * code paths that just need a count or fingerprint set still walk the
 * full array.
 *
 * This module is the foundation for issue #33 — a SQLite-backed iterator
 * that lets the state machine stream findings rather than hold them
 * resident. The interface is intentionally narrow (only the operations
 * the orchestrator actually performs on `state.scanFindings`) so a
 * future PR can swap the in-memory implementation for a persisted one
 * without rewriting every state-machine call site.
 *
 * Scope of this PR (additive only):
 *   - {@link ScanFindingsStore} — the interface.
 *   - {@link InMemoryScanFindingsStore} — the current behavior, an array
 *     wrapper. The orchestrator is NOT migrated to use it yet (deferred);
 *     this lands the contract + tests so the migration PR can focus on
 *     call-site rewrites alone.
 *
 * Follow-up PR will add `SqliteScanFindingsStore` (cursor-paged iteration
 * via `better-sqlite3`'s `stmt.iterate()`) and migrate the call sites in
 * `orchestrator.ts` listed in #33.
 */

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
