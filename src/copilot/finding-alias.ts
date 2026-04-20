/**
 * Deterministic short-ID aliases for findings and exploit chains (Phase B.3).
 *
 * Operators want to type `verify F-0108` or `open C-01` instead of
 * 12-char fingerprints / opaque chain ids. This module derives a stable
 * per-run alias map from the finding list without requiring a separate
 * persistence layer: sort findings by severity (desc) then fingerprint
 * (asc, lexicographic) and assign F-0001, F-0002, …; sort chains the
 * same way for C-01, C-02, …
 *
 * "Deterministic" = the same finding/chain always gets the same alias
 * for a given snapshot. Once aliases are persisted with the run (v2
 * of this module), the alias also survives across re-hydration.
 */

import type { ExploitChain } from "../types.js";
import type { ActionableFinding } from "../ui/state.js";

// ---------------------------------------------------------------------------
// Computation
// ---------------------------------------------------------------------------

/** A single alias entry (forward + reverse for easy printing). */
export interface AliasEntry {
  /** Short alias (e.g. "F-0001"). */
  alias: string;
  /** Canonical id the alias points to. */
  target: string;
}

/** Severity precedence — highest-impact findings get the lowest numbers. */
const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

function severityRank(finding: ActionableFinding): number {
  const sev = (finding.displaySeverity ?? finding.severity ?? "").toLowerCase();
  if (sev.includes("crit")) return SEVERITY_ORDER.critical!;
  if (sev.includes("high")) return SEVERITY_ORDER.high!;
  if (sev.includes("med")) return SEVERITY_ORDER.medium!;
  return SEVERITY_ORDER.low!;
}

function compareFindings(a: ActionableFinding, b: ActionableFinding): number {
  const da = severityRank(a);
  const db = severityRank(b);
  if (da !== db) return da - db;
  return a.fingerprint.localeCompare(b.fingerprint);
}

/**
 * Assign F-NNNN aliases in severity-then-fingerprint order. Aliases are
 * zero-padded to 4 digits (F-0001) so a lexicographic sort matches a
 * numeric sort up to 9999 findings.
 */
export function computeFindingAliases(findings: ReadonlyArray<ActionableFinding>): AliasEntry[] {
  return [...findings].sort(compareFindings).map((f, i) => ({
    alias: `F-${String(i + 1).padStart(4, "0")}`,
    target: f.fingerprint,
  }));
}

/**
 * Assign C-NN aliases to exploit chains in severity-then-id order. Two
 * digits is typical (a single run rarely produces more than 99 chains).
 */
export function computeChainAliases(chains: ReadonlyArray<ExploitChain>): AliasEntry[] {
  const severityPos: Record<ExploitChain["overallSeverity"], number> = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
  };
  return [...chains]
    .sort((a, b) => {
      const ds = severityPos[a.overallSeverity] - severityPos[b.overallSeverity];
      return ds !== 0 ? ds : a.id.localeCompare(b.id);
    })
    .map((chain, i) => ({
      alias: `C-${String(i + 1).padStart(2, "0")}`,
      target: chain.id,
    }));
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/**
 * Case-insensitive alias resolver. Accepts the alias itself (`F-0108`),
 * the raw fingerprint, or a fingerprint prefix ≥ 4 chars.
 *
 * Returns the target (fingerprint / chain id) or undefined.
 */
export function resolveAlias(
  input: string,
  aliases: ReadonlyArray<AliasEntry>,
  /**
   * Optional raw-id corpus — when set, a non-alias input falls back to
   * prefix-match against these ids so operators can always paste a bare
   * fingerprint / chain id.
   */
  rawCorpus?: ReadonlyArray<string>,
): string | undefined {
  if (!input) return undefined;
  const normalized = input.trim();

  // Alias path — F-\d+ or C-\d+ (case-insensitive).
  const aliasPattern = /^[fc]-\d+$/i;
  if (aliasPattern.test(normalized)) {
    const wanted = canonicaliseAlias(normalized);
    const hit = aliases.find((a) => a.alias === wanted);
    if (hit) return hit.target;
    return undefined;
  }

  // Raw id path — exact or prefix match. Ambiguous prefixes return undefined.
  if (rawCorpus && rawCorpus.length > 0) {
    const exact = rawCorpus.find((id) => id === normalized);
    if (exact) return exact;
    if (normalized.length >= 4) {
      const matches = rawCorpus.filter((id) => id.startsWith(normalized));
      if (matches.length === 1) return matches[0];
    }
  }
  return undefined;
}

/** Normalise aliases to the canonical zero-padded form (`f-1` → `F-0001`). */
function canonicaliseAlias(raw: string): string {
  const [prefix, digits] = raw.toUpperCase().split("-");
  if (!prefix || !digits) return raw.toUpperCase();
  const width = prefix === "F" ? 4 : 2;
  return `${prefix}-${digits.padStart(width, "0")}`;
}

// ---------------------------------------------------------------------------
// Formatters (used by `/show aliases`)
// ---------------------------------------------------------------------------

/**
 * Format an alias table for a list of findings / chains, optionally filtered
 * by a prefix (e.g. "F-" shows only findings). Output is plain text — the
 * shell wraps it as a history entry.
 */
export function formatAliasTable(
  findingAliases: ReadonlyArray<AliasEntry>,
  chainAliases: ReadonlyArray<AliasEntry>,
  prefix?: string,
  /** Optional title lookups — shown after the target for context. */
  titleByTarget?: Record<string, string | undefined>,
): string {
  const filter = prefix?.toUpperCase();
  const rows: Array<[string, string, string]> = [];

  for (const entry of chainAliases) {
    if (filter && !entry.alias.startsWith(filter)) continue;
    rows.push([entry.alias, entry.target, titleByTarget?.[entry.target] ?? ""]);
  }
  for (const entry of findingAliases) {
    if (filter && !entry.alias.startsWith(filter)) continue;
    rows.push([entry.alias, entry.target.slice(0, 12), titleByTarget?.[entry.target] ?? ""]);
  }

  if (rows.length === 0) {
    return filter ? `No aliases match "${prefix}".` : "No aliases for the current run.";
  }

  const widths = [
    Math.max("alias".length, ...rows.map((r) => r[0].length)),
    Math.max("target".length, ...rows.map((r) => r[1].length)),
  ];
  const pad = (s: string, w: number) => s.padEnd(w);
  const header = `${pad("alias", widths[0]!)}  ${pad("target", widths[1]!)}  title`;
  const hr = `${"─".repeat(widths[0]!)}  ${"─".repeat(widths[1]!)}  ${"─".repeat(5)}`;
  const body = rows
    .map(([a, t, title]) => `${pad(a, widths[0]!)}  ${pad(t, widths[1]!)}  ${title}`)
    .join("\n");
  return `${header}\n${hr}\n${body}`;
}
