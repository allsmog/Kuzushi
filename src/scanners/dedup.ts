import type { Finding } from "./types.js";

/**
 * Normalize a CWE identifier to a canonical form (e.g. "CWE-89").
 * Returns empty string for unparseable values.
 */
const CWE_PATTERN = /CWE-(\d+)/;
function normalizeCwe(cwe: string): string {
  const match = cwe.toUpperCase().match(CWE_PATTERN);
  return match ? `CWE-${Number.parseInt(match[1], 10)}` : "";
}

/**
 * Compute the list of normalized CWE identifiers for a finding, deduplicated.
 * Returns an empty array when the finding has no CWEs or all are unparseable.
 */
function getCweList(finding: Finding): string[] {
  if (!finding.cwe || !Array.isArray(finding.cwe) || finding.cwe.length === 0) {
    return [];
  }
  let normalized: string[] | undefined;
  let seen: Set<string> | undefined;
  for (const raw of finding.cwe) {
    const canonical = normalizeCwe(raw);
    if (!canonical) continue;
    if (!normalized) {
      normalized = [canonical];
      continue;
    }
    if (!seen) {
      // Lazy allocate the Set only when we have >1 CWE on this finding.
      if (normalized[0] === canonical) continue;
      seen = new Set(normalized);
    }
    if (!seen.has(canonical)) {
      seen.add(canonical);
      normalized.push(canonical);
    }
  }
  return normalized ?? [];
}

/**
 * Deduplicate findings that flag the same code location across multiple tasks.
 *
 * Groups by (filePath, startLine), merges CWE-overlapping findings within each
 * group, and keeps the highest-scored finding per overlap cluster.
 *
 * Findings at the same location with completely disjoint CWE sets represent
 * distinct vulnerability types and are all retained.
 *
 * Findings without any CWE information are treated as having a unique implicit
 * CWE (they can only deduplicate against each other by exact CWE-less match,
 * which means they never overlap with CWE-bearing findings).
 *
 * Implementation: union-find keyed by normalized CWE id. Each CWE-bearing
 * finding unions itself with the representative of every CWE it carries;
 * CWE-less findings stay singleton. O(N · α(N) · avgCwesPerFinding) per
 * location group.
 */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  if (findings.length === 0) {
    return [];
  }

  // Group by location key: filePath:startLine
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    const key = `${finding.filePath}:${finding.startLine}`;
    let group = groups.get(key);
    if (!group) {
      group = [];
      groups.set(key, group);
    }
    group.push(finding);
  }

  const result: Finding[] = [];

  for (const group of groups.values()) {
    if (group.length === 1) {
      result.push(group[0]);
      continue;
    }

    // Union-find over finding indices within this location group.
    // Each CWE-bearing finding unions with the first finding it sees that
    // shares any CWE. CWE-less findings are always their own root.
    const n = group.length;
    const parent = new Int32Array(n);
    for (let i = 0; i < n; i++) parent[i] = i;

    const find = (x: number): number => {
      // Iterative path compression.
      let root = x;
      while (parent[root] !== root) root = parent[root];
      let cursor = x;
      while (parent[cursor] !== root) {
        const next = parent[cursor];
        parent[cursor] = root;
        cursor = next;
      }
      return root;
    };
    const union = (a: number, b: number): void => {
      const ra = find(a);
      const rb = find(b);
      if (ra === rb) return;
      // Keep the lower index as root to preserve first-seen semantics for
      // the cluster-representative walk below.
      if (ra < rb) parent[rb] = ra;
      else parent[ra] = rb;
    };

    // cweOwner: CWE id → first finding index that carried it.
    const cweOwner = new Map<string, number>();
    // Cache normalized CWE lists so we only compute once per finding.
    const cweLists: string[][] = new Array(n);

    for (let i = 0; i < n; i++) {
      const cwes = getCweList(group[i]);
      cweLists[i] = cwes;
      if (cwes.length === 0) continue;
      for (const cwe of cwes) {
        const owner = cweOwner.get(cwe);
        if (owner === undefined) {
          cweOwner.set(cwe, i);
        } else {
          union(i, owner);
        }
      }
    }

    // Collect best finding per cluster root. Order-stable within a group so
    // ties prefer the first-seen finding.
    const bestByRoot = new Map<number, Finding>();
    const rootOrder: number[] = [];

    for (let i = 0; i < n; i++) {
      // CWE-less findings are never union()'d (no CWE to key off), so their
      // parent stays `i` and they naturally form singleton clusters —
      // matching the original implementation's behavior.
      const root = find(i);
      const current = bestByRoot.get(root);
      if (!current) {
        bestByRoot.set(root, group[i]);
        rootOrder.push(root);
        continue;
      }
      const currentScore = current.score ?? 0;
      const candidateScore = group[i].score ?? 0;
      if (candidateScore > currentScore) {
        bestByRoot.set(root, group[i]);
      }
    }

    for (const root of rootOrder) {
      const best = bestByRoot.get(root);
      if (best) result.push(best);
    }
  }

  // Sort by score descending.
  result.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));

  return result;
}
