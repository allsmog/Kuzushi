import type { Finding } from "./types.js";

/**
 * Normalize a CWE identifier to a canonical form (e.g. "CWE-89").
 * Returns empty string for unparseable values.
 */
function normalizeCwe(cwe: string): string {
  const match = cwe.toUpperCase().match(/CWE-(\d+)/);
  return match ? `CWE-${Number.parseInt(match[1], 10)}` : "";
}

/**
 * Compute the set of normalized CWE identifiers for a finding.
 * Returns an empty set when the finding has no CWEs or all are unparseable.
 */
function getCweSet(finding: Finding): Set<string> {
  if (!finding.cwe || !Array.isArray(finding.cwe)) {
    return new Set();
  }
  const normalized = finding.cwe.map(normalizeCwe).filter(Boolean);
  return new Set(normalized);
}

/**
 * Check whether two CWE sets share at least one identifier.
 */
function cweSetsOverlap(a: Set<string>, b: Set<string>): boolean {
  if (a.size === 0 || b.size === 0) {
    return false;
  }
  for (const cwe of a) {
    if (b.has(cwe)) {
      return true;
    }
  }
  return false;
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

    // Within each location group, cluster findings by CWE overlap.
    // Each cluster is a set of findings that transitively share at least one CWE.
    // We use a union-find-like approach: iterate findings and merge into existing
    // clusters when overlap is detected.
    const clusters: Array<{ findings: Finding[]; cwes: Set<string> }> = [];

    for (const finding of group) {
      const findingCwes = getCweSet(finding);

      if (findingCwes.size === 0) {
        // Findings without CWE info cannot overlap with anything — keep as singleton.
        clusters.push({ findings: [finding], cwes: new Set() });
        continue;
      }

      // Find all existing clusters this finding overlaps with.
      const overlappingIndices: number[] = [];
      for (let i = 0; i < clusters.length; i++) {
        if (clusters[i].cwes.size > 0 && cweSetsOverlap(findingCwes, clusters[i].cwes)) {
          overlappingIndices.push(i);
        }
      }

      if (overlappingIndices.length === 0) {
        // No overlap — start a new cluster.
        clusters.push({ findings: [finding], cwes: new Set(findingCwes) });
      } else {
        // Merge into the first overlapping cluster and absorb any other
        // overlapping clusters into it (transitive merge).
        const primaryIdx = overlappingIndices[0];
        const primary = clusters[primaryIdx];
        primary.findings.push(finding);
        for (const cwe of findingCwes) {
          primary.cwes.add(cwe);
        }

        // Merge additional overlapping clusters into primary (reverse order for safe splicing).
        for (let j = overlappingIndices.length - 1; j >= 1; j--) {
          const mergeIdx = overlappingIndices[j];
          const merged = clusters[mergeIdx];
          for (const f of merged.findings) {
            primary.findings.push(f);
          }
          for (const cwe of merged.cwes) {
            primary.cwes.add(cwe);
          }
          clusters.splice(mergeIdx, 1);
        }
      }
    }

    // From each cluster, keep only the highest-scored finding.
    for (const cluster of clusters) {
      let best = cluster.findings[0];
      for (let i = 1; i < cluster.findings.length; i++) {
        const candidate = cluster.findings[i];
        const candidateScore = candidate.score ?? 0;
        const bestScore = best.score ?? 0;
        if (candidateScore > bestScore) {
          best = candidate;
        }
      }
      result.push(best);
    }
  }

  // Sort by score descending.
  result.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));

  return result;
}
