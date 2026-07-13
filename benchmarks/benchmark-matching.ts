import { type MatchingEdge, minimumCostMaximumMatching } from "./benchmark-flow-matching.js";
import type { GroundTruthEntry, MatchResult, SarifResult } from "./types.js";

export interface ScoredFinding {
  result: SarifResult;
  identity: string;
  file: string;
  line: number;
  endLine: number;
  ruleId: string;
  cwes: string[];
}

interface IndexedFinding {
  findingIndex: number;
  line: number;
  identity: string;
}

type FindingIndex = Map<string, IndexedFinding[]>;

const MAX_CANDIDATE_EDGES = 250_000;

class CandidateEdgeBudget {
  private count = 0;

  add(): void {
    this.count += 1;
    if (this.count > MAX_CANDIDATE_EDGES) {
      throw new Error(`Benchmark matching exceeds ${MAX_CANDIDATE_EDGES} candidate edges`);
    }
  }
}

export function matchFindings(
  groundTruth: GroundTruthEntry[],
  findings: ScoredFinding[],
  tolerance: number,
): { matches: MatchResult[]; unmatched: ScoredFinding[] } {
  const index = buildFindingIndex(findings);
  const budget = new CandidateEdgeBudget();
  const edges = groundTruth.map((entry) => candidateEdges(entry, index, tolerance, budget));
  const findingByGroundTruth = minimumCostMaximumMatching(
    groundTruthOrder(groundTruth),
    findings.length,
    edges,
  );
  const findingOwner = new Set(findingByGroundTruth.values());
  const matches = groundTruth.map((entry, index) =>
    matchResult(entry, findings, findingByGroundTruth.get(index)),
  );
  return { matches, unmatched: findings.filter((_, index) => !findingOwner.has(index)) };
}

function candidateEdges(
  entry: GroundTruthEntry,
  index: FindingIndex,
  tolerance: number,
  budget: CandidateEdgeBudget,
): MatchingEdge[] {
  const file = normalizePath(entry.file);
  const candidates = index.get(findingKey(file, cweNumber(entry.cwe))) ?? [];
  const edges: MatchingEdge[] = [];
  const lowerLine = entry.line - tolerance;
  const upperLine = entry.line + tolerance;
  for (
    let cursor = lowerBoundByLine(candidates, lowerLine);
    cursor < candidates.length;
    cursor += 1
  ) {
    const finding = candidates[cursor];
    if (finding.line > upperLine) break;
    budget.add();
    edges.push({
      findingIndex: finding.findingIndex,
      distance: Math.abs(finding.line - entry.line),
      identity: finding.identity,
    });
  }
  return edges.sort(compareEdges);
}

function buildFindingIndex(findings: ScoredFinding[]): FindingIndex {
  const index: FindingIndex = new Map();
  findings.forEach((finding, findingIndex) => {
    for (const cwe of new Set(finding.cwes.map(cweNumber))) {
      if (cwe < 0) continue;
      const key = findingKey(finding.file, cwe);
      const bucket = index.get(key) ?? [];
      bucket.push({ findingIndex, line: finding.line, identity: finding.identity });
      index.set(key, bucket);
    }
  });
  for (const bucket of index.values()) {
    bucket.sort(
      (left, right) => left.line - right.line || left.identity.localeCompare(right.identity),
    );
  }
  return index;
}

function compareEdges(left: MatchingEdge, right: MatchingEdge): number {
  return left.distance - right.distance || left.identity.localeCompare(right.identity);
}

function findingKey(file: string, cwe: number): string {
  return `${file}\0${cwe}`;
}

function lowerBoundByLine(findings: IndexedFinding[], target: number): number {
  let low = 0;
  let high = findings.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (findings[middle].line < target) low = middle + 1;
    else high = middle;
  }
  return low;
}

function matchResult(
  entry: GroundTruthEntry,
  findings: ScoredFinding[],
  findingIndex: number | undefined,
): MatchResult {
  const finding = findingIndex === undefined ? null : findings[findingIndex].result;
  return { groundTruth: entry, finding, matched: finding !== null };
}

function groundTruthOrder(entries: GroundTruthEntry[]): number[] {
  return entries
    .map((_, index) => index)
    .sort((left, right) =>
      groundTruthKey(entries[left]).localeCompare(groundTruthKey(entries[right])),
    );
}

function groundTruthKey(entry: GroundTruthEntry): string {
  return `${normalizePath(entry.file)}:${String(entry.line).padStart(10, "0")}:${entry.cwe}:${entry.id}`;
}

function normalizePath(filePath: string): string {
  return filePath
    .replace(/\\/g, "/")
    .replace(/^file:\/\/\//i, "/")
    .replace(/^\/+/, "")
    .replace(/^[A-Za-z]:\//, "")
    .replace(/^\.\//, "")
    .toLowerCase();
}

function cweNumber(cwe: string): number {
  const match = cwe.match(/(\d+)/);
  return match ? Number(match[1]) : -1;
}
