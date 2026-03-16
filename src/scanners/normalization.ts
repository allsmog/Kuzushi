import type { CorroboratingSignal, Finding } from "./types.js";
import type { LlmRescoreResult } from "./llm-rescore.js";

const RULE_STOP_WORDS = new Set([
  "codeql",
  "semgrep",
  "security",
  "audit",
  "vulnerability",
  "vuln",
  "rule",
  "query",
  "javascript",
  "js",
  "typescript",
  "ts",
  "python",
  "py",
  "go",
  "java",
  "cpp",
  "cs",
  "dotnet",
  "csharp",
  "ruby",
  "rust",
  "lang",
]);

export interface ClusteredFindingResult {
  findings: Finding[];
  corroboratedClusters: number;
}

export function clusterFindings(findings: Finding[]): ClusteredFindingResult {
  if (findings.length === 0) {
    return { findings: [], corroboratedClusters: 0 };
  }

  const byFingerprint = new Map<string, Finding>();
  for (const finding of findings) {
    const existing = byFingerprint.get(finding.fingerprint);
    if (!existing || getRankingScore(finding) > getRankingScore(existing)) {
      byFingerprint.set(finding.fingerprint, finding);
    }
  }

  const groups = new Map<string, Finding[]>();
  for (const finding of byFingerprint.values()) {
    const key = buildClusterKey(finding);
    const existing = groups.get(key) ?? [];
    existing.push(finding);
    groups.set(key, existing);
  }

  const clustered: Finding[] = [];
  let corroboratedClusters = 0;

  for (const group of groups.values()) {
    const sorted = [...group].sort((a, b) => getRankingScore(b) - getRankingScore(a));
    const primary = sorted[0];
    const corroboratingSignals = mergeCorroboration(primary, sorted.slice(1));
    if (corroboratingSignals.length > 0) {
      corroboratedClusters += 1;
    }
    clustered.push({
      ...primary,
      adjustedScore: primary.adjustedScore ?? primary.score,
      corroboratingSignals: corroboratingSignals.length > 0 ? corroboratingSignals : primary.corroboratingSignals,
    });
  }

  clustered.sort((a, b) => getRankingScore(b) - getRankingScore(a));
  return { findings: clustered, corroboratedClusters };
}

export function getRankingScore(finding: Finding): number {
  return finding.adjustedScore ?? finding.score;
}

export function selectFindingsForRescore(
  findings: Finding[],
  maxFindings?: number,
): Finding[] {
  const sorted = [...findings].sort((a, b) => getRankingScore(b) - getRankingScore(a));
  if (maxFindings === undefined) {
    return sorted;
  }

  const window = Math.max(maxFindings * 2, maxFindings);
  return sorted.slice(0, window);
}

export function applyRescoreResults(
  findings: Finding[],
  rescoreResults: LlmRescoreResult[],
): { findings: Finding[]; skippedByLlmRescore: number } {
  if (rescoreResults.length === 0) {
    return { findings, skippedByLlmRescore: 0 };
  }

  const resultByFingerprint = new Map(rescoreResults.map((result) => [result.fingerprint, result]));
  const kept: Finding[] = [];
  let skipped = 0;

  for (const finding of findings) {
    const result = resultByFingerprint.get(finding.fingerprint);
    if (result && !result.keep) {
      skipped += 1;
      continue;
    }
    kept.push(finding);
  }

  return { findings: kept, skippedByLlmRescore: skipped };
}

export function capFindingsForTriage(findings: Finding[], maxFindings?: number): Finding[] {
  const sorted = [...findings].sort((a, b) => getRankingScore(b) - getRankingScore(a));
  return sorted.slice(0, maxFindings);
}

function mergeCorroboration(primary: Finding, corroborating: Finding[]): CorroboratingSignal[] {
  const result: CorroboratingSignal[] = [...(primary.corroboratingSignals ?? [])];
  const seen = new Set(result.map((signal) => signal.fingerprint));

  for (const finding of corroborating) {
    if (seen.has(finding.fingerprint)) {
      continue;
    }
    seen.add(finding.fingerprint);
    result.push({
      scanner: finding.scanner,
      fingerprint: finding.fingerprint,
      ruleId: finding.ruleId,
      filePath: finding.filePath,
      startLine: finding.startLine,
      cwe: [...finding.cwe],
      score: finding.score,
    });
  }

  return result;
}

function buildClusterKey(finding: Finding): string {
  const filePath = normalizePathForKey(finding.filePath);
  const line = Number.isFinite(finding.startLine) ? Math.max(1, Math.floor(finding.startLine)) : 1;
  const normalizedCwe = normalizeCweForKey(finding.cwe);
  if (normalizedCwe.length > 0) {
    return `loc+cwe|${filePath}|${line}|${normalizedCwe.join(",")}`;
  }

  const normalizedRule = normalizeRuleForKey(finding.ruleId);
  if (normalizedRule) {
    return `loc+rule|${filePath}|${line}|${normalizedRule}`;
  }

  const normalizedMessage = normalizeMessageForKey(finding.message);
  if (normalizedMessage) {
    return `loc+msg|${filePath}|${line}|${normalizedMessage}`;
  }

  return `fp|${finding.fingerprint}`;
}

function normalizePathForKey(filePath: string): string {
  return filePath
    .replace(/\\/g, "/")
    .replace(/^\/+/, "")
    .toLowerCase();
}

function normalizeCweForKey(cwe: string[]): string[] {
  const normalized = cwe
    .map((item) => {
      const match = item.toUpperCase().match(/CWE-(\d+)/);
      return match ? `CWE-${Number.parseInt(match[1], 10)}` : "";
    })
    .filter(Boolean);

  return [...new Set(normalized)].sort((a, b) => a.localeCompare(b));
}

function normalizeRuleForKey(ruleId: string): string {
  const cleaned = ruleId
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim();

  if (!cleaned) {
    return "";
  }

  const tokens = cleaned
    .split(/\s+/)
    .filter((token) => token.length > 0 && !RULE_STOP_WORDS.has(token));

  if (tokens.length === 0) {
    return "";
  }

  return tokens.slice(-4).join("-");
}

function normalizeMessageForKey(message: string): string {
  return message
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, " ")
    .trim()
    .split(/\s+/)
    .slice(0, 6)
    .join("-");
}
