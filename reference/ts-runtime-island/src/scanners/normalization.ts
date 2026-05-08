import type { LlmRescoreResult } from "./llm-rescore.js";
import type { CorroboratingSignal, Finding } from "./types.js";

const PROOF_STATE_PRECEDENCE: Record<NonNullable<Finding["proofState"]>, number> = {
  symbolic_only: 0,
  inconclusive: 1,
  execution_attempted: 2,
  execution_rejected: 3,
  execution_confirmed: 4,
};

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
    if (!existing || shouldReplaceFingerprintEntry(existing, finding)) {
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
      corroboratingSignals:
        corroboratingSignals.length > 0 ? corroboratingSignals : primary.corroboratingSignals,
    });
  }

  clustered.sort((a, b) => getRankingScore(b) - getRankingScore(a));
  return { findings: clustered, corroboratedClusters };
}

export function getRankingScore(finding: Finding): number {
  return finding.adjustedScore ?? finding.score;
}

export function selectFindingsForRescore(findings: Finding[], maxFindings?: number): Finding[] {
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
      taskId: finding.taskId,
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

function shouldReplaceFingerprintEntry(existing: Finding, candidate: Finding): boolean {
  const existingScore = getRankingScore(existing);
  const candidateScore = getRankingScore(candidate);
  if (candidateScore > existingScore) {
    return true;
  }
  if (candidateScore < existingScore) {
    return false;
  }

  const existingProof = existing.proofState ? PROOF_STATE_PRECEDENCE[existing.proofState] : -1;
  const candidateProof = candidate.proofState ? PROOF_STATE_PRECEDENCE[candidate.proofState] : -1;
  if (candidateProof > existingProof) {
    return true;
  }
  if (candidateProof < existingProof) {
    return false;
  }

  const existingProvenanceCount = existing.engineProvenance?.length ?? 0;
  const candidateProvenanceCount = candidate.engineProvenance?.length ?? 0;
  if (candidateProvenanceCount > existingProvenanceCount) {
    return true;
  }
  if (candidateProvenanceCount < existingProvenanceCount) {
    return false;
  }

  return false;
}

/**
 * Extract dataflow source and sink from finding message/evidence for clustering.
 * Returns source|sink key if both can be extracted, undefined otherwise.
 */
export function normalizeDataflowForKey(finding: Finding): string | undefined {
  const text = `${finding.message} ${finding.evidence ?? ""}`.toLowerCase();

  // Extract source: input parameters, request properties, user-controlled data
  const sourcePatterns = [
    /(?:from|source|input|param(?:eter)?|user[- ]?(?:input|controlled|supplied))\s*[:\-=]?\s*[`"']?(\w[\w.[\]]*)/i,
    /(?:req|request)\.(query|body|params|headers|cookies)(?:\.(\w+)|\[["'](\w+)["']\])?/i,
    /(?:tainted|untrusted|external)\s+(?:data|input|value)\s+[`"']?(\w[\w.]*)/i,
  ];

  let source: string | undefined;
  for (const pattern of sourcePatterns) {
    const match = text.match(pattern);
    if (match) {
      source = (match[3] ?? match[2] ?? match[1] ?? "").trim().toLowerCase();
      if (source.length > 1) break;
      source = undefined;
    }
  }

  // Extract sink: dangerous function calls, SQL queries, command execution
  const sinkPatterns = [
    /(?:to|sink|into|passed to|flows? to)\s*[:\-=]?\s*[`"']?(\w[\w.]*\(\)?)'/i,
    /(?:exec|execute|query|eval|innerHTML|write|send|render|spawn|system)\s*\(/i,
    /(?:sql|command|shell|template|html)\s+(?:injection|execution)/i,
  ];

  let sink: string | undefined;
  for (const pattern of sinkPatterns) {
    const match = text.match(pattern);
    if (match) {
      sink = (match[1] ?? match[0] ?? "").trim().toLowerCase().replace(/[()]/g, "");
      if (sink.length > 1) break;
      sink = undefined;
    }
  }

  if (source && sink) {
    return `${source}|${sink}`;
  }

  return undefined;
}

function buildClusterKey(finding: Finding): string {
  const filePath = normalizePathForKey(finding.filePath);
  const line = Number.isFinite(finding.startLine) ? Math.max(1, Math.floor(finding.startLine)) : 1;

  // Try dataflow-based clustering: same source→sink at different callsites
  const dataflowKey = normalizeDataflowForKey(finding);
  const normalizedCwe = normalizeCweForKey(finding.cwe);
  if (dataflowKey && normalizedCwe.length > 0) {
    return `loc+dataflow|${dataflowKey}|${normalizedCwe.join(",")}`;
  }

  // Fall back to location-based clustering
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
  return filePath.replace(/\\/g, "/").replace(/^\/+/, "").toLowerCase();
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
