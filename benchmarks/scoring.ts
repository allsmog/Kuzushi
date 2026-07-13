import { matchFindings, type ScoredFinding } from "./benchmark-matching.js";
import type {
  BenchmarkMetrics,
  BenchmarkResultProvenance,
  BenchmarkSpendReceipt,
  CweMetrics,
  GroundTruthDataset,
  MatchResult,
  SarifLog,
  SarifResult,
  SarifRule,
} from "./types.js";

export const DEFAULT_LINE_TOLERANCE = 10;
export const MAX_LINE_TOLERANCE = 100;
const MAX_CWES_PER_FINDING = 64;

interface Counts {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
}

export interface BenchmarkEvaluation {
  metrics: BenchmarkMetrics;
  scoredFindingCount: number;
}

export function parseLineTolerance(raw: string): number {
  const normalized = raw.trim();
  if (!/^\d+$/.test(normalized)) throw invalidTolerance(raw);
  const value = Number(normalized);
  if (!Number.isSafeInteger(value) || value > MAX_LINE_TOLERANCE) throw invalidTolerance(raw);
  return value;
}

export function evaluateBenchmark(
  dataset: GroundTruthDataset,
  sarif: SarifLog,
  lineTolerance: number,
  costUsd: number,
  spend: BenchmarkSpendReceipt,
  durationMs: number,
  provenance: BenchmarkResultProvenance,
): BenchmarkEvaluation {
  const findings = flattenSarifFindings(sarif);
  const outcome = matchFindings(dataset.entries, findings, lineTolerance);
  return {
    metrics: computeMetrics(dataset.name, outcome, costUsd, spend, durationMs, provenance),
    scoredFindingCount: findings.length,
  };
}

function invalidTolerance(raw: string): Error {
  return new Error(
    `Invalid line tolerance ${JSON.stringify(raw)}; expected a decimal integer from 0 to ${MAX_LINE_TOLERANCE}`,
  );
}

function flattenSarifFindings(sarif: SarifLog): ScoredFinding[] {
  if (!Array.isArray(sarif.runs) || sarif.runs.length === 0) {
    throw new Error("No runs found in SARIF file");
  }
  const deduped = new Map<string, ScoredFinding>();
  for (const run of sarif.runs) addRunFindings(deduped, run.results, run.tool?.driver?.rules);
  return [...deduped.values()].sort((left, right) => left.identity.localeCompare(right.identity));
}

function addRunFindings(
  deduped: Map<string, ScoredFinding>,
  results: SarifResult[],
  rules: SarifRule[] | undefined,
): void {
  if (!Array.isArray(results)) throw new Error("Every SARIF run must contain a results array");
  const tags = ruleTagMap(rules);
  for (const result of results) {
    const finding = scoredFinding(result, tags);
    if (finding) mergeFinding(deduped, finding);
  }
}

function mergeFinding(deduped: Map<string, ScoredFinding>, finding: ScoredFinding): void {
  const existing = deduped.get(finding.identity);
  if (!existing) {
    deduped.set(finding.identity, finding);
    return;
  }
  ensureDuplicateIsConsistent(existing, finding);
  existing.cwes = sortedUnique([...existing.cwes, ...finding.cwes]);
}

function ensureDuplicateIsConsistent(existing: ScoredFinding, duplicate: ScoredFinding): void {
  const sameSite =
    existing.file === duplicate.file &&
    existing.line === duplicate.line &&
    existing.endLine === duplicate.endLine;
  if (sameSite && existing.ruleId === duplicate.ruleId) return;
  throw new Error(`Conflicting SARIF results reuse stable identity ${existing.identity}`);
}

function scoredFinding(result: SarifResult, tags: Map<string, string[]>): ScoredFinding | null {
  if (typeof result?.ruleId !== "string" || result.ruleId.trim().length === 0) {
    throw new Error("SARIF result is missing a nonempty ruleId");
  }
  const location = result.locations?.[0]?.physicalLocation;
  const uri = location?.artifactLocation?.uri;
  if (typeof uri === "string" && externalUri(uri)) return null;
  return localScoredFinding(result, tags, localPath(uri), location?.region);
}

function localScoredFinding(
  result: SarifResult,
  tags: Map<string, string[]>,
  file: string | null,
  region: { startLine: number; endLine?: number } | undefined,
): ScoredFinding {
  const line = region?.startLine;
  if (!file || !Number.isSafeInteger(line) || (line ?? 0) < 1) {
    throw new Error(
      `SARIF result ${JSON.stringify(result.ruleId)} has no scoreable local location`,
    );
  }
  const endLine = validEndLine(region?.endLine, line!);
  const cwes = extractCwes(result, tags);
  if (cwes.length > MAX_CWES_PER_FINDING) {
    throw new Error(`SARIF result ${JSON.stringify(result.ruleId)} contains too many CWE labels`);
  }
  return {
    result,
    identity: findingIdentity(result, file, line!, endLine),
    file,
    line: line!,
    endLine,
    ruleId: result.ruleId.trim().toLowerCase(),
    cwes,
  };
}

function validEndLine(value: number | undefined, startLine: number): number {
  if (value === undefined) return startLine;
  if (!Number.isSafeInteger(value) || value < startLine) {
    throw new Error("SARIF result has an invalid endLine");
  }
  return value;
}

function findingIdentity(result: SarifResult, file: string, line: number, endLine: number): string {
  const fingerprint = result.fingerprints?.["kuzushi/v1"]?.trim();
  if (fingerprint) return `kuzushi/v1:${fingerprint}`;
  const identity = stringProperty(result, "kuzushiIdentityId");
  if (identity) return `kuzushi-identity:${identity}`;
  return `location:${file}:${line}:${endLine}:${result.ruleId.trim().toLowerCase()}`;
}

function stringProperty(result: SarifResult, key: string): string | null {
  const value = result.properties?.[key];
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function localPath(uri: string | undefined): string | null {
  if (!uri || externalUri(uri)) return null;
  const normalized = uri
    .replace(/\\/g, "/")
    .replace(/^file:\/\/\//i, "/")
    .replace(/^\/+/, "")
    .replace(/^[A-Za-z]:\//, "")
    .replace(/^\.\//, "")
    .toLowerCase();
  return normalized.length > 0 ? normalized : null;
}

function externalUri(uri: string): boolean {
  if (/^[A-Za-z]:[\\/]/.test(uri)) return false;
  return /^[a-z][a-z\d+.-]*:/i.test(uri) && !/^file:/i.test(uri);
}

function ruleTagMap(rules: SarifRule[] | undefined): Map<string, string[]> {
  const tags = new Map<string, string[]>();
  for (const rule of rules ?? []) tags.set(rule.id, rule.properties?.tags ?? []);
  return tags;
}

function extractCwes(result: SarifResult, tags: Map<string, string[]>): string[] {
  const values = [
    ...(tags.get(result.ruleId) ?? []),
    result.properties?.kuzushiCwe ?? "",
    result.ruleId,
    result.message?.text ?? "",
  ];
  const cwes = values.flatMap(cwesInText).filter((value): value is string => value !== null);
  return sortedUnique(cwes);
}

function cwesInText(value: string): Array<string | null> {
  return [...value.matchAll(/cwe[_-]?(\d+)/gi)].map((match) => canonicalCwe(match[1]));
}

function canonicalCwe(value: string): string | null {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 0) return null;
  return `CWE-${String(number).padStart(3, "0")}`;
}

function sortedUnique(values: string[]): string[] {
  return [...new Set(values)].sort((left, right) => cweNumber(left) - cweNumber(right));
}

function computeMetrics(
  dataset: string,
  outcome: { matches: MatchResult[]; unmatched: ScoredFinding[] },
  costUsd: number,
  spend: BenchmarkSpendReceipt,
  durationMs: number,
  provenance: BenchmarkResultProvenance,
): BenchmarkMetrics {
  const totals = emptyCounts();
  const buckets = new Map<string, Counts>();
  for (const result of outcome.matches) applyGroundTruthResult(totals, buckets, result);
  for (const finding of outcome.unmatched) applyUnmatchedFinding(totals, buckets, finding);
  return {
    dataset,
    provenance,
    ...totals,
    ...metricsFor(totals),
    perCwe: perCweMetrics(buckets),
    costUsd,
    spend,
    durationMs,
  };
}

function applyGroundTruthResult(
  totals: Counts,
  buckets: Map<string, Counts>,
  result: MatchResult,
): void {
  const outcome = classifiedGroundTruthOutcome(result);
  totals[outcome] += 1;
  bucketFor(buckets, result.groundTruth.cwe)[outcome] += 1;
}

function classifiedGroundTruthOutcome(result: MatchResult): keyof Counts {
  if (result.groundTruth.isVulnerable) return result.matched ? "tp" : "fn";
  return result.matched ? "fp" : "tn";
}

function applyUnmatchedFinding(
  totals: Counts,
  buckets: Map<string, Counts>,
  finding: ScoredFinding,
): void {
  totals.fp += 1;
  bucketFor(buckets, finding.cwes[0] ?? "UNKNOWN").fp += 1;
}

function bucketFor(buckets: Map<string, Counts>, cwe: string): Counts {
  const existing = buckets.get(cwe);
  if (existing) return existing;
  const created = emptyCounts();
  buckets.set(cwe, created);
  return created;
}

function emptyCounts(): Counts {
  return { tp: 0, fp: 0, fn: 0, tn: 0 };
}

function metricsFor(counts: Counts): Pick<CweMetrics, "precision" | "recall" | "f1"> {
  const precision = ratio(counts.tp, counts.tp + counts.fp);
  const recall = ratio(counts.tp, counts.tp + counts.fn);
  const f1 = ratio(2 * precision * recall, precision + recall);
  return { precision, recall, f1 };
}

function ratio(numerator: number, denominator: number): number {
  return denominator > 0 ? numerator / denominator : 0;
}

function perCweMetrics(buckets: Map<string, Counts>): Record<string, CweMetrics> {
  return Object.fromEntries(
    [...buckets.entries()]
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([cwe, counts]) => [cwe, { ...counts, ...metricsFor(counts) }]),
  );
}

function cweNumber(cwe: string): number {
  const match = cwe.match(/(\d+)/);
  return match ? Number(match[1]) : Number.MAX_SAFE_INTEGER;
}
