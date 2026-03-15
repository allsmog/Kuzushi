/**
 * Shared types for the benchmark evaluation harness.
 */

/** A single entry in a ground-truth dataset. */
export interface GroundTruthEntry {
  /** Unique test case identifier (e.g. "BenchmarkTest00001"). */
  id: string;
  /** Relative file path within the repo. */
  file: string;
  /** Source line of the vulnerability (or FP test site). */
  line: number;
  /** CWE identifier (e.g. "CWE-089"). */
  cwe: string;
  /** true = real vulnerability, false = non-vulnerable test case. */
  isVulnerable: boolean;
  /** Optional human-readable category (e.g. "sqli", "xss"). */
  category?: string;
}

/** A complete ground-truth dataset for a benchmark suite. */
export interface GroundTruthDataset {
  name: string;
  language: string;
  repoUrl: string;
  /** Git commit or tag to pin the benchmark at. */
  repoRef?: string;
  entries: GroundTruthEntry[];
}

/** Result of matching a single ground-truth entry against SARIF findings. */
export interface MatchResult {
  groundTruth: GroundTruthEntry;
  /** The matched SARIF result, or null if no match (FN for vulns, TN for non-vulns). */
  finding: SarifResult | null;
  matched: boolean;
}

/** Per-CWE metrics breakdown. */
export interface CweMetrics {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number;
  recall: number;
  f1: number;
}

/** Aggregate benchmark metrics for a single dataset evaluation. */
export interface BenchmarkMetrics {
  dataset: string;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number;
  recall: number;
  f1: number;
  perCwe: Record<string, CweMetrics>;
  costUsd: number;
  durationMs: number;
}

// ── Minimal SARIF v2.1.0 type stubs for parsing ──

export interface SarifLog {
  $schema?: string;
  version: string;
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      rules?: SarifRule[];
    };
  };
  results: SarifResult[];
  properties?: Record<string, unknown>;
}

export interface SarifRule {
  id: string;
  properties?: {
    tags?: string[];
    [key: string]: unknown;
  };
}

export interface SarifResult {
  ruleId: string;
  level?: string;
  message: { text: string };
  locations?: SarifLocation[];
  properties?: {
    verdict?: string;
    confidence?: number;
    rationale?: string;
    exploitable?: boolean;
    [key: string]: unknown;
  };
  suppressions?: Array<{ kind: string; justification?: string }>;
}

export interface SarifLocation {
  physicalLocation?: {
    artifactLocation?: { uri: string };
    region?: { startLine: number; endLine?: number };
  };
}

/** A diff entry when comparing two SARIF files. */
export interface SarifDiffEntry {
  kind: "added" | "removed" | "changed";
  fingerprint: string;
  ruleId: string;
  file: string;
  line: number;
  details?: {
    before?: { verdict?: string; confidence?: number };
    after?: { verdict?: string; confidence?: number };
  };
}

/** Stored baseline metrics for regression gating. */
export interface BaselineMetrics {
  updatedAt: string;
  datasets: Record<string, BenchmarkMetrics>;
}
