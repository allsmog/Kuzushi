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
  /** Full immutable Git commit digest, or a synthetic ref for fixture:// datasets. */
  repoRef: string;
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
  /** Self-contained identity for the inputs and contract that produced this result. */
  provenance: BenchmarkResultProvenance;
  tp: number;
  fp: number;
  fn: number;
  tn: number;
  precision: number;
  recall: number;
  f1: number;
  perCwe: Record<string, CweMetrics>;
  costUsd: number;
  /** Receipt proving costUsd came from one explicit aggregate spend record. */
  spend: BenchmarkSpendReceipt;
  durationMs: number;
}

export type BenchmarkSpendSource = "canonical-run-summary" | "deterministic-fixture";

export interface BenchmarkSpendReceipt {
  measured: true;
  runId: string;
  source: BenchmarkSpendSource;
  /** Models observed in canonical trace-backed run summaries. */
  models: string[];
  /** Number of observed model calls across the exported scan run set. */
  llmCallCount: number;
  /** False when a canonical trace could not be parsed completely. */
  llmAuditComplete: boolean;
  /** Hash of the resolved runtime config recorded by the outer run. */
  configHash?: string;
}

// ── Minimal SARIF v2.1.0 type stubs for parsing ──

export interface SarifLog {
  $schema?: string;
  version: string;
  runs: SarifRun[];
  properties?: Record<string, unknown>;
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
  fingerprints?: Record<string, string>;
  properties?: {
    verdict?: string;
    confidence?: number;
    rationale?: string;
    exploitable?: boolean;
    kuzushiCwe?: string;
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

export type BenchmarkExecutionMode = "deterministic-fixture" | "real-model";

/** Explicit operator/fixture declaration. Digests are derived by the harness. */
export interface BenchmarkProvenanceInput {
  schemaVersion: 1;
  executionMode: BenchmarkExecutionMode;
  harnessContractVersion: string;
  scanConfig: BenchmarkScanConfig;
  modelIdentity: string;
  kuzushiRevision: string;
  generatedAt: string;
}

/** Exact command-line surface the benchmark harness owns and applies. */
export interface BenchmarkScanConfig {
  mode?: "standard" | "whitebox-static";
  tasks?: string;
  failOn?: "low" | "medium" | "high" | "critical";
  budget?: string;
}

/** Fields that must match before metrics can be compared. */
export interface BenchmarkComparableProvenance {
  datasetName: string;
  datasetDigest: string;
  datasetRevision: string;
  harnessContractVersion: string;
  harnessDigest: string;
  scanConfigDigest: string;
  modelIdentity: string;
  scoringMode: "strict-cwe-v1";
}

/** Fields that identify the two observations without blocking comparison. */
export interface BenchmarkObservedProvenance {
  kuzushiRevision: string;
  generatedAt: string;
  durationMs: number;
  runId: string;
  spendSource: BenchmarkSpendSource;
  models: string[];
  llmCallCount: number;
  llmAuditComplete: boolean;
  configHash?: string;
}

export interface BenchmarkResultProvenance {
  schemaVersion: 1;
  mode: BenchmarkExecutionMode;
  comparable: BenchmarkComparableProvenance;
  observed: BenchmarkObservedProvenance;
}

export interface BaselineMetrics {
  schemaVersion: 2;
  updatedAt: string;
  datasets: Record<string, BenchmarkMetrics>;
}
