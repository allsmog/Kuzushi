import type { ScannerConfig, ScannerId } from "./scanners/types.js";

/** Pluggable message bus backend. */
export type BusBackend = "in-process" | "redis" | "google-pubsub" | "nats";

/** Scanner execution mode. */
export type ScanMode = "sequential" | "concurrent";

/** Runtime provider for agent execution. */
export type AgentRuntimeBackend = "claude-sdk" | "acp";

/** Verdict assigned by AI triage. */
export type Verdict = "tp" | "fp" | "needs_review";

/** Options for running a scan. */
export interface ScanOpts {
  severity: string[];
  maxFindings?: number;
  excludePatterns: string[];
  scanners?: ScannerId[];
  fresh: boolean;
}

/** Result of AI triage for a single finding. */
export interface TriageResult {
  fingerprint: string;
  verdict: Verdict;
  confidence: number;
  rationale: string;
  verificationSteps: string[];
  fixPatch: string | null;
}

/** User configuration stored at ~/.kuzushi/config.json (and optional project override). */
export interface KuzushiConfig {
  /** Scanner model identifier (e.g. "claude-sonnet-4-20250514"). */
  model: string;
  /** Optional override model for triage agents. */
  triageModel?: string;
  /** Max turns for triage agents. */
  triageMaxTurns: number;
  /** Message bus backend for pipeline events. */
  busBackend: BusBackend;
  /** Number of in-flight triage tasks. */
  triageConcurrency: number;
  /** Scanner execution strategy. */
  scanMode: ScanMode;
  /** Backend used for agent execution. */
  agentRuntimeBackend?: AgentRuntimeBackend;
  /** Optional list of additional AgentTask IDs to enable in DAG execution. */
  enabledTasks?: string[];
  /** Enabled scanner IDs, in execution order. */
  scanners: ScannerId[];
  /** Default severity filter. */
  severity: string[];
  /** Default exclude patterns for Semgrep-like scanners. */
  excludePatterns: string[];
  /** Scanner-specific config blocks keyed by scanner id. */
  scannerConfig: Record<string, ScannerConfig>;
}

/** A persisted finding row from SQLite. */
export interface FindingRow {
  scanner: ScannerId;
  fingerprint: string;
  repo: string;
  ref: string;
  ruleId: string;
  filePath: string;
  startLine: number;
  severity: string;
  message: string;
  verdict: Verdict;
  confidence: number;
  rationale: string;
  verificationSteps: string;
  fixPatch: string | null;
  createdAt: string;
  updatedAt: string;
}
