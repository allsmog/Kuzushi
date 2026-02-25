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
  triageCostUsd?: number;
}

/** Result of exploitability verification for a triaged finding. */
export interface VerificationResult {
  fingerprint: string;
  exploitable: boolean;
  pocPayload: string | null;
  pocDescription: string;
  attackVector: string | null;
  preconditions: string[];
  confidence: number;
  verifyCostUsd?: number;
}

/** Heuristic repository metadata used to enrich triage/verification prompts. */
export interface RepoContext {
  languages: string[];
  frameworks: string[];
  authPatterns: string[];
  sanitizationLibs: string[];
  ormOrDb: string[];
  entryPoints: string[];
}

/** User configuration stored at ~/.kuzushi/config.json (and optional project override). */
export interface KuzushiConfig {
  /** Scanner model identifier (e.g. "claude-sonnet-4-20250514"). */
  model: string;
  /** Optional override model for triage agents. */
  triageModel?: string;
  /** Max turns for triage agents. */
  triageMaxTurns: number;
  /** Enable post-triage exploitability verification phase. */
  verify?: boolean;
  /** Optional override model for verification agents. */
  verifyModel?: string;
  /** Max turns for verification agents. */
  verifyMaxTurns?: number;
  /** Number of in-flight verification tasks. */
  verifyConcurrency?: number;
  /** Which triage verdicts should enter verification. */
  verifyVerdicts?: Verdict[];
  /** Minimum triage confidence required before entering verification. */
  verifyMinConfidence?: number;
  /** Enable pre-scan repository context gathering task. */
  enableContextGathering?: boolean;
  /** Persist per-run JSONL audit logs. */
  auditLog?: boolean;
  /** Optional markdown report output path. */
  reportOutput?: string;
  /** Retry count for triage worker transient failures. */
  maxTriageRetries?: number;
  /** Retry count for verification worker transient failures. */
  maxVerifyRetries?: number;
  /** Initial retry backoff delay in milliseconds. */
  retryBackoffMs?: number;
  /** Backoff multiplier applied per retry attempt. */
  retryBackoffMultiplier?: number;
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
  verifyExploitable?: number | null;
  verifyPocPayload?: string | null;
  verifyPocDescription?: string | null;
  verifyAttackVector?: string | null;
  verifyPreconditions?: string | null;
  verifyConfidence?: number | null;
  verifyCostUsd?: number | null;
  createdAt: string;
  updatedAt: string;
}
