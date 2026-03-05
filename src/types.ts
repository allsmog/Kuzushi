import type { ScannerConfig, ScannerId } from "./scanners/types.js";

/** Pluggable message bus backend. */
export type BusBackend = "in-process" | "redis" | "google-pubsub" | "nats";

/** Scanner execution mode. */
export type ScanMode = "sequential" | "concurrent";

/** Runtime provider for agent execution. */
export type AgentRuntimeBackend = "pi-ai" | "acp";

/** Configuration for agent runtime authentication and endpoint selection. */
export interface AgentRuntimeConfig {
  /** API key for the LLM provider. Overrides ANTHROPIC_API_KEY when set. */
  apiKey?: string;
  /** Base URL for the LLM API endpoint. Overrides ANTHROPIC_BASE_URL when set. */
  baseUrl?: string;
}

/** Verdict assigned by AI triage. */
export type Verdict = "tp" | "fp" | "needs_review";

export interface TriagePathAssessment {
  why: string;
  isFalsePositive: boolean;
  evidence: string;
}

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
  source?: TriagePathAssessment;
  sink?: TriagePathAssessment;
  isVulnerable?: boolean;
  exploitScenario?: string;
  recommendedFix?: string;
  ruleRefinementHint?: string;
  triageSchemaVersion?: string;
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

/** Result of PoC harness generation for a verified-exploitable finding. */
export interface PocHarnessResult {
  fingerprint: string;
  scriptPath: string | null;
  language: string | null;
  scriptContent: string | null;
  parsed: boolean;
  parseError: string | null;
  skipped: boolean;
  skipReason: string | null;
  costUsd?: number;
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
  /** Scanner model identifier (e.g. "anthropic:claude-sonnet-4-6"). */
  model: string;
  /** Optional override model for triage agents. */
  triageModel?: string;
  /** Max turns for triage agents. null = unlimited. */
  triageMaxTurns: number | null;
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
  /** Enable post-verification PoC harness generation phase. */
  pocHarness?: boolean;
  /** Optional override model for PoC harness generation agents. */
  pocHarnessModel?: string;
  /** Max turns for PoC harness generation agents. */
  pocHarnessMaxTurns?: number;
  /** Number of in-flight PoC harness generation tasks. */
  pocHarnessConcurrency?: number;
  /** Enable pre-scan repository context gathering task. */
  enableContextGathering?: boolean;
  /** Persist per-run JSONL audit logs. */
  auditLog?: boolean;
  /** Optional markdown report output path. */
  reportOutput?: string;
  /** Optional SARIF report output path. */
  sarifOutput?: string;
  /** Retry count for triage worker transient failures. */
  maxTriageRetries?: number;
  /** Retry count for verification worker transient failures. */
  maxVerifyRetries?: number;
  /** Retry count for PoC harness worker transient failures. */
  maxPocHarnessRetries?: number;
  /** Initial retry backoff delay in milliseconds. */
  retryBackoffMs?: number;
  /** Backoff multiplier applied per retry attempt. */
  retryBackoffMultiplier?: number;
  /** Message bus backend for pipeline events. */
  busBackend: BusBackend;
  /** Maximum findings per batch triage LLM call. */
  triageBatchSize: number;
  /** Number of in-flight triage tasks. */
  triageConcurrency: number;
  /** Scanner execution strategy. */
  scanMode: ScanMode;
  /** Backend used for agent execution. */
  agentRuntimeBackend?: AgentRuntimeBackend;
  /** Optional runtime-level credentials and endpoint overrides. */
  agentRuntimeConfig?: AgentRuntimeConfig;
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
  triageDetailsJson?: string | null;
  verifyExploitable?: number | null;
  verifyPocPayload?: string | null;
  verifyPocDescription?: string | null;
  verifyAttackVector?: string | null;
  verifyPreconditions?: string | null;
  verifyConfidence?: number | null;
  verifyCostUsd?: number | null;
  pocHarnessPath?: string | null;
  pocHarnessLanguage?: string | null;
  pocHarnessParsed?: number | null;
  pocHarnessParseError?: string | null;
  pocHarnessSkipped?: number | null;
  pocHarnessSkipReason?: string | null;
  pocHarnessCostUsd?: number | null;
  createdAt: string;
  updatedAt: string;
}
