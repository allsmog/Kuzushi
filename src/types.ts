import type { ScannerConfig, ScannerId } from "./scanners/types.js";
import type { QualityGateConfig } from "./quality-gate.js";
import type { ConfidenceSignalWeights } from "./scoring/composite-confidence.js";

// Re-export Zod schemas for consumers that need runtime validation.
export {
  FindingSchema,
  TriageResultSchema,
  VerificationResultSchema,
  KuzushiConfigSchema,
  PocHarnessResultSchema,
  RepoContextSchema,
  EnrichedRepoContextSchema,
  ExploitChainSchema,
  PrecedentsSchema,
  SecurityProfileSchema,
  FindingRowSchema,
  VerdictSchema,
  EvidenceStepSchema,
  TriagePathAssessmentSchema,
  RawTriageOutputSchema,
  RawVerificationOutputSchema,
  RawPocHarnessOutputSchema,
  formatZodErrors,
  formatValidationErrorMessage,
} from "./schemas.js";

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

/** Configuration for triage quality assertion checks. */
export interface TriageAssertionConfig {
  /** Whether triage assertions are enabled. Default true (informational only). */
  enabled?: boolean;
  /** Custom weights for individual assertion checks. */
  weights?: {
    rationaleHasEvidence?: number;
    verificationStepsActionable?: number;
    confidenceMatchesEvidence?: number;
    noEmptyRationale?: number;
  };
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
  /** Git ref to diff against for differential review (e.g. "main", "HEAD~5"). */
  diffBase?: string;
  /** Injected summary of first-pass findings for agentic two-pass review mode. */
  agenticReviewContext?: string;
}

/** A single step in the fine-grained evidence chain produced during triage. */
export interface EvidenceStep {
  stepType: string;
  description: string;
  confidence: number;
  evidence: string;
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
  evidenceTrail?: Array<{ level: string; evidence: string }>;
  triageCostUsd?: number;
  /** Calibrated confidence computed from per-step evidence weights. */
  calibratedConfidence?: number;
  /** Per-step evidence chain for fine-grained confidence calibration. */
  evidenceChain?: EvidenceStep[];
}

/** Proof-level verdict for verification. */
export type ProofVerdict = "exploited" | "blocked_by_security" | "out_of_scope" | "false_positive";

/** Result of exploitability verification for a triaged finding. */
export interface VerificationResult {
  fingerprint: string;
  exploitable: boolean;
  pocPayload: string | null;
  pocDescription: string;
  attackVector: string | null;
  preconditions: string[];
  confidence: number;
  proofLevel?: 1 | 2 | 3 | 4;
  proofVerdict?: ProofVerdict;
  bypassAttempts?: string[];
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
  /** PoC execution results (populated when pocExecute is enabled). */
  pocExecExitCode?: number;
  pocExecStdout?: string;
  pocExecStderr?: string;
  pocExecVerdict?: "PASS" | "FAIL" | "ERROR" | "TIMEOUT";
  pocExecDurationMs?: number;
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

/** Extended repository context produced by the LLM context enricher. */
export interface EnrichedRepoContext {
  base: RepoContext;
  enrichment: {
    customMiddleware: Array<{ name: string; filePath: string; purpose: string; appliesTo?: string }>;
    customSanitizers: Array<{ name: string; filePath: string; sanitizationType: string; usedBy?: string }>;
    trustBoundaries: Array<{ name: string; description: string; entryPoints?: string[] }>;
    dataClassifications: Array<{ dataType: string; sensitivity: "public" | "internal" | "confidential" | "restricted"; locations?: string[] }>;
    architecturalNotes: string[];
  };
}

/** Parsed organization precedents for triage/verification prompt injection. */
export interface Precedents {
  hardExclusions: string[];
  signalCriteria: string[];
  architecturalPrecedents: string[];
}

/** A domain-specific security vulnerability category profile. */
export interface SecurityProfile {
  name: string;
  items: string[];
  appliesTo?: string[];
}

/** An exploitation chain linking multiple findings into a critical attack path. */
export interface ExploitChain {
  id: string;
  name: string;
  steps: Array<{
    findingFingerprint: string;
    role: string;
    description: string;
  }>;
  overallSeverity: "CRITICAL" | "HIGH" | "MEDIUM";
  preconditions: string[];
  impactDescription: string;
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
  /** Maximum findings per batch verification LLM call. */
  verifyBatchSize?: number;
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
  /** Optional JSON report output path. */
  jsonOutput?: string;
  /** Optional CSV report output path. */
  csvOutput?: string;
  /** Optional JSONL report output path. */
  jsonlOutput?: string;
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
  /** Enable pre-triage FP suppression filter. */
  fpFilterEnabled?: boolean;
  /** Additional regex patterns for FP suppression. */
  fpFilterCustomExclusions?: string[];
  /** Enable post-triage variant analysis. */
  variantAnalysis?: boolean;
  /** Optional override model for variant analysis. */
  variantAnalysisModel?: string;
  /** Max variant findings per confirmed TP. */
  variantAnalysisMaxFindings?: number;
  /** Enable LLM context enrichment task. */
  enableContextEnrichment?: boolean;
  /** Optional override model for context enrichment. */
  contextEnrichmentModel?: string;
  /** Git ref for differential review (e.g. "main"). */
  diffBase?: string;
  /** Enable two-stage LLM re-scoring after hard FP filter. */
  llmRescoreEnabled?: boolean;
  /** Model for LLM re-scoring (defaults to haiku for cost efficiency). */
  llmRescoreModel?: string;
  /** Minimum score (1-10) to keep a finding after LLM re-score. Default 4. */
  llmRescoreThreshold?: number;
  /** Enable post-triage exploitation chain analysis. Default false. */
  chainAnalysis?: boolean;
  /** Optional override model for chain analysis. */
  chainAnalysisModel?: string;
  /** Path to organization precedents file. */
  precedentsPath?: string;
  /** Path to security profiles file. */
  securityProfilesPath?: string;
  /** Sort findings by score descending before triage. Default true. */
  prioritizeFindings?: boolean;
  /** Maximum cost budget in USD. Pipeline stops early when exceeded. */
  costBudgetUsd?: number;
  /** Enable dynamic task selection based on repo context. Default false. */
  enableDynamicTaskSelection?: boolean;
  /** Enable PoC harness execution after generation. Default false. */
  pocExecute?: boolean;
  /** Sandbox backend for PoC execution. Default "docker". */
  pocSandbox?: "docker" | "process";
  /** Timeout for PoC execution in milliseconds. Default 30000. */
  pocExecTimeoutMs?: number;
  /** Enable fine-grained per-step confidence calibration. Default false. */
  confidenceCalibration?: boolean;
  /** Per-signal weights for multi-signal composite confidence scoring. */
  confidenceSignalWeights?: ConfidenceSignalWeights;
  /** Enable trajectory memory for cross-run learning. Default false. */
  trajectoryMemory?: boolean;
  /** Max exemplar trajectories injected into triage prompt. Default 2. */
  trajectoryMaxExemplars?: number;
  /** Triage strategy: single agent or multi-agent panel. Default "single". */
  triageStrategy?: "single" | "multi-agent";
  /** Model for multi-agent triage specialists. Defaults to triageModel. */
  triageSpecialistModel?: string;
  /** Max turns for each specialist sub-agent. null = unlimited. */
  triageSpecialistMaxTurns?: number | null;
  /** Configuration for triage quality assertion checks. Non-blocking, informational only. */
  triageAssertions?: TriageAssertionConfig;
  /** Quality gate configuration for CI/CD enforcement. */
  qualityGates?: QualityGateConfig;
  /** External task specifiers to load at runtime (file:// or package: URIs). */
  externalTasks?: string[];
  /** Enable loading of external tasks. Must be true for externalTasks to take effect. Default false. */
  enableExternalTasks?: boolean;
  /** Pipeline hooks configuration. */
  hooks?: { files?: string[] };
  /** Security opt-in required for loading external hook files. Default false. */
  enableExternalHooks?: boolean;
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
  compositeConfidence?: number | null;
  confidenceSignalsJson?: string | null;
  createdAt: string;
  updatedAt: string;
}
