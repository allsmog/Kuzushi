import type { ScannerConfig, ScannerId } from "./scanners/types.js";
import type { EngineProvenance, ProofState, TaintPathStep } from "./scanners/types.js";
import type { QualityGateConfig } from "./quality-gate.js";
import type { ConfidenceSignalWeights } from "./scoring/composite-confidence.js";

// Re-export Zod schemas for consumers that need runtime validation.
export {
  TaintPathStepSchema,
  EngineProvenanceSchema,
  ProofStateSchema,
  DynamicAnalysisStatusSchema,
  DynamicCoverageModeSchema,
  DynamicAnalysisRunSchema,
  PatchStatusSchema,
  PatchResultSchema,
  FindingMetadataSchema,
  FindingSchema,
  TriageResultSchema,
  VerificationResultSchema,
  KuzushiConfigSchema,
  PocHarnessResultSchema,
  RepoContextSchema,
  EnrichedRepoContextSchema,
  ApplicationModelSchema,
  ThreatScenarioSchema,
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
    cweMentionsRelevant?: number;
    fixPatchValid?: number;
    severityVerdictAlignment?: number;
    verdictConsistency?: number;
    costEfficiency?: number;
    latencyReasonable?: number;
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
  /** Composite confidence blending scanner and triage signals. */
  compositeConfidence?: number;
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
  /** Composite confidence combining multiple signals (self-reported, calibrated, verification). */
  compositeConfidence?: number;
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
  iterations?: number;
  refinementHistory?: Array<{
    attempt: number;
    error: string;
    approach: string;
  }>;
}

export type DynamicAnalysisStatus = "confirmed" | "interesting" | "rejected" | "error";

export type DynamicCoverageMode = "none" | "node-v8" | "python-coverage";

export interface DynamicAnalysisRun {
  dynamicRunId: string;
  pipelineRunId?: string;
  fingerprint: string;
  repo: string;
  status: DynamicAnalysisStatus;
  score: number;
  proofValue: number;
  language?: string;
  harnessPath?: string | null;
  harnessLanguage?: string | null;
  seedInputs?: string[];
  coverageMode?: DynamicCoverageMode;
  coverageSummary?: string;
  executionExitCode?: number | null;
  executionStdout?: string;
  executionStderr?: string;
  executionVerdict?: "PASS" | "FAIL" | "ERROR" | "TIMEOUT";
  executionDurationMs?: number | null;
  iterations: number;
  costUsd?: number;
  metadata?: Record<string, unknown>;
  createdAt?: string;
  updatedAt?: string;
}

export type PatchStatus =
  | "APPLY_FAILED"
  | "BUILD_FAILED"
  | "STILL_VULNERABLE"
  | "TESTS_FAILED"
  | "SOUND"
  | "UNKNOWN";

export interface PatchResult {
  patchRunId: string;
  fingerprint: string;
  repo: string;
  diff: string | null;
  status: PatchStatus;
  iterations: number;
  buildCommand?: string | null;
  testCommand?: string | null;
  worktreePath?: string | null;
  costUsd?: number;
  validatorLog?: string;
  history: Array<{
    attempt: number;
    diff: string;
    status: PatchStatus;
    output: string;
  }>;
  createdAt?: string;
  updatedAt?: string;
}

export interface FindingMetadata {
  latestDynamicRunId?: string;
  dynamicRunIds?: string[];
  latestPatchRunId?: string;
  patchRunIds?: string[];
  latestDynamicStatus?: DynamicAnalysisStatus;
  notes?: string[];
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

export interface ModelEvidenceAnchor {
  filePath: string;
  startLine: number;
  description: string;
}

export interface ApplicationRoute {
  id: string;
  method: string;
  path: string;
  filePath: string;
  startLine: number;
  framework?: string;
  handlerSymbol?: string;
  middleware: string[];
  authMechanisms: string[];
}

export interface ApplicationOutboundClient {
  id: string;
  kind: string;
  filePath: string;
  startLine: number;
  symbol?: string;
  targetHint?: string;
  protocol?: string;
}

export interface ApplicationDataStore {
  id: string;
  kind: string;
  name: string;
  filePath: string;
  startLine: number;
}

export interface ApplicationBackgroundJob {
  id: string;
  name: string;
  filePath: string;
  startLine: number;
  queue?: string;
  handlerSymbol?: string;
}

export interface ApplicationServiceBoundary {
  id: string;
  name: string;
  kind: "entrypoint" | "outbound" | "queue" | "datastore" | "trust-zone";
  description: string;
  evidenceAnchors: ModelEvidenceAnchor[];
}

export interface ApplicationModel {
  version: string;
  routes: ApplicationRoute[];
  outboundClients: ApplicationOutboundClient[];
  dataStores: ApplicationDataStore[];
  backgroundJobs: ApplicationBackgroundJob[];
  serviceBoundaries: ApplicationServiceBoundary[];
  relevantFiles: string[];
  notes: string[];
}

export type ThreatScenarioDetectorId =
  | "code-config-detect"
  | "dangerous-api-detect"
  | "auth-access-detect"
  | "security-misconfig-detect"
  | "ssrf-detect"
  | "nosql-injection-detect"
  | "prototype-pollution-detect"
  | "template-injection-detect"
  | "graphql-security-detect"
  | "race-condition-detect";

export interface ThreatScenario {
  id: string;
  detectorId: ThreatScenarioDetectorId;
  title: string;
  rationale: string;
  attackSurface: string;
  expectedGuard?: string;
  relatedFiles: string[];
  relatedSymbols: string[];
  sourceThreatIds: string[];
  cwe: string[];
  entryPoint?: {
    kind: string;
    filePath: string;
    startLine: number;
    method?: string;
    path?: string;
    handlerSymbol?: string;
  };
  sink?: {
    kind: string;
    filePath: string;
    startLine: number;
    symbol?: string;
    detail?: string;
  };
  evidenceAnchors: ModelEvidenceAnchor[];
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

/** A file entry in the pre-computed file index. */
export interface FileIndexEntry {
  path: string; // relative to repo root
}

/** A security-relevant pattern match found during file indexing. */
export interface SecurityPatternMatch {
  pattern: string;
  filePath: string;
  lineNumber: number;
  lineContent: string;
}

/** Pre-computed file tree and security pattern matches from context-gatherer. */
export interface FileIndex {
  tree: FileIndexEntry[];
  totalFiles: number;
  truncated: boolean;
  patternMatches: Record<string, SecurityPatternMatch[]>;
}

/** User configuration stored at ~/.kuzushi/config.json (and optional project override). */
export interface KuzushiConfig {
  /** Scanner model identifier (e.g. "anthropic:claude-sonnet-4-6"). */
  model: string;
  /** Optional override model for triage agents. */
  triageModel?: string;
  /** Optional override model for batch triage (classification). Defaults to Haiku. */
  triageBatchModel?: string;
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
  /** Enable the cheap pre-triage classifier stage. Default false. */
  enableClassifier?: boolean;
  /** Model for the cheap pre-triage classifier. Defaults to the cheapest configured model path. */
  classifierModel?: string;
  /** Minimum classifier confidence required to keep a finding. Default 0.5. */
  classifierThreshold?: number;
  /** Optional ensemble models for eligible agentic scan tasks. */
  ensembleModels?: string[];
  /** Git ref for differential review (e.g. "main"). */
  diffBase?: string;
  /** Optional Git ref for taint-analysis-specific differential slicing. */
  taintDiffBase?: string;
  /** Differential taint behavior when taintDiffBase is set. */
  taintDiffMode?: "delta" | "baseline";
  /** Enable deterministic grounding for taint supplements and rendering hints. Default true. */
  taintGroundingEnabled?: boolean;
  /** Enable the cheap structural index support layer. Default false. */
  astIndexEnabled?: boolean;
  /** Enable call-graph assist enrichment for high-value findings. Default false. */
  callGraphAssistEnabled?: boolean;
  /** Enable targeted dynamic analysis tasks. Default false. */
  dynamicAnalysisEnabled?: boolean;
  /** Enable coverage-guided refinement inside the dynamic lane. Default false. */
  coverageGuidedEnabled?: boolean;
  /** Max refinement iterations for dynamic analysis tasks. Default 3. */
  dynamicMaxIterations?: number;
  /** Max number of findings routed into the dynamic lane. Default 20. */
  dynamicMaxCandidates?: number;
  /** Minimum ranking score for dynamic analysis candidates. Default 7. */
  dynamicMinScore?: number;
  /** Per-finding dynamic analysis budget in USD. Default 2. */
  dynamicPerFindingBudgetUsd?: number;
  /** Enable patch synthesis and validation pipeline. Default false. */
  patchingEnabled?: boolean;
  /** Max patch synthesis iterations. Default 3. */
  patchMaxIterations?: number;
  /** Optional override build command for manual patch validation. */
  patchBuildCommand?: string;
  /** Optional override test command for manual patch validation. */
  patchTestCommand?: string;
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
  /** Max turns for agentic task executions in the DAG. Default 15. */
  taskMaxTurns?: number;
  /** Enable dynamic task selection based on repo context. Default false. */
  enableDynamicTaskSelection?: boolean;
  /** Enable PoC harness execution after generation. Default false. */
  pocExecute?: boolean;
  /** Sandbox backend for PoC execution. Default "docker". */
  pocSandbox?: "docker" | "process";
  /** Timeout for PoC execution in milliseconds. Default 30000. */
  pocExecTimeoutMs?: number;
  /** Max PoC refinement iterations when execution feedback is enabled. Default 3. */
  pocRefinementMaxIterations?: number;
  /** Inject PoC reflection guidance every N failed attempts. Default 2. */
  pocReflectionInterval?: number;
  /** Max verification refinement iterations when execution feedback is enabled. Default 3. */
  verifyRefinementMaxIterations?: number;
  /** Inject verification reflection guidance every N failed attempts. Default 2. */
  verifyReflectionInterval?: number;
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
  /** Path to custom triage prompt template file. */
  triagePromptFile?: string;
  /** Path to custom verify prompt template file. */
  verifyPromptFile?: string;
  /** Command to spawn the ACP adapter process. */
  acpAdapterCommand?: string;
  /** Enable multi-turn session persistence for ACP. */
  acpSessionPersist?: boolean;
  /** Bootstrap files injected into system prompts. */
  bootstrapFiles?: {
    files?: string[];
    maxCharsPerFile?: number;
    totalMaxChars?: number;
  };
  /** Tool policy overrides keyed by policy name. */
  toolPolicies?: Record<string, { allow?: string[]; deny?: string[] }>;
  /** Model fallback chains: maps primary model to ordered list of fallback models. */
  modelFallbacks?: Record<string, string[]>;
  /** Cooldown duration (ms) before retrying a failed model. Default 60000. */
  modelFallbackCooldownMs?: number;
  /** Enable incremental scanner result caching across runs. Default false. */
  incrementalCache?: boolean;
  /** Skip triage for high-confidence agentic findings (score >= 7, confidence HIGH). Default false. */
  skipTriageForHighConfidenceAgentic?: boolean;
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
  pocRunExitCode?: number | null;
  pocRunStdout?: string | null;
  pocRunStderr?: string | null;
  pocRunVerdict?: "PASS" | "FAIL" | "ERROR" | "TIMEOUT" | null;
  pocRunDurationMs?: number | null;
  compositeConfidence?: number | null;
  confidenceSignalsJson?: string | null;
  taintPathJson?: string | null;
  proofState?: ProofState | null;
  engineProvenanceJson?: string | null;
  createdAt: string;
  updatedAt: string;
}
