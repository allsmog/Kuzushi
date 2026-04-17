import type { EvidenceAnchor } from "./agents/tasks/threat-modeling/types.js";
import type { DiscoveredModule } from "./discovery/types.js";
import type { QualityGateConfig } from "./quality-gate-types.js";
import type { ProofState, TaskConfig, TaskId } from "./scanners/types.js";
import type { ConfidenceSignalWeights } from "./scoring/composite-confidence.js";

export type { CryptoBehavioralRun } from "./crypto-behavioral/types.js";
// Re-export Zod schemas for consumers that need runtime validation.
export {
  ApplicationModelSchema,
  CryptoBehavioralRunSchema,
  CryptoBehavioralVerdictSchema,
  DynamicAnalysisRunSchema,
  DynamicAnalysisStatusSchema,
  DynamicCoverageModeSchema,
  EngineProvenanceSchema,
  EnrichedRepoContextSchema,
  EvidenceStepSchema,
  ExploitChainSchema,
  FindingMetadataSchema,
  FindingRowSchema,
  FindingSchema,
  formatValidationErrorMessage,
  formatZodErrors,
  KuzushiConfigSchema,
  PatchResultSchema,
  PatchStatusSchema,
  PocHarnessResultSchema,
  PrecedentsSchema,
  ProofStateSchema,
  RawPocHarnessOutputSchema,
  RawTriageOutputSchema,
  RawVerificationOutputSchema,
  RepoContextSchema,
  SecurityProfileSchema,
  TaintPathStepSchema,
  ThreatScenarioSchema,
  TriagePathAssessmentSchema,
  TriageResultSchema,
  VerdictSchema,
  VerificationResultSchema,
} from "./schemas.js";

/** Pluggable message bus backend. */
export type BusBackend = "in-process";

/** Scanner execution mode. */
export type ScanMode = "sequential" | "concurrent";

/** Runtime provider for agent execution. */
export type AgentRuntimeBackend = "claude" | "pi-ai";

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

/**
 * Verdict assigned by AI triage for scan findings.
 *
 * Part of the Kuzushi verdict taxonomy:
 * @see {@link ProofVerdict} — proof-level verdict from exploitability verification
 * @see CryptoBehavioralVerdict in `src/crypto-behavioral/types.ts` — behavioral test verdict for crypto findings
 */
export type Verdict = "tp" | "fp" | "needs_review" | "by_design";

export interface TriagePathAssessment {
  why: string;
  isFalsePositive: boolean;
  evidence: string;
}

export type { ScanOpts } from "./scan-opts.js";

/** A single step in the fine-grained evidence chain produced during triage. */
export interface EvidenceStep {
  stepType: string;
  description: string;
  confidence: number;
  evidence: string;
}

/** A structured code citation referencing a specific code location with context. */
export interface CodeCitation {
  filePath: string;
  startLine: number;
  endLine: number;
  snippet: string;
  description: string;
}

/** Structured attack-path analysis linking entry point to impact. */
export interface AttackPathAnalysis {
  /** Ordered chain of steps from entry to impact. */
  chain: string[];
  /** Narrative explanation of the attack path. */
  narrative: string;
  /** Reasoning for the assessed likelihood level. */
  likelihoodReasoning: string;
  /** Reasoning for the assessed impact level. */
  impactReasoning: string;
}

/** An identified security control or existing defense. */
export interface SecurityControl {
  name: string;
  description: string;
  filePath?: string;
}

/** Result of AI triage for a single finding. */
export interface TriageResult {
  fingerprint: string;
  /** Human-readable title for the finding (5-12 words). */
  title?: string;
  /** Alice-and-Bob style attack narrative describing who, what, and impact. */
  attackNarrative?: string;
  /** Assessed security severity: critical, high, medium, or low. */
  displaySeverity?: "critical" | "high" | "medium" | "low";
  verdict: Verdict;
  confidence: number;
  rationale: string;
  verificationSteps: string[];
  fixPatch: string | null;
  source?: TriagePathAssessment;
  sink?: TriagePathAssessment;
  /** The dangerous function/API that data flows into (e.g. 'eval', 'popen', 'SafeExecWithTimeout'). */
  sinkFunction?: string | null;
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
  /** Structured code citations with file paths, line ranges, and snippets. */
  codeCitations?: CodeCitation[];
  /** Attack-path analysis with chain diagram, narrative, and risk reasoning. */
  attackPath?: AttackPathAnalysis;
  /** Explicit assumptions underlying the triage assessment. */
  assumptions?: string[];
  /** Existing security controls and defenses identified during investigation. */
  controls?: SecurityControl[];
  /** Aspects the analysis could not verify or areas of uncertainty. */
  blindspots?: string[];
  /** Threat model threat IDs that this finding relates to (e.g. ["T-01", "T-03"]). */
  sourceThreatIds?: string[];
}

/**
 * Proof-level verdict for exploitability verification.
 *
 * Part of the Kuzushi verdict taxonomy:
 * @see {@link Verdict} — AI triage verdict for scan findings
 * @see CryptoBehavioralVerdict in `src/crypto-behavioral/types.ts` — behavioral test verdict for crypto findings
 */
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
  /** Structured code citations with file paths, line ranges, and snippets. */
  codeCitations?: CodeCitation[];
  /** Attack-path analysis with chain diagram, narrative, and risk reasoning. */
  attackPath?: AttackPathAnalysis;
  /** Explicit assumptions underlying the verification assessment. */
  assumptions?: string[];
  /** Existing security controls and defenses identified during verification. */
  controls?: SecurityControl[];
  /** Aspects the verification could not confirm or areas of uncertainty. */
  blindspots?: string[];
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
  | "VERIFIED"
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
  blame?: { sha: string; author: string; date: string; summary: string };
  introducedIn?: string;
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
    customMiddleware: Array<{
      name: string;
      filePath: string;
      purpose: string;
      appliesTo?: string;
    }>;
    customSanitizers: Array<{
      name: string;
      filePath: string;
      sanitizationType: string;
      usedBy?: string;
    }>;
    trustBoundaries: Array<{ name: string; description: string; entryPoints?: string[] }>;
    dataClassifications: Array<{
      dataType: string;
      sensitivity: "public" | "internal" | "confidential" | "restricted";
      locations?: string[];
    }>;
    architecturalNotes: string[];
  };
}

/**
 * Evidence anchor tying a model element to a source location.
 *
 * This is a backward-compatible alias for the canonical {@link EvidenceAnchor}
 * defined in `src/agents/tasks/threat-modeling/types.ts`. New code should
 * prefer importing `EvidenceAnchor` directly from the threat-modeling module.
 */
export type ModelEvidenceAnchor = EvidenceAnchor;

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
  | "race-condition-detect"
  | "command-injection-detect"
  | "xxe-detect"
  | "deserialization-detect"
  | "sharp-edges-detect";

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
  /** Default model identifier for AI tasks and stages (e.g. "anthropic:claude-sonnet-4-6"). */
  model: string;
  /** Enable post-triage exploitability verification phase. */
  verify?: boolean;
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
  /** Enable LLM-based verification gate (cheap Haiku call to decide verify/auto-accept/skip). */
  verifyGateEnabled?: boolean;
  /** Enable post-verification PoC harness generation phase. */
  pocHarness?: boolean;
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
  /**
   * When a triage response is tp/needs_review but lacks sufficient evidence
   * (< 2 citations referencing real files, or a tp without a 2+ step attack
   * path), re-invoke triage once with a reinforcement prompt that tells the
   * agent what was missing and instructs it to use semantic navigation tools.
   * If the second response is still insufficient, the verdict is downgraded
   * to needs_review with the gaps recorded in blindspots[]. Defaults to true.
   */
  enforceTriageEvidence?: boolean;
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
  /** Enabled task IDs, in execution order. */
  tasks: TaskId[];
  /** Default severity filter. */
  severity: string[];
  /** Default exclude patterns for task runners such as Semgrep. */
  excludePatterns: string[];
  /** Task-specific config blocks keyed by task id or task family id. */
  taskConfig: Record<string, TaskConfig>;
  /** Enable pre-triage FP suppression filter. */
  fpFilterEnabled?: boolean;
  /** Additional regex patterns for FP suppression. */
  fpFilterCustomExclusions?: string[];
  /** Enable pre-triage design-decision auto-classifier (by_design verdict). Default true. */
  designDecisionClassifier?: boolean;
  /** Enable post-triage variant analysis. */
  variantAnalysis?: boolean;
  /** Max variant findings per confirmed TP. */
  variantAnalysisMaxFindings?: number;
  /** Enable post-verification sweep of codebase with generated custom rules. */
  variantRuleSweepEnabled?: boolean;
  /** Enable LLM context enrichment task. */
  enableContextEnrichment?: boolean;
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
  /** Enable LLM-powered code graph construction and enrichment. Default false. */
  codeGraphEnabled?: boolean;
  /** Multi-strategy analysis mode. Default "off". */
  multiStrategyMode?: "off" | "adaptive" | "full";
  /** Budget per finding across all strategies in USD. Default 2.0. */
  multiStrategyBudgetUsd?: number;
  /** Budget per individual strategy in USD. Default 0.50. */
  multiStrategyPerStrategyBudgetUsd?: number;
  /** Per-strategy timeout in milliseconds. Default 60000. */
  multiStrategyTimeoutMs?: number;
  /** Enable auto-rule generation from confirmed multi-strategy findings. Default false. */
  multiStrategyAutoRuleGeneration?: boolean;
  /** Rescan codebase with generated rules for variant detection. Default false. */
  multiStrategyRescanWithRules?: boolean;
  /** Generate Semgrep rules from verified exploitable findings and persist to .kuzushi/custom-rules/. Default false. */
  autoRuleGeneration?: boolean;
  /** Enable targeted dynamic analysis tasks. Default false. */
  dynamicAnalysisEnabled?: boolean;
  /** Enable crypto behavioral runtime confirmation after secrets-crypto detection. Default false. */
  cryptoBehavioralTestEnabled?: boolean;
  /** Timeout for crypto behavioral harness execution in milliseconds. Default 120000. */
  cryptoBehavioralTimeoutMs?: number;
  /** Max number of crypto findings routed into the crypto behavioral task. Default 10. */
  cryptoBehavioralMaxFindings?: number;
  /** Max LLM spend allowed per crypto behavioral finding before stopping later findings. Default 1. */
  cryptoBehavioralPerFindingBudgetUsd?: number;
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
  /** Enable automatic patch generation in pipeline. Default false. */
  autoPatchEnabled?: boolean;
  /** Trigger threshold for auto-patch: patch after verify, poc, or triage. Default "verify". */
  autoPatchAfter?: "verify" | "poc" | "triage";
  /** Depth of re-verification after patching. Default "scanner". */
  patchVerifyDepth?: "task" | "triage" | "full";
  /** Max concurrent patch synthesis tasks. Default 2. */
  patchConcurrency?: number;
  /** Enable two-stage LLM re-scoring after hard FP filter. */
  llmRescoreEnabled?: boolean;
  /** Minimum score (1-10) to keep a finding after LLM re-score. Default 4. */
  llmRescoreThreshold?: number;
  /** Enable post-triage exploitation chain analysis. Default false. */
  chainAnalysis?: boolean;
  /** Path to organization precedents file. */
  precedentsPath?: string;
  /** Path to security profiles file. */
  securityProfilesPath?: string;
  /** Sort findings by score descending before triage. Default true. */
  prioritizeFindings?: boolean;
  /** Maximum cost budget in USD. Pipeline stops early when exceeded. */
  costBudgetUsd?: number;
  /** Maximum findings to enter LLM triage. Top-scored findings are prioritized. Default 50. */
  triageMaxFindings?: number;
  /** Minimum score (0-100) a finding must have to enter the triage queue. Findings below this threshold are dropped before any LLM call. Default: 0 (disabled). */
  triageMinScore?: number;
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
  /** Enable incremental scanner result caching across runs. Default true. */
  incrementalCache?: boolean;
  /** Include importers of changed files in incremental rescan scope. Default true. */
  incrementalDepTracking?: boolean;
  /** Days before scanner cache entries expire. Default 30. */
  incrementalCacheTtlDays?: number;
  /** Enable SSE streaming server for live pipeline events. Default false. */
  streamingEnabled?: boolean;
  /** Port for the SSE streaming server. Default 0 (auto-assign). */
  streamingPort?: number;
  /** Skip triage for high-confidence agentic findings (score >= 7, confidence HIGH). Default false. */
  skipTriageForHighConfidenceAgentic?: boolean;
  /** Monorepo module discovery and manual module overrides. */
  monorepo?: {
    /** Monorepo handling mode. "off" disables auto-discovery for this project. */
    mode?: "auto" | "off";
    /** Manual module list. When set, skips LLM discovery. */
    modules?: DiscoveredModule[];
    /** Module names to exclude from discovery or scanning. */
    excludeModules?: string[];
    /** Override model used for module discovery. */
    discoveryModel?: string;
    /** Max number of modules emitted by discovery. Default 30. */
    maxModules?: number;
    /** Total budget for the entire monorepo scan. Falls back to costBudgetUsd. */
    budgetUsd?: number;
    /** Reserve percentage of budget for cross-module analysis. Default 0.10. */
    crossModuleReserve?: number;
    /** Enable cross-module data flow tracing. Default true. */
    crossModuleTracing?: boolean;
    /** Enable architectural threat model. Default true. */
    architecturalThreatModel?: boolean;
  };
}

// ── Operator Scan Context (Intake UI) ──

/** Trust-level annotation for external dependencies. */
export type TrustLevel = "trusted" | "semi-trusted" | "untrusted" | "unknown";

/** Sensitivity classification for data tags. */
export type DataSensitivity = "public" | "internal" | "confidential" | "restricted";

/** Review status of an individual context item during operator intake. */
export type IntakeItemStatus = "accepted" | "edited" | "deleted" | "skipped" | "added";

/** A single item in the operator context, with review tracking. */
export interface OperatorContextItem<T = string> {
  value: T;
  status: IntakeItemStatus;
  /** Original auto-generated value before operator edits. */
  original?: T;
  /** Free-text note from operator. */
  note?: string;
}

/** Trust context: deployment, infrastructure, external defenses, confirmed mitigations. */
export interface TrustContext {
  deploymentModel: OperatorContextItem[];
  infrastructure: OperatorContextItem[];
  externalDefenses: OperatorContextItem[];
  confirmedMitigations: OperatorContextItem[];
}

/** Scope prioritization: high/low value paths, sensitive data tags. */
export interface ScopePrioritization {
  highValuePaths: OperatorContextItem[];
  lowValuePaths: OperatorContextItem[];
  sensitiveDataTags: OperatorContextItem<{
    dataType: string;
    sensitivity: DataSensitivity;
    locations: string[];
  }>[];
}

/** Architecture context: entry points, external deps with trust levels, data flows. */
export interface ArchitectureContext {
  entryPoints: OperatorContextItem<{
    kind: string;
    path: string;
    method?: string;
    description?: string;
  }>[];
  externalDeps: OperatorContextItem<{
    name: string;
    kind: string;
    trustLevel: TrustLevel;
    description?: string;
  }>[];
  dataFlows: OperatorContextItem<{
    from: string;
    to: string;
    dataClassification?: string;
    description?: string;
  }>[];
}

/** Historical feedback: suppressed FP and confirmed TP fingerprints from prior runs. */
export interface HistoricalFeedback {
  suppressedFpFingerprints: OperatorContextItem<{
    fingerprint: string;
    ruleId: string;
    reason?: string;
  }>[];
  confirmedTpFingerprints: OperatorContextItem<{
    fingerprint: string;
    ruleId: string;
    description?: string;
  }>[];
}

/** Operator-reviewed scan context persisted to .kuzushi/scan-context.json. */
export interface OperatorScanContext {
  version: string;
  trust: TrustContext;
  scope: ScopePrioritization;
  architecture: ArchitectureContext;
  historical: HistoricalFeedback;
  /** Whether this context has been reviewed by a human. */
  operatorReviewed: boolean;
  /** ISO timestamp of last operator review. */
  lastReviewedAt?: string;
  /** ISO timestamp of auto-generation. */
  generatedAt: string;
}

/** A persisted finding row from SQLite. */
export interface FindingRow {
  taskId: TaskId;
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
