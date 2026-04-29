import type Database from "better-sqlite3";
import type { AgentRuntime } from "../../agent-runtime/types.js";
import type { PipelineHookChain } from "../../hooks/chain.js";
import type { DagRegistry } from "../../modules/dag-registry.js";
import type { Precedents } from "../../precedents.js";
import type { Finding } from "../../scanners/types.js";
import type { StageTimestamps } from "../../scoring/run-metrics.js";
import type { GeneratedRule } from "../../strategies/types.js";
import type {
  EnrichedRepoContext,
  ExploitChain,
  KuzushiConfig,
  PocHarnessResult,
  RepoContext,
  ScanOpts,
  TriageResult,
  Verdict,
  VerificationResult,
} from "../../types.js";
import type { RunContext } from "../events.js";
import type { ScanFindingsStore } from "./scan-findings-store.js";

export interface QueuedFinding {
  finding: Finding;
  index: number;
  total: number;
}

export interface VerificationCandidate {
  finding: Finding;
  triageResult: TriageResult;
}

export interface QueuedVerification extends VerificationCandidate {
  index: number;
  total: number;
}

export interface PocHarnessCandidate extends VerificationCandidate {
  verificationResult: VerificationResult;
}

export interface QueuedPocHarness extends PocHarnessCandidate {
  index: number;
  total: number;
}

export interface DynamicAnalysisCandidate {
  finding: Finding;
  triageResult: TriageResult;
  verificationResult?: VerificationResult;
  pocHarnessResult?: PocHarnessResult;
  score: number;
  proofValue: number;
}

export interface QueuedDynamicAnalysis extends DynamicAnalysisCandidate {
  index: number;
  total: number;
}

export interface RunState {
  context: RunContext;
  checkpointRunId: string;
  resuming: boolean;
  config: KuzushiConfig;
  scanOpts: ScanOpts;
  /** Latched once we hit `maxRawFindings` so we only warn once per run. */
  maxRawFindingsWarned?: boolean;
  tasks: string[];
  startedAt: string;
  /**
   * Memory-bounded buffer over scan findings. Defaults to
   * {@link import("./scan-findings-store.js").InMemoryScanFindingsStore},
   * with a SQLite-backed implementation available for very large monorepo
   * scans (gated by `KuzushiConfig.scanFindingsBackend`).
   *
   * Migrated from `Finding[]` in #33 — see `scan-findings-store.ts`.
   */
  scanFindings: ScanFindingsStore;
  totalFindings: number;
  skippedAlreadyTriaged: number;
  skippedLowConfidence: number;
  skippedByFpFilter: number;
  skippedByScoreFilter: number;
  autoClassifiedByDesign: number;
  verifyGateAutoAccepted: number;
  verifyGateSkipped: number;
  verifyGateCostUsd: number;
  /** Sink patterns verified as exploitable — key: `CWE:sinkFunction`, value: first fingerprint. */
  verifiedPatterns: Map<string, string>;
  triageQueue: QueuedFinding[];
  queueCursor: number;
  triageTotal: number;
  inFlight: number;
  triaged: number;
  triageErrors: number;
  totalCostUsd: number;
  verifyEnabled: boolean;
  verifyVerdicts: Set<Verdict>;
  verifyCandidates: VerificationCandidate[];
  verifyQueue: QueuedVerification[];
  verifyCursor: number;
  verifyTotal: number;
  verifyInFlight: number;
  verified: number;
  verifyErrors: number;
  verifyCostUsd: number;
  verifyDispatching: boolean;
  verifyDispatchedFingerprints: Set<string>;
  verificationStarted: boolean;
  verificationCompleted: boolean;
  resumingVerification: boolean;
  pocHarnessEnabled: boolean;
  pocHarnessCandidates: PocHarnessCandidate[];
  pocHarnessQueue: QueuedPocHarness[];
  pocHarnessCursor: number;
  pocHarnessTotal: number;
  pocHarnessInFlight: number;
  pocHarnessGenerated: number;
  pocHarnessSkipped: number;
  pocHarnessErrors: number;
  pocHarnessCostUsd: number;
  pocHarnessDispatching: boolean;
  pocHarnessStarted: boolean;
  reportRequested: boolean;
  reportEmitted: boolean;
  refinementEnabled: boolean;
  refinementDeltaOnly: boolean;
  refinementIterations: number;
  refinementIteration: number;
  refinementInFlight: boolean;
  dispatching: boolean;
  collectScanFindingEvents: boolean;
  repoContext?: RepoContext;
  enrichedRepoContext?: EnrichedRepoContext["enrichment"];
  precedents?: Precedents;
  taskOutputs: Map<string, unknown>;
  failedTasks: string[];
  skippedByLlmRescore: number;
  softSuppressedFindings: number;
  corroboratedClusters: number;
  variantAnalysisCompleted: boolean;
  variantFindings: number;
  variantAnalysisCostUsd: number;
  exploitChains: ExploitChain[];
  chainAnalysisCostUsd: number;
  budgetExceeded: boolean;
  budgetWarningEmitted: boolean;
  stageTimestamps: StageTimestamps;
  hookChain?: PipelineHookChain;
  deadLetterFindings: Array<{
    fingerprint: string;
    error: string;
    attempts: number;
    lastAttempt: string;
  }>;
  triageAttempts: Map<string, number>;
  verifyAttempts: Map<string, number>;
  dynamicAnalysisEnabled: boolean;
  dynamicCandidates: DynamicAnalysisCandidate[];
  dynamicQueue: QueuedDynamicAnalysis[];
  dynamicCursor: number;
  dynamicTotal: number;
  dynamicInFlight: number;
  dynamicConfirmed: number;
  dynamicInteresting: number;
  dynamicRejected: number;
  dynamicErrors: number;
  dynamicCostUsd: number;
  dynamicDispatching: boolean;
  dynamicStarted: boolean;
  dynamicCompleted: boolean;
  dynamicAttempts: Map<string, number>;
  autoPatchEnabled: boolean;
  patchCandidates: Set<string>;
  patchQueue: string[];
  patchCursor: number;
  patchInFlight: number;
  patchCompleted: number;
  patchVerified: number;
  patchFailed: number;
  patchCostUsd: number;
  patchErrors: number;
  patchDispatching: boolean;
  patchStarted: boolean;
  generatedRules: GeneratedRule[];
  /** Tracks fingerprints already queued for rule generation to prevent duplicates. */
  generatingRuleFingerprints?: Set<string>;
  ruleSweepCompleted: boolean;
  ruleSweepFindings: number;
  /** Formatted operator context string for prompt injection. */
  operatorContext?: string;
}

export interface OrchestratorDeps {
  dagRegistry: DagRegistry;
  db: Database.Database;
  runtime: AgentRuntime;
}
