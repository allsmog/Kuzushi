import type { Finding, ScannerId } from "../scanners/types.js";
import type { TaskOutputKind } from "../agents/types.js";
import type {
  DynamicAnalysisRun,
  EnrichedRepoContext,
  ExploitChain,
  KuzushiConfig,
  PatchStatus,
  PocHarnessResult,
  ScanOpts,
  TriageResult,
  VerificationResult,
  Verdict,
} from "../types.js";
import type { QualityGateResult } from "../quality-gate.js";
import type { RunMetrics } from "../scoring/run-metrics.js";
import type { EventEnvelope } from "./types.js";
import type { ErrorCategory } from "../errors.js";
import type { GeneratedRule } from "../strategies/types.js";

export interface RunContext {
  runId: string;
  repoRoot: string;
  scanPath?: string;
  repoName: string;
  dbPath: string;
  reportMode?: "full" | "suppress";
}

export interface PipelineStats {
  scanners: ScannerId[];
  totalFindings: number;
  queuedForTriage: number;
  skippedAlreadyTriaged: number;
  skippedLowConfidence?: number;
  skippedByFpFilter?: number;
  softSuppressedFindings?: number;
  skippedByLlmRescore?: number;
  corroboratedClusters?: number;
  triaged: number;
  triageErrors: number;
  totalCostUsd?: number;
  verified?: number;
  verifyErrors?: number;
  verifyCostUsd?: number;
  pocHarnessGenerated?: number;
  pocHarnessSkipped?: number;
  pocHarnessErrors?: number;
  pocHarnessCostUsd?: number;
  variantFindings?: number;
  variantAnalysisCostUsd?: number;
  ruleSweepFindings?: number;
  chainCount?: number;
  chainAnalysisCostUsd?: number;
  dynamicConfirmed?: number;
  dynamicInteresting?: number;
  dynamicRejected?: number;
  dynamicErrors?: number;
  dynamicCostUsd?: number;
  incrementalCachedFiles?: number;
  incrementalRescannedFiles?: number;
  incrementalDepExpandedFiles?: number;
  patchGenerated?: number;
  patchVerified?: number;
  patchFailed?: number;
  patchCostUsd?: number;
  patchErrors?: number;
  budgetExceeded?: boolean;
  failedTasks?: string[];
  deadLetterCount?: number;
  extractionDegradation?: { status: string; reasons: string[] };
  stitchDegradation?: { type: string; reason: string; message: string };
  tiPriorDegraded?: boolean;
  qualityGateResult?: QualityGateResult;
  runMetrics?: RunMetrics;
  startedAt: string;
  completedAt: string;
}

export type PipelineStartEvent = EventEnvelope<
  "pipeline:start",
  {
    context: RunContext;
    config: KuzushiConfig;
    scanOpts: ScanOpts;
    resumeRunId?: string;
  }
>;

export type PipelineCompleteEvent = EventEnvelope<
  "pipeline:complete",
  {
    context: RunContext;
    stats: PipelineStats;
  }
>;

export type PipelineErrorEvent = EventEnvelope<
  "pipeline:error",
  {
    context: RunContext;
    error: string;
    fatal: boolean;
    errorCategory?: ErrorCategory;
  }
>;

export type BusHandlerErrorEvent = EventEnvelope<
  "bus:handler-error",
  {
    sourceEventType: string;
    sourceEventId?: string;
    error: string;
  }
>;

export type TaskStartEvent = EventEnvelope<
  "task:start",
  {
    context: RunContext;
    taskId: string;
    outputKind: TaskOutputKind;
    input: unknown;
    upstreamOutputs: Map<string, unknown>;
  }
>;

export type TaskProgressEvent = EventEnvelope<
  "task:progress",
  {
    context: RunContext;
    taskId: string;
    outputKind: TaskOutputKind;
    progress: unknown;
  }
>;

export type TaskCompleteEvent = EventEnvelope<
  "task:complete",
  {
    context: RunContext;
    taskId: string;
    outputKind: TaskOutputKind;
    output: unknown;
    durationMs: number;
    costUsd?: number;
  }
>;

export type TaskErrorEvent = EventEnvelope<
  "task:error",
  {
    context: RunContext;
    taskId: string;
    outputKind: TaskOutputKind;
    error: string;
    errorCategory?: ErrorCategory;
  }
>;

export type TaskSkippedEvent = EventEnvelope<
  "task:skipped",
  {
    context: RunContext;
    taskId: string;
    reason: string;
  }
>;

export type StageCompleteEvent = EventEnvelope<
  "stage:complete",
  {
    context: RunContext;
    stageIndex: number;
    taskIds: string[];
  }
>;

export type ScanStartEvent = EventEnvelope<
  "scan:start",
  {
    context: RunContext;
    scanners: ScannerId[];
    scanOpts: ScanOpts;
  }
>;

export type ScanFindingEvent = EventEnvelope<
  "scan:finding",
  {
    context: RunContext;
    finding: Finding;
    scannerId: ScannerId;
  }
>;

export type ScanScannerCompleteEvent = EventEnvelope<
  "scan:scanner-complete",
  {
    context: RunContext;
    scannerId: ScannerId;
    findingCount: number;
    durationMs: number;
  }
>;

export type ScanCompleteEvent = EventEnvelope<
  "scan:complete",
  {
    context: RunContext;
    totalFindings: number;
  }
>;

export type TriageStartEvent = EventEnvelope<
  "triage:start",
  {
    context: RunContext;
    findingCount: number;
    model: string;
    skippedAlreadyTriaged?: number;
  }
>;

export type TriageFindingQueuedEvent = EventEnvelope<
  "triage:finding-queued",
  {
    context: RunContext;
    finding: Finding;
    repoContext?: unknown;
    enrichedContext?: EnrichedRepoContext["enrichment"];
    precedents?: unknown;
    threatModelSummary?: string;
    index: number;
    total: number;
  }
>;

export type TriageBatchQueuedEvent = EventEnvelope<
  "triage:batch-queued",
  {
    context: RunContext;
    findings: Finding[];
    repoContext?: unknown;
    enrichedContext?: EnrichedRepoContext["enrichment"];
    precedents?: unknown;
    threatModelSummary?: string;
    total: number;
  }
>;

export type TriageResultEvent = EventEnvelope<
  "triage:result",
  {
    context: RunContext;
    finding: Finding;
    result: TriageResult;
    costUsd?: number;
    attempts?: number;
    index: number;
    total: number;
  }
>;

export type TriageErrorEvent = EventEnvelope<
  "triage:error",
  {
    context: RunContext;
    finding: Finding;
    error: string;
    costUsd?: number;
    attempts?: number;
    index: number;
    total: number;
    errorCategory?: ErrorCategory;
  }
>;

export type TriageAgentActivityEvent = EventEnvelope<
  "triage:agent-activity",
  {
    context: RunContext;
    fingerprint: string;
    kind: "tool-start" | "tool-progress" | "tool-complete" | "reasoning";
    toolName?: string;
    toolInput?: Record<string, unknown>;
    summary?: string;
    elapsedSeconds?: number;
    index: number;
    total: number;
  }
>;

export type TriageAssertionsEvent = EventEnvelope<
  "triage:assertions",
  {
    context: RunContext;
    fingerprint: string;
    assertions: Array<{ name: string; passed: boolean; score: number; weight: number; reason: string }>;
    qualityScore: number;
  }
>;

export type TriageCompleteEvent = EventEnvelope<
  "triage:complete",
  {
    context: RunContext;
    triaged: number;
    errors: number;
    totalCostUsd?: number;
  }
>;

export type TriageQueueDepthEvent = EventEnvelope<
  "triage:queue-depth",
  {
    context: RunContext;
    queued: number;
    inFlight: number;
    processed: number;
    total: number;
  }
>;

export type VerificationStartEvent = EventEnvelope<
  "verification:start",
  {
    context: RunContext;
    findingCount: number;
    model: string;
  }
>;

export type VerificationFindingQueuedEvent = EventEnvelope<
  "verification:finding-queued",
  {
    context: RunContext;
    finding: Finding;
    triageResult: TriageResult;
    repoContext?: unknown;
    enrichedContext?: EnrichedRepoContext["enrichment"];
    precedents?: unknown;
    index: number;
    total: number;
  }
>;

export type VerificationBatchQueuedEvent = EventEnvelope<
  "verification:batch-queued",
  {
    context: RunContext;
    items: Array<{
      finding: Finding;
      triageResult: TriageResult;
      index: number;
      total: number;
    }>;
    repoContext?: unknown;
    enrichedContext?: EnrichedRepoContext["enrichment"];
  }
>;

export type VerificationResultEvent = EventEnvelope<
  "verification:result",
  {
    context: RunContext;
    finding: Finding;
    triageResult: TriageResult;
    result: VerificationResult;
    costUsd?: number;
    attempts?: number;
    index: number;
    total: number;
  }
>;

export type VerificationErrorEvent = EventEnvelope<
  "verification:error",
  {
    context: RunContext;
    finding: Finding;
    triageResult: TriageResult;
    error: string;
    costUsd?: number;
    attempts?: number;
    index: number;
    total: number;
    errorCategory?: ErrorCategory;
  }
>;

export type VerificationAgentActivityEvent = EventEnvelope<
  "verification:agent-activity",
  {
    context: RunContext;
    fingerprint: string;
    kind: "tool-start" | "tool-progress" | "tool-complete" | "reasoning";
    toolName?: string;
    toolInput?: Record<string, unknown>;
    summary?: string;
    elapsedSeconds?: number;
    index: number;
    total: number;
  }
>;

export type VerificationCompleteEvent = EventEnvelope<
  "verification:complete",
  {
    context: RunContext;
    verified: number;
    errors: number;
    totalCostUsd?: number;
  }
>;

export type VerificationQueueDepthEvent = EventEnvelope<
  "verification:queue-depth",
  {
    context: RunContext;
    queued: number;
    inFlight: number;
    processed: number;
    total: number;
  }
>;

export type PocHarnessStartEvent = EventEnvelope<
  "poc-harness:start",
  {
    context: RunContext;
    findingCount: number;
    model: string;
  }
>;

export type PocHarnessFindingQueuedEvent = EventEnvelope<
  "poc-harness:finding-queued",
  {
    context: RunContext;
    finding: Finding;
    triageResult: TriageResult;
    verificationResult: VerificationResult;
    repoContext?: unknown;
    index: number;
    total: number;
  }
>;

export type PocHarnessResultEvent = EventEnvelope<
  "poc-harness:result",
  {
    context: RunContext;
    finding: Finding;
    triageResult: TriageResult;
    verificationResult: VerificationResult;
    result: PocHarnessResult;
    costUsd?: number;
    attempts?: number;
    index: number;
    total: number;
  }
>;

export type PocHarnessErrorEvent = EventEnvelope<
  "poc-harness:error",
  {
    context: RunContext;
    finding: Finding;
    triageResult: TriageResult;
    verificationResult: VerificationResult;
    error: string;
    costUsd?: number;
    attempts?: number;
    index: number;
    total: number;
  }
>;

export type PocHarnessAgentActivityEvent = EventEnvelope<
  "poc-harness:agent-activity",
  {
    context: RunContext;
    fingerprint: string;
    kind: "tool-start" | "tool-progress" | "tool-complete" | "reasoning";
    toolName?: string;
    toolInput?: Record<string, unknown>;
    summary?: string;
    elapsedSeconds?: number;
    index: number;
    total: number;
  }
>;

export type PocHarnessCompleteEvent = EventEnvelope<
  "poc-harness:complete",
  {
    context: RunContext;
    generated: number;
    skipped: number;
    errors: number;
    totalCostUsd?: number;
  }
>;

export type PocHarnessQueueDepthEvent = EventEnvelope<
  "poc-harness:queue-depth",
  {
    context: RunContext;
    queued: number;
    inFlight: number;
    processed: number;
    total: number;
  }
>;

// ─── Dynamic Analysis Events ────────────────────────────────────────────────

export type DynamicAnalysisStartEvent = EventEnvelope<
  "dynamic:start",
  {
    context: RunContext;
    findingCount: number;
    model: string;
  }
>;

export type DynamicAnalysisFindingQueuedEvent = EventEnvelope<
  "dynamic:finding-queued",
  {
    context: RunContext;
    finding: Finding;
    triageResult: TriageResult;
    verificationResult?: VerificationResult;
    pocHarnessResult?: PocHarnessResult;
    repoContext?: unknown;
    index: number;
    total: number;
  }
>;

export type DynamicAnalysisResultEvent = EventEnvelope<
  "dynamic:result",
  {
    context: RunContext;
    finding: Finding;
    result: DynamicAnalysisRun;
    costUsd?: number;
    attempts?: number;
    index: number;
    total: number;
  }
>;

export type DynamicAnalysisErrorEvent = EventEnvelope<
  "dynamic:error",
  {
    context: RunContext;
    finding: Finding;
    error: string;
    costUsd?: number;
    attempts?: number;
    index: number;
    total: number;
  }
>;

export type DynamicAnalysisAgentActivityEvent = EventEnvelope<
  "dynamic:agent-activity",
  {
    context: RunContext;
    fingerprint: string;
    kind: "tool-start" | "tool-progress" | "tool-complete" | "reasoning";
    toolName?: string;
    toolInput?: Record<string, unknown>;
    summary?: string;
    elapsedSeconds?: number;
    index: number;
    total: number;
  }
>;

export type DynamicAnalysisCompleteEvent = EventEnvelope<
  "dynamic:complete",
  {
    context: RunContext;
    confirmed: number;
    interesting: number;
    rejected: number;
    errors: number;
    totalCostUsd?: number;
  }
>;

export type DynamicAnalysisQueueDepthEvent = EventEnvelope<
  "dynamic:queue-depth",
  {
    context: RunContext;
    queued: number;
    inFlight: number;
    processed: number;
    total: number;
  }
>;

export type StoreUpsertedEvent = EventEnvelope<
  "store:upserted",
  {
    context: RunContext;
    fingerprint: string;
    verdict: Verdict;
  }
>;

export type TaintAnalysisRefinementStartEvent = EventEnvelope<
  "taint-analysis:refinement-start",
  {
    context: RunContext;
    model: string;
    iteration: number;
    totalIterations: number;
    findings: Finding[];
    labelOutput?: unknown;
    repoContext?: unknown;
    refinementDeltaOnly: boolean;
  }
>;

export type TaintAnalysisRefinementResultEvent = EventEnvelope<
  "taint-analysis:refinement-result",
  {
    context: RunContext;
    iteration: number;
    affectedPasses: number[];
    updatedFindings: Finding[];
    deltaFindings: Finding[];
    deltaTriaged: number;
    deltaErrors: number;
    triageCostUsd: number;
  }
>;

export type TaintAnalysisRefinementErrorEvent = EventEnvelope<
  "taint-analysis:refinement-error",
  {
    context: RunContext;
    iteration: number;
    error: string;
  }
>;

export type VariantAnalysisStartEvent = EventEnvelope<
  "variant-analysis:start",
  {
    context: RunContext;
    confirmedCount: number;
    model: string;
  }
>;

export type VariantAnalysisCompleteEvent = EventEnvelope<
  "variant-analysis:complete",
  {
    context: RunContext;
    variantFindings: number;
    costUsd: number;
  }
>;

export type ChainAnalysisStartEvent = EventEnvelope<
  "chain-analysis:start",
  {
    context: RunContext;
    confirmedCount: number;
    model: string;
  }
>;

export type ChainAnalysisCompleteEvent = EventEnvelope<
  "chain-analysis:complete",
  {
    context: RunContext;
    chainCount: number;
    costUsd: number;
  }
>;

export type PocExecutionQueuedEvent = EventEnvelope<
  "poc-execution:queued",
  {
    context: RunContext;
    fingerprint: string;
    scriptPath: string;
    language: string;
  }
>;

export type PocExecutionResultEvent = EventEnvelope<
  "poc-execution:result",
  {
    context: RunContext;
    fingerprint: string;
    exitCode: number;
    stdout: string;
    stderr: string;
    timedOut: boolean;
    durationMs: number;
    verdict: "PASS" | "FAIL" | "ERROR" | "TIMEOUT";
  }
>;

export type PocExecutionErrorEvent = EventEnvelope<
  "poc-execution:error",
  {
    context: RunContext;
    fingerprint: string;
    error: string;
  }
>;

export type BudgetExceededEvent = EventEnvelope<
  "budget:exceeded",
  { context: RunContext; totalCostUsd: number; budgetUsd: number }
>;

/* ── LLM observability events ─────────────────────────────────────── */

export type LlmCallStartEvent = EventEnvelope<
  "llm:call-start",
  {
    model: string;
    promptLength: number;
    runId: string;
  }
>;

export type LlmCallCompleteEvent = EventEnvelope<
  "llm:call-complete",
  {
    model: string;
    durationMs: number;
    tokensUsed: number;
    costUsd: number;
    runId: string;
  }
>;

export type LlmCallErrorEvent = EventEnvelope<
  "llm:call-error",
  {
    model: string;
    error: string;
    retryable: boolean;
    runId: string;
  }
>;

export type LlmRetryEvent = EventEnvelope<
  "llm:retry",
  {
    model: string;
    attempt: number;
    maxAttempts: number;
    delayMs: number;
    runId: string;
  }
>;

/* ── Retry observability events ───────────────────────────────────── */

export type RetryAttemptEvent = EventEnvelope<
  "retry:attempt",
  {
    operation: string;
    attempt: number;
    maxAttempts: number;
    error: string;
  }
>;

export type RetryExhaustedEvent = EventEnvelope<
  "retry:exhausted",
  {
    operation: string;
    attempts: number;
    finalError: string;
  }
>;

/* ── Budget observability events ──────────────────────────────────── */

export type BudgetCheckEvent = EventEnvelope<
  "budget:check",
  {
    currentSpend: number;
    maxBudget: number;
    percentUsed: number;
  }
>;

export type BudgetWarningEvent = EventEnvelope<
  "budget:warning",
  {
    currentSpend: number;
    maxBudget: number;
    percentUsed: number;
  }
>;

export type ReportRequestedEvent = EventEnvelope<
  "report:requested",
  {
    context: RunContext;
    stats?: Partial<PipelineStats>;
    fingerprints?: string[];
    exploitChains?: ExploitChain[];
    reportMode?: "full" | "suppress";
  }
>;

export type ReportCompleteEvent = EventEnvelope<
  "report:complete",
  {
    context: RunContext;
  }
>;

export type PromptReportEvent = EventEnvelope<
  "prompt:report",
  {
    context: RunContext;
    taskId: string;
    sections: Array<{ name: string; charCount: number; estimatedTokens: number }>;
    totalChars: number;
    totalEstimatedTokens: number;
    warnings: string[];
  }
>;

export type TaskApprovalRequestedEvent = EventEnvelope<
  "task:approval-requested",
  {
    context: RunContext;
    taskId: string;
    description: string;
  }
>;

// ── Patch synthesis events ────────────────────────────────────────────────

export type PatchRequestedEvent = EventEnvelope<
  "patch:requested",
  {
    context: RunContext;
    fingerprint: string;
    trigger: "verify" | "poc" | "triage";
  }
>;

export type PatchStartEvent = EventEnvelope<
  "patch:start",
  {
    context: RunContext;
    fingerprint: string;
  }
>;

export type PatchCompleteEvent = EventEnvelope<
  "patch:complete",
  {
    context: RunContext;
    fingerprint: string;
    status: PatchStatus;
    worktreePath: string | null;
    costUsd: number;
    iterations: number;
  }
>;

export type PatchErrorEvent = EventEnvelope<
  "patch:error",
  {
    context: RunContext;
    fingerprint: string;
    error: string;
    attempt: number;
  }
>;

export type PatchQueueDepthEvent = EventEnvelope<
  "patch:queue-depth",
  {
    context: RunContext;
    depth: number;
  }
>;

// ── Patch re-verification events ─────────────────────────────────────────

export type PatchVerifyRequestedEvent = EventEnvelope<
  "patch-verify:requested",
  {
    context: RunContext;
    fingerprint: string;
    worktreePath: string;
    depth: "scanner" | "triage" | "full";
  }
>;

export type PatchVerifyStartEvent = EventEnvelope<
  "patch-verify:start",
  {
    context: RunContext;
    fingerprint: string;
  }
>;

export type PatchVerifyCompleteEvent = EventEnvelope<
  "patch-verify:complete",
  {
    context: RunContext;
    fingerprint: string;
    verified: boolean;
    depth: "scanner" | "triage" | "full";
    details: string;
  }
>;

export type PatchVerifyErrorEvent = EventEnvelope<
  "patch-verify:error",
  {
    context: RunContext;
    fingerprint: string;
    error: string;
  }
>;

export type AutoRuleGeneratedEvent = EventEnvelope<
  "auto-rule:generated",
  {
    context: RunContext;
    rule: GeneratedRule;
    sourceFinding: { fingerprint: string; filePath: string; startLine: number };
  }
>;

export type KuzushiEvent =
  | PipelineStartEvent
  | PipelineCompleteEvent
  | PipelineErrorEvent
  | BusHandlerErrorEvent
  | TaskStartEvent
  | TaskProgressEvent
  | TaskCompleteEvent
  | TaskErrorEvent
  | TaskSkippedEvent
  | StageCompleteEvent
  | ScanStartEvent
  | ScanFindingEvent
  | ScanScannerCompleteEvent
  | ScanCompleteEvent
  | TriageStartEvent
  | TriageFindingQueuedEvent
  | TriageBatchQueuedEvent
  | TriageResultEvent
  | TriageErrorEvent
  | TriageAgentActivityEvent
  | TriageAssertionsEvent
  | TriageCompleteEvent
  | TriageQueueDepthEvent
  | VerificationStartEvent
  | VerificationFindingQueuedEvent
  | VerificationBatchQueuedEvent
  | VerificationResultEvent
  | VerificationErrorEvent
  | VerificationAgentActivityEvent
  | VerificationCompleteEvent
  | VerificationQueueDepthEvent
  | PocHarnessStartEvent
  | PocHarnessFindingQueuedEvent
  | PocHarnessResultEvent
  | PocHarnessErrorEvent
  | PocHarnessAgentActivityEvent
  | PocHarnessCompleteEvent
  | PocHarnessQueueDepthEvent
  | DynamicAnalysisStartEvent
  | DynamicAnalysisFindingQueuedEvent
  | DynamicAnalysisResultEvent
  | DynamicAnalysisErrorEvent
  | DynamicAnalysisAgentActivityEvent
  | DynamicAnalysisCompleteEvent
  | DynamicAnalysisQueueDepthEvent
  | StoreUpsertedEvent
  | TaintAnalysisRefinementStartEvent
  | TaintAnalysisRefinementResultEvent
  | TaintAnalysisRefinementErrorEvent
  | VariantAnalysisStartEvent
  | VariantAnalysisCompleteEvent
  | ChainAnalysisStartEvent
  | ChainAnalysisCompleteEvent
  | PocExecutionQueuedEvent
  | PocExecutionResultEvent
  | PocExecutionErrorEvent
  | BudgetExceededEvent
  | LlmCallStartEvent
  | LlmCallCompleteEvent
  | LlmCallErrorEvent
  | LlmRetryEvent
  | RetryAttemptEvent
  | RetryExhaustedEvent
  | BudgetCheckEvent
  | BudgetWarningEvent
  | ReportRequestedEvent
  | ReportCompleteEvent
  | PromptReportEvent
  | TaskApprovalRequestedEvent
  | PatchRequestedEvent
  | PatchStartEvent
  | PatchCompleteEvent
  | PatchErrorEvent
  | PatchQueueDepthEvent
  | PatchVerifyRequestedEvent
  | PatchVerifyStartEvent
  | PatchVerifyCompleteEvent
  | PatchVerifyErrorEvent
  | AutoRuleGeneratedEvent;
