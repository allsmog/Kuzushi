import type { OutputKind } from "../agents/types.js";
import type { PocExecutionVerdict, ReportMode } from "../contracts.js";
import type { ErrorCategory } from "../errors.js";
import type { QualityGateResult } from "../quality-gate-types.js";
import type { Finding, TaskId } from "../scanners/types.js";
import type { RunMetrics } from "../scoring/run-metrics-types.js";
import type { GeneratedRule } from "../strategies/types.js";
import type {
  DynamicAnalysisRun,
  EnrichedRepoContext,
  ExploitChain,
  KuzushiConfig,
  PatchStatus,
  PocHarnessResult,
  ScanOpts,
  TriageResult,
  Verdict,
  VerificationResult,
} from "../types.js";
import type { EventEnvelope } from "./types.js";

export type { RunContext } from "./run-context.js";

import type { RunContext } from "./run-context.js";

export interface PipelineStats {
  tasks: TaskId[];
  totalFindings: number;
  queuedForTriage: number;
  skippedAlreadyTriaged: number;
  skippedLowConfidence?: number;
  skippedByFpFilter?: number;
  skippedByScoreFilter?: number;
  autoClassifiedByDesign?: number;
  softSuppressedFindings?: number;
  skippedByLlmRescore?: number;
  corroboratedClusters?: number;
  triaged: number;
  triageErrors: number;
  totalCostUsd?: number;
  verified?: number;
  verifyErrors?: number;
  verifyCostUsd?: number;
  verifyGateAutoAccepted?: number;
  verifyGateSkipped?: number;
  verifyGateCostUsd?: number;
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
    seedTaskOutputs?: Map<string, unknown>;
    monorepoContext?: import("../monorepo/types.js").MonorepoSharedContext;
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
    outputKind: OutputKind;
    input: unknown;
    upstreamOutputs: Map<string, unknown>;
  }
>;

export type TaskProgressEvent = EventEnvelope<
  "task:progress",
  {
    context: RunContext;
    taskId: string;
    outputKind: OutputKind;
    progress: unknown;
  }
>;

export type TaskCompleteEvent = EventEnvelope<
  "task:complete",
  {
    context: RunContext;
    taskId: string;
    outputKind: OutputKind;
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
    outputKind: OutputKind;
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

export type ScanFindingEvent = EventEnvelope<
  "scan:finding",
  {
    context: RunContext;
    finding: Finding;
    scannerId: TaskId;
  }
>;

export type ScanCompleteEvent = EventEnvelope<
  "scan:complete",
  {
    context: RunContext;
    totalFindings: number;
  }
>;

export type ScanAgentActivityEvent = EventEnvelope<
  "scan:agent-activity",
  {
    context: RunContext;
    taskId: string;
    kind: "tool-start" | "tool-progress" | "tool-complete" | "reasoning";
    toolName?: string;
    toolInput?: Record<string, unknown>;
    summary?: string;
    elapsedSeconds?: number;
  }
>;

/**
 * Lifecycle events for scan-stage tasks that the orchestrator runs directly
 * during `handleScanComplete` (post-DAG ranking helpers like
 * `reachability-check` and `call-graph-assist`). These don't go through the
 * scan-worker `task:start` dispatch path — emitting `task:start` would cause
 * the worker to re-run them — but they still need a UI subtask row so the
 * pipeline view and "tasks running" counter stay truthful while they execute.
 *
 * Only the report-worker subscribes; scan-worker ignores them by design.
 */
export type ScanPostTaskStartEvent = EventEnvelope<
  "scan:post-task-start",
  {
    context: RunContext;
    taskId: string;
    detail?: string;
  }
>;

export type ScanPostTaskCompleteEvent = EventEnvelope<
  "scan:post-task-complete",
  {
    context: RunContext;
    taskId: string;
    durationMs: number;
    costUsd?: number;
    error?: string;
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
    /** Threat IDs known to the threat model, used to validate source_threat_ids. */
    knownThreatIds?: string[];
    operatorContext?: string;
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
    /** Threat IDs known to the threat model, used to validate source_threat_ids. */
    knownThreatIds?: string[];
    operatorContext?: string;
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

/**
 * Shared payload for every `${moduleId}:agent-activity` event. One row in
 * the UI's `agentActivity` map is keyed by `fingerprint` (e.g. finding id
 * for triage/verify/poc, actor name for carlini-threat-hunt).
 *
 * `done: true` signals the fingerprint's agent has reached a terminal state
 * (success, error, or abort); the shared handler in the report-worker drops
 * the row so the "N agents active" count is accurate. Producers that run a
 * single monolithic agent (non-fan-out) simply don't set this field.
 *
 * `moduleId` is optional and derivable from the event topic
 * (`triage:agent-activity` → `"triage"`); included for fast routing in
 * pattern-subscribed handlers.
 */
export interface TaskAgentActivityPayload {
  context: RunContext;
  fingerprint: string;
  kind: "tool-start" | "tool-progress" | "tool-complete" | "reasoning";
  toolName?: string;
  toolInput?: Record<string, unknown>;
  summary?: string;
  elapsedSeconds?: number;
  index: number;
  total: number;
  /**
   * Terminal signal — UI drops this fingerprint's row on the next tick.
   * Producers that fan out sub-agents (carlini-threat-hunt actors, verify finding
   * workers, …) set `done: true` on the last event for each fingerprint.
   */
  done?: boolean;
  /**
   * Emitting module id (e.g. `"carlini-threat-hunt"`). Optional and derivable from
   * the topic name; populated by `ExecutionContext.reportAgentActivity` for
   * subscribers that can't easily pattern-match the topic.
   */
  moduleId?: string;
}

/**
 * Template-literal supertype for all per-agent activity events. Any event
 * whose type matches `${moduleId}:agent-activity` carries a
 * `TaskAgentActivityPayload`. Consumers subscribe by exact topic (fast path)
 * or pattern-match the suffix (orchestrator / report-worker do this so new
 * fan-out tools get uniform UI plumbing without bus wiring).
 *
 * The five narrow per-module aliases (`TriageAgentActivityEvent`,
 * `VerificationAgentActivityEvent`, `PocHarnessAgentActivityEvent`,
 * `DynamicAnalysisAgentActivityEvent`, `CarliniThreatHuntAgentActivityEvent`) used
 * to live here for source compatibility. They were collapsed into this
 * supertype as part of the module-forward reconciliation — every consumer
 * now types against `TaskAgentActivityEvent` directly.
 */
export type TaskAgentActivityEvent = EventEnvelope<
  `${string}:agent-activity`,
  TaskAgentActivityPayload
>;

export type TriageAssertionsEvent = EventEnvelope<
  "triage:assertions",
  {
    context: RunContext;
    fingerprint: string;
    assertions: Array<{
      name: string;
      passed: boolean;
      score: number;
      weight: number;
      reason: string;
    }>;
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
    threatModelSummary?: string;
    /** Threat IDs known to the threat model, used to validate source_threat_ids. */
    knownThreatIds?: string[];
    operatorContext?: string;
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
    operatorContext?: string;
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
  TaskAgentActivityPayload
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
    verdict: PocExecutionVerdict;
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

/* ── Task phase-progress events ───────────────────────────────────── */

/**
 * Fine-grained progress inside a long-running task — lets the shell spinner
 * show "building threat model · phase 2 (S4 threats)" instead of freezing on
 * just the task id while a multi-phase LLM pipeline churns.
 */
export type TaskPhaseProgressEvent = EventEnvelope<
  "task:phase-progress",
  {
    taskId: string;
    /** Short human-readable phase label, e.g. "phase 2 (S4 threats)". */
    phase: string;
  }
>;

/**
 * Sub-step description for the shell's rolling activity tail. Tools emit
 * these (via `ctx.reportActivity(...)` or `publishTaskActivity(...)`) so the
 * operator sees what's happening mid-tool, not just a frozen spinner.
 */
export type TaskActivityEvent = EventEnvelope<
  "task:activity",
  {
    taskId: string;
    /** One-line human description of the current sub-step. */
    description: string;
    /** Optional phase label (also feeds the phase strip). */
    phase?: string;
    /** Optional step/total if the task is iterating a known-size batch. */
    step?: number;
    total?: number;
  }
>;

/**
 * Ephemeral subprocess output preview for the shell's `⎿` live tail.
 * Sibling of `task:activity` but semantically different: these are
 * raw stdout / tool-use streams the operator reads "while it runs",
 * not structured progress. The shell drops them when the tool resolves
 * and never appends them to scrollback.
 *
 * Tools emit via `ctx.reportOutput(line)` (or `publishTaskOutput(...)`).
 */
export type TaskOutputEvent = EventEnvelope<
  "task:output",
  {
    taskId: string;
    /** One output line, already clamped / summarized by the producer. */
    line: string;
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
    reportMode?: ReportMode;
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
    depth: "task" | "triage" | "full";
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
    depth: "task" | "triage" | "full";
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

// ── Run lifecycle events (DB persistence via store-worker) ──────────────

export type RunStatusEvent = EventEnvelope<
  "run:status",
  {
    context: RunContext;
    status: string;
    extra?: {
      totalCostUsd?: number;
      completedAt?: string;
      findingsJson?: string;
      metricsJson?: string;
    };
  }
>;

export type RunCostEvent = EventEnvelope<
  "run:cost",
  {
    context: RunContext;
    costUsd: number;
  }
>;

export type RunFindingsCheckpointEvent = EventEnvelope<
  "run:findings-checkpoint",
  {
    context: RunContext;
    findings: Finding[];
  }
>;

export type RunContextCheckpointEvent = EventEnvelope<
  "run:context-checkpoint",
  {
    context: RunContext;
    repoContext: unknown;
  }
>;

export type RunMetricsEvent = EventEnvelope<
  "run:metrics",
  {
    context: RunContext;
    metrics: RunMetrics;
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
  | ScanFindingEvent
  | ScanCompleteEvent
  | ScanAgentActivityEvent
  | ScanPostTaskStartEvent
  | ScanPostTaskCompleteEvent
  | TriageStartEvent
  | TriageFindingQueuedEvent
  | TriageBatchQueuedEvent
  | TriageResultEvent
  | TriageErrorEvent
  | TaskAgentActivityEvent
  | TriageAssertionsEvent
  | TriageCompleteEvent
  | TriageQueueDepthEvent
  | VerificationStartEvent
  | VerificationFindingQueuedEvent
  | VerificationBatchQueuedEvent
  | VerificationResultEvent
  | VerificationErrorEvent
  | VerificationCompleteEvent
  | VerificationQueueDepthEvent
  | PocHarnessStartEvent
  | PocHarnessFindingQueuedEvent
  | PocHarnessResultEvent
  | PocHarnessErrorEvent
  | PocHarnessCompleteEvent
  | PocHarnessQueueDepthEvent
  | DynamicAnalysisStartEvent
  | DynamicAnalysisFindingQueuedEvent
  | DynamicAnalysisResultEvent
  | DynamicAnalysisErrorEvent
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
  | TaskPhaseProgressEvent
  | TaskActivityEvent
  | TaskOutputEvent
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
  | AutoRuleGeneratedEvent
  | RunStatusEvent
  | RunCostEvent
  | RunFindingsCheckpointEvent
  | RunContextCheckpointEvent
  | RunMetricsEvent;
