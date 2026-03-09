import type { Finding, ScannerId } from "../scanners/types.js";
import type { TaskOutputKind } from "../agents/types.js";
import type {
  ExploitChain,
  KuzushiConfig,
  PocHarnessResult,
  ScanOpts,
  TriageResult,
  VerificationResult,
  Verdict,
} from "../types.js";
import type { EventEnvelope } from "./types.js";

export interface RunContext {
  runId: string;
  repoRoot: string;
  scanPath?: string;
  repoName: string;
  dbPath: string;
}

export interface PipelineStats {
  scanners: ScannerId[];
  totalFindings: number;
  queuedForTriage: number;
  skippedAlreadyTriaged: number;
  skippedLowConfidence?: number;
  skippedByFpFilter?: number;
  skippedByLlmRescore?: number;
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
  chainCount?: number;
  chainAnalysisCostUsd?: number;
  budgetExceeded?: boolean;
  failedTasks?: string[];
  extractionDegradation?: { status: string; reasons: string[] };
  stitchDegradation?: { type: string; reason: string; message: string };
  tiPriorDegraded?: boolean;
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
  }
>;

export type TriageFindingQueuedEvent = EventEnvelope<
  "triage:finding-queued",
  {
    context: RunContext;
    finding: Finding;
    repoContext?: unknown;
    precedents?: unknown;
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
    precedents?: unknown;
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
    precedents?: unknown;
    index: number;
    total: number;
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

export type BudgetExceededEvent = EventEnvelope<
  "budget:exceeded",
  { context: RunContext; totalCostUsd: number; budgetUsd: number }
>;

export type ReportRequestedEvent = EventEnvelope<
  "report:requested",
  {
    context: RunContext;
    stats?: Partial<PipelineStats>;
    fingerprints?: string[];
    exploitChains?: ExploitChain[];
  }
>;

export type ReportCompleteEvent = EventEnvelope<
  "report:complete",
  {
    context: RunContext;
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
  | TriageCompleteEvent
  | TriageQueueDepthEvent
  | VerificationStartEvent
  | VerificationFindingQueuedEvent
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
  | StoreUpsertedEvent
  | TaintAnalysisRefinementStartEvent
  | TaintAnalysisRefinementResultEvent
  | TaintAnalysisRefinementErrorEvent
  | VariantAnalysisStartEvent
  | VariantAnalysisCompleteEvent
  | ChainAnalysisStartEvent
  | ChainAnalysisCompleteEvent
  | BudgetExceededEvent
  | ReportRequestedEvent
  | ReportCompleteEvent;
