import type { Finding, ScannerId } from "../scanners/types.js";
import type { TaskOutputKind } from "../agents/types.js";
import type { KuzushiConfig, ScanOpts, TriageResult, Verdict } from "../types.js";
import type { EventEnvelope } from "./types.js";

export interface RunContext {
  runId: string;
  repoRoot: string;
  repoName: string;
  dbPath: string;
}

export interface PipelineStats {
  scanners: ScannerId[];
  totalFindings: number;
  queuedForTriage: number;
  skippedAlreadyTriaged: number;
  triaged: number;
  triageErrors: number;
  startedAt: string;
  completedAt: string;
}

export type PipelineStartEvent = EventEnvelope<
  "pipeline:start",
  {
    context: RunContext;
    config: KuzushiConfig;
    scanOpts: ScanOpts;
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
    index: number;
    total: number;
  }
>;

export type TriageResultEvent = EventEnvelope<
  "triage:result",
  {
    context: RunContext;
    finding: Finding;
    result: TriageResult;
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

export type StoreUpsertedEvent = EventEnvelope<
  "store:upserted",
  {
    context: RunContext;
    fingerprint: string;
    verdict: Verdict;
  }
>;

export type ReportRequestedEvent = EventEnvelope<
  "report:requested",
  {
    context: RunContext;
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
  | TriageResultEvent
  | TriageErrorEvent
  | TriageAgentActivityEvent
  | TriageCompleteEvent
  | TriageQueueDepthEvent
  | StoreUpsertedEvent
  | ReportRequestedEvent
  | ReportCompleteEvent;
