import type Database from "better-sqlite3";
import { normalizeTaskIds } from "../agents/registry.js";
import type { TaskRegistry } from "../agents/registry.js";
import type { Finding } from "../scanners/types.js";
import type { ScannerRegistry } from "../scanners/registry.js";
import { getTriagedFingerprints } from "../store.js";
import type { KuzushiConfig, ScanOpts } from "../types.js";
import type {
  BusHandlerErrorEvent,
  PipelineErrorEvent,
  PipelineStartEvent,
  ReportCompleteEvent,
  RunContext,
  ScanCompleteEvent,
  ScanFindingEvent,
  TaskCompleteEvent,
  TaskErrorEvent,
  TriageErrorEvent,
  TriageResultEvent,
} from "./events.js";
import { createEvent } from "./helpers.js";
import type { MessageBus } from "./types.js";

interface QueuedFinding {
  finding: Finding;
  index: number;
  total: number;
}

interface RunState {
  context: RunContext;
  config: KuzushiConfig;
  scanOpts: ScanOpts;
  scanners: string[];
  startedAt: string;
  scanFindings: Finding[];
  totalFindings: number;
  skippedAlreadyTriaged: number;
  triageQueue: QueuedFinding[];
  queueCursor: number;
  triageTotal: number;
  inFlight: number;
  triaged: number;
  triageErrors: number;
  reportRequested: boolean;
  dispatching: boolean;
  collectScanFindingEvents: boolean;
  taskOutputs: Map<string, unknown>;
}

export interface OrchestratorDeps {
  registry: ScannerRegistry;
  taskRegistry?: TaskRegistry;
  db: Database.Database;
}

type TaskOutcome =
  | { kind: "complete"; event: TaskCompleteEvent }
  | { kind: "error"; event: TaskErrorEvent };

/**
 * Coordinator-style orchestrator for the event-driven scan pipeline.
 */
export class PipelineOrchestrator {
  private readonly runs = new Map<string, RunState>();

  constructor(
    private readonly bus: MessageBus,
    private readonly deps: OrchestratorDeps,
  ) {
    this.registerHandlers();
  }

  private registerHandlers(): void {
    this.bus.subscribe<PipelineStartEvent>("pipeline:start", async (event) => {
      await this.handlePipelineStart(event);
    });

    this.bus.subscribe<ScanFindingEvent>("scan:finding", (event) => {
      this.handleScanFinding(event);
    });

    this.bus.subscribe<ScanCompleteEvent>("scan:complete", async (event) => {
      await this.handleScanComplete(event);
    });

    this.bus.subscribe<TriageResultEvent>("triage:result", async (event) => {
      await this.handleTriageResult(event);
    });

    this.bus.subscribe<TriageErrorEvent>("triage:error", async (event) => {
      await this.handleTriageError(event);
    });

    this.bus.subscribe<ReportCompleteEvent>("report:complete", async (event) => {
      await this.handleReportComplete(event);
    });

    this.bus.subscribe<BusHandlerErrorEvent>("bus:handler-error", async (event) => {
      await this.handleBusHandlerError(event);
    });

    this.bus.subscribe<PipelineErrorEvent>("pipeline:error", (event) => {
      if (!event.payload.fatal) {
        return;
      }
      this.runs.delete(event.meta.runId);
    });
  }

  private async handlePipelineStart(event: PipelineStartEvent): Promise<void> {
    const runId = event.meta.runId;
    const { context, config, scanOpts } = event.payload;

    let scanners: string[];
    try {
      scanners = this.deps.registry.resolveEnabled(scanOpts, config);
    } catch (error) {
      await this.bus.publish(
        createEvent("pipeline:error", runId, {
          context,
          error: toErrorMessage(error),
          fatal: true,
        }),
      );
      return;
    }

    const state: RunState = {
      context,
      config,
      scanOpts,
      scanners,
      startedAt: event.meta.timestamp,
      scanFindings: [],
      totalFindings: 0,
      skippedAlreadyTriaged: 0,
      triageQueue: [],
      queueCursor: 0,
      triageTotal: 0,
      inFlight: 0,
      triaged: 0,
      triageErrors: 0,
      reportRequested: false,
      dispatching: false,
      collectScanFindingEvents: !this.deps.taskRegistry,
      taskOutputs: new Map<string, unknown>(),
    };

    this.runs.set(runId, state);

    if (this.deps.taskRegistry) {
      await this.runTaskDag(state, runId);
      return;
    }

    await this.startLegacyScan(state, runId);
  }

  private async startLegacyScan(state: RunState, runId: string): Promise<void> {
    await this.bus.publish(
      createEvent("scan:start", runId, {
        context: state.context,
        scanners: state.scanners,
        scanOpts: state.scanOpts,
      }),
    );
  }

  private async runTaskDag(state: RunState, runId: string): Promise<void> {
    if (!this.deps.taskRegistry) {
      await this.startLegacyScan(state, runId);
      return;
    }

    const enabledTaskIds = normalizeTaskIds([
      ...state.scanners,
      ...(state.config.enabledTasks ?? []),
    ]);

    let stages: string[][];
    try {
      stages = this.deps.taskRegistry.resolveOrder(enabledTaskIds);
    } catch (error) {
      await this.bus.publish(
        createEvent("pipeline:error", runId, {
          context: state.context,
          error: toErrorMessage(error),
          fatal: true,
        }),
      );
      return;
    }

    for (let stageIndex = 0; stageIndex < stages.length; stageIndex += 1) {
      const group = stages[stageIndex];
      const outcomes = group.map((taskId) => this.waitForTaskOutcome(runId, taskId));

      for (const taskId of group) {
        const task = this.deps.taskRegistry.get(taskId);
        await this.bus.publish(
          createEvent("task:start", runId, {
            context: state.context,
            taskId,
            outputKind: task.outputKind,
            input: state.scanOpts,
            upstreamOutputs: new Map(state.taskOutputs),
          }),
        );
      }

      const resolved = await Promise.all(outcomes);
      const failed = resolved.find((outcome) => outcome.kind === "error");
      if (failed && failed.kind === "error") {
        await this.bus.publish(
          createEvent("pipeline:error", runId, {
            context: state.context,
            error: `Task \"${failed.event.payload.taskId}\" failed: ${failed.event.payload.error}`,
            fatal: true,
          }),
        );
        return;
      }

      for (const outcome of resolved) {
        if (outcome.kind === "complete") {
          state.taskOutputs.set(outcome.event.payload.taskId, outcome.event.payload.output);
          if (outcome.event.payload.outputKind === "findings") {
            state.scanFindings.push(...coerceFindings(outcome.event.payload.output));
          }
        }
      }

      await this.bus.publish(
        createEvent("stage:complete", runId, {
          context: state.context,
          stageIndex,
          taskIds: [...group],
        }),
      );
    }

    await this.bus.publish(
      createEvent("scan:complete", runId, {
        context: state.context,
        totalFindings: state.scanFindings.length,
      }),
    );
  }

  private waitForTaskOutcome(runId: string, taskId: string): Promise<TaskOutcome> {
    const complete = this.bus.waitFor<TaskCompleteEvent>(
      "task:complete",
      (event) => event.meta.runId === runId && event.payload.taskId === taskId,
    ).then((event) => ({ kind: "complete" as const, event }));

    const error = this.bus.waitFor<TaskErrorEvent>(
      "task:error",
      (event) => event.meta.runId === runId && event.payload.taskId === taskId,
    ).then((event) => ({ kind: "error" as const, event }));

    return Promise.race([complete, error]);
  }

  private handleScanFinding(event: ScanFindingEvent): void {
    const state = this.runs.get(event.meta.runId);
    if (!state) {
      return;
    }

    if (!state.collectScanFindingEvents) {
      return;
    }

    state.scanFindings.push(event.payload.finding);
  }

  private async handleScanComplete(event: ScanCompleteEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    const rankedFindings = selectTopFindings(state.scanFindings, state.scanOpts.maxFindings);
    state.totalFindings = rankedFindings.length;

    let alreadyTriaged = new Set<string>();
    if (!state.scanOpts.fresh) {
      try {
        alreadyTriaged = getTriagedFingerprints(this.deps.db);
      } catch (error) {
        await this.bus.publish(
          createEvent("pipeline:error", runId, {
            context: state.context,
            error: toErrorMessage(error),
            fatal: true,
          }),
        );
        return;
      }
    }

    const triageCandidates = rankedFindings.filter(
      (finding) => !alreadyTriaged.has(finding.fingerprint),
    );

    state.skippedAlreadyTriaged = rankedFindings.length - triageCandidates.length;
    state.triageTotal = triageCandidates.length;
    state.triageQueue = triageCandidates.map((finding, idx) => ({
      finding,
      index: idx + 1,
      total: triageCandidates.length,
    }));
    state.queueCursor = 0;

    await this.bus.publish(
      createEvent("triage:start", runId, {
        context: state.context,
        findingCount: triageCandidates.length,
        model: state.config.triageModel ?? state.config.model,
      }),
    );

    await this.publishQueueDepth(state, runId);

    if (triageCandidates.length === 0) {
      await this.finishTriageAndRequestReport(state, runId);
      return;
    }

    await this.dispatchTriage(state, runId);
  }

  private async handleTriageResult(event: TriageResultEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    state.inFlight = Math.max(0, state.inFlight - 1);
    state.triaged += 1;
    await this.publishQueueDepth(state, runId);

    if (this.isTriageDone(state)) {
      await this.finishTriageAndRequestReport(state, runId);
      return;
    }

    await this.dispatchTriage(state, runId);
  }

  private async handleTriageError(event: TriageErrorEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    state.inFlight = Math.max(0, state.inFlight - 1);
    state.triageErrors += 1;
    await this.publishQueueDepth(state, runId);

    if (this.isTriageDone(state)) {
      await this.finishTriageAndRequestReport(state, runId);
      return;
    }

    await this.dispatchTriage(state, runId);
  }

  private async handleReportComplete(event: ReportCompleteEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    await this.bus.publish(
      createEvent("pipeline:complete", runId, {
        context: state.context,
        stats: {
          scanners: [...state.scanners],
          totalFindings: state.totalFindings,
          queuedForTriage: state.triageTotal,
          skippedAlreadyTriaged: state.skippedAlreadyTriaged,
          triaged: state.triaged,
          triageErrors: state.triageErrors,
          startedAt: state.startedAt,
          completedAt: event.meta.timestamp,
        },
      }),
    );

    this.runs.delete(runId);
  }

  private async handleBusHandlerError(event: BusHandlerErrorEvent): Promise<void> {
    const state = this.runs.get(event.meta.runId);
    if (!state) {
      return;
    }

    await this.bus.publish(
      createEvent("pipeline:error", event.meta.runId, {
        context: state.context,
        error: `Bus handler failure on ${event.payload.sourceEventType}: ${event.payload.error}`,
        fatal: true,
      }),
    );
  }

  private async dispatchTriage(state: RunState, runId: string): Promise<void> {
    if (state.dispatching) {
      return;
    }

    state.dispatching = true;
    try {
      const concurrency = normalizeConcurrency(state.config.triageConcurrency);

      while (state.inFlight < concurrency && state.queueCursor < state.triageQueue.length) {
        const item = state.triageQueue[state.queueCursor];
        state.queueCursor += 1;
        state.inFlight += 1;

        await this.bus.publish(
          createEvent("triage:finding-queued", runId, {
            context: state.context,
            finding: item.finding,
            index: item.index,
            total: item.total,
          }),
        );
      }

      await this.publishQueueDepth(state, runId);
    } finally {
      state.dispatching = false;
    }
  }

  private isTriageDone(state: RunState): boolean {
    const processed = state.triaged + state.triageErrors;
    return (
      state.triageTotal > 0
      && processed >= state.triageTotal
      && state.inFlight === 0
      && !state.reportRequested
    );
  }

  private async finishTriageAndRequestReport(state: RunState, runId: string): Promise<void> {
    if (state.reportRequested) {
      return;
    }

    await this.bus.publish(
      createEvent("triage:complete", runId, {
        context: state.context,
        triaged: state.triaged,
        errors: state.triageErrors,
      }),
    );

    await this.bus.publish(
      createEvent("report:requested", runId, {
        context: state.context,
      }),
    );

    state.reportRequested = true;
  }

  private async publishQueueDepth(state: RunState, runId: string): Promise<void> {
    const queued = Math.max(0, state.triageQueue.length - state.queueCursor);
    const processed = state.triaged + state.triageErrors;

    await this.bus.publish(
      createEvent("triage:queue-depth", runId, {
        context: state.context,
        queued,
        inFlight: state.inFlight,
        processed,
        total: state.triageTotal,
      }),
    );
  }
}

export function registerOrchestrator(
  bus: MessageBus,
  deps: OrchestratorDeps,
): PipelineOrchestrator {
  return new PipelineOrchestrator(bus, deps);
}

function normalizeConcurrency(raw: number): number {
  if (!Number.isFinite(raw) || raw < 1) {
    return 1;
  }

  return Math.floor(raw);
}

function selectTopFindings(findings: Finding[], maxFindings?: number): Finding[] {
  const deduped = new Map<string, Finding>();

  for (const finding of findings) {
    const existing = deduped.get(finding.fingerprint);
    if (!existing || finding.score > existing.score) {
      deduped.set(finding.fingerprint, finding);
    }
  }

  return [...deduped.values()]
    .sort((a, b) => b.score - a.score)
    .slice(0, maxFindings);
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
}

function coerceFindings(value: unknown): Finding[] {
  if (!Array.isArray(value)) {
    return [];
  }

  const findings: Finding[] = [];

  for (const item of value) {
    if (!isRecord(item)) {
      continue;
    }

    const finding = coerceFinding(item);
    if (!finding) {
      continue;
    }

    findings.push(finding);
  }

  return findings;
}

function coerceFinding(item: Record<string, unknown>): Finding | null {
  const scanner = asString(item["scanner"]);
  const fingerprint = asString(item["fingerprint"]);
  const ruleId = asString(item["ruleId"]);
  const filePath = asString(item["filePath"]);
  const severity = asString(item["severity"]);
  const message = asString(item["message"]);
  const scannerConfidence = asString(item["scannerConfidence"]);
  const likelihood = asString(item["likelihood"]);
  const impact = asString(item["impact"]);
  const startLine = asNumber(item["startLine"]);
  const score = asNumber(item["score"]);
  const subcategory = asStringArray(item["subcategory"]);
  const cwe = asStringArray(item["cwe"]);

  if (
    !scanner
    || !fingerprint
    || !ruleId
    || !filePath
    || startLine === null
    || !severity
    || !message
    || !scannerConfidence
    || !subcategory
    || !likelihood
    || !impact
    || !cwe
    || score === null
  ) {
    return null;
  }

  return {
    scanner,
    fingerprint,
    ruleId,
    filePath,
    startLine,
    severity,
    message,
    scannerConfidence,
    subcategory,
    likelihood,
    impact,
    cwe,
    score,
  };
}

function asString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  return value;
}

function asNumber(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }

  return value;
}

function asStringArray(value: unknown): string[] | null {
  if (!Array.isArray(value)) {
    return null;
  }

  if (!value.every((item) => typeof item === "string")) {
    return null;
  }

  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object";
}
