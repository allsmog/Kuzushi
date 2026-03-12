import type Database from "better-sqlite3";
import { normalizeTaskIds } from "../agents/registry.js";
import type { TaskRegistry } from "../agents/registry.js";
import type { TaskContext as AgentTaskContext } from "../agents/types.js";
import { chainAnalysisTask } from "../agents/tasks/chain-analysis.js";
import type { TaskSelectionResult } from "../agents/tasks/task-selector.js";
import { createDefaultKnowledgeRegistry } from "../knowledge/index.js";
import type { KnowledgeRegistry } from "../knowledge/types.js";
import type { Finding } from "../scanners/types.js";
import { selectTopFindings } from "../scanners/finding-selection.js";
import { HardExclusionFilter } from "../scanners/fp-filter.js";
import { rescoreFindings } from "../scanners/llm-rescore.js";
import type { ScannerRegistry } from "../scanners/registry.js";
import {
  getPocHarnessedFingerprints,
  getStoredTriageResults,
  getStoredVerificationResults,
  getRun,
  getTriagedFingerprints,
  getVerifiedFingerprints,
  updateRunCost,
  updateRunContext,
  updateRunFindings,
  updateRunStatus,
} from "../store.js";
import type {
  ExploitChain,
  KuzushiConfig,
  RepoContext,
  ScanOpts,
  TriageResult,
  VerificationResult,
  Verdict,
} from "../types.js";
import { coerceRepoContext } from "../repo-context.js";
import { loadPrecedents, type Precedents } from "../precedents.js";
import { getTaskOutputMeta } from "../task-output-meta.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../utils.js";
import { runVariantAnalysis } from "./workers/variant-analysis-worker.js";
import type {
  BusHandlerErrorEvent,
  PipelineStats,
  PipelineErrorEvent,
  PipelineStartEvent,
  TaintAnalysisRefinementErrorEvent,
  TaintAnalysisRefinementResultEvent,
  PocHarnessErrorEvent,
  PocHarnessResultEvent,
  ReportCompleteEvent,
  RunContext,
  ScanCompleteEvent,
  ScanFindingEvent,
  TaskCompleteEvent,
  TaskErrorEvent,
  TriageErrorEvent,
  TriageResultEvent,
  VerificationErrorEvent,
  VerificationResultEvent,
} from "./events.js";
import { createEvent } from "./helpers.js";
import type { MessageBus } from "./types.js";

interface QueuedFinding {
  finding: Finding;
  index: number;
  total: number;
}

interface VerificationCandidate {
  finding: Finding;
  triageResult: TriageResult;
}

interface QueuedVerification extends VerificationCandidate {
  index: number;
  total: number;
}

interface PocHarnessCandidate extends VerificationCandidate {
  verificationResult: VerificationResult;
}

interface QueuedPocHarness extends PocHarnessCandidate {
  index: number;
  total: number;
}

interface RunState {
  context: RunContext;
  checkpointRunId: string;
  resuming: boolean;
  config: KuzushiConfig;
  scanOpts: ScanOpts;
  scanners: string[];
  startedAt: string;
  scanFindings: Finding[];
  totalFindings: number;
  skippedAlreadyTriaged: number;
  skippedLowConfidence: number;
  skippedByFpFilter: number;
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
  precedents?: Precedents;
  taskOutputs: Map<string, unknown>;
  failedTasks: string[];
  skippedByLlmRescore: number;
  variantFindings: number;
  variantAnalysisCostUsd: number;
  exploitChains: ExploitChain[];
  chainAnalysisCostUsd: number;
  budgetExceeded: boolean;
}

export interface OrchestratorDeps {
  registry: ScannerRegistry;
  taskRegistry?: TaskRegistry;
  db: Database.Database;
}

type TaskOutcome =
  | { kind: "complete"; event: TaskCompleteEvent }
  | { kind: "error"; event: TaskErrorEvent };

/** Wait for ALL task outcomes (success or error) without aborting early. */
function allSettledCollect(outcomes: Promise<TaskOutcome>[]): Promise<TaskOutcome[]> {
  return Promise.all(outcomes);
}

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

    this.bus.subscribe<VerificationResultEvent>("verification:result", async (event) => {
      await this.handleVerificationResult(event);
    });

    this.bus.subscribe<VerificationErrorEvent>("verification:error", async (event) => {
      await this.handleVerificationError(event);
    });

    this.bus.subscribe<PocHarnessResultEvent>("poc-harness:result", async (event) => {
      await this.handlePocHarnessResult(event);
    });

    this.bus.subscribe<PocHarnessErrorEvent>("poc-harness:error", async (event) => {
      await this.handlePocHarnessError(event);
    });

    this.bus.subscribe<ReportCompleteEvent>("report:complete", async (event) => {
      await this.handleReportComplete(event);
    });

    this.bus.subscribe<TaintAnalysisRefinementResultEvent>("taint-analysis:refinement-result", async (event) => {
      await this.handleTaintAnalysisRefinementResult(event);
    });

    this.bus.subscribe<TaintAnalysisRefinementErrorEvent>("taint-analysis:refinement-error", async (event) => {
      await this.handleTaintAnalysisRefinementError(event);
    });

    this.bus.subscribe<BusHandlerErrorEvent>("bus:handler-error", async (event) => {
      await this.handleBusHandlerError(event);
    });

    this.bus.subscribe<PipelineErrorEvent>("pipeline:error", async (event) => {
      if (!event.payload.fatal) {
        return;
      }
      const state = this.runs.get(event.meta.runId);
      const checkpointRunId = state?.checkpointRunId ?? event.meta.runId;
      try {
        updateRunStatus(this.deps.db, checkpointRunId, "error");
      } catch {
        // Best-effort status persistence for fatal run failures.
      }
      this.runs.delete(event.meta.runId);
    });
  }

  private async handlePipelineStart(event: PipelineStartEvent): Promise<void> {
    const runId = event.meta.runId;
    const {
      context,
      config,
      scanOpts,
      resumeRunId,
    } = event.payload;

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
      checkpointRunId: resumeRunId ?? runId,
      resuming: false,
      config,
      scanOpts,
      scanners,
      startedAt: event.meta.timestamp,
      scanFindings: [],
      totalFindings: 0,
      skippedAlreadyTriaged: 0,
      skippedLowConfidence: 0,
      skippedByFpFilter: 0,
      triageQueue: [],
      queueCursor: 0,
      triageTotal: 0,
      inFlight: 0,
      triaged: 0,
      triageErrors: 0,
      totalCostUsd: 0,
      verifyEnabled: config.verify === true,
      verifyVerdicts: new Set(resolveVerifyVerdicts(config.verifyVerdicts)),
      verifyCandidates: [],
      verifyQueue: [],
      verifyCursor: 0,
      verifyTotal: 0,
      verifyInFlight: 0,
      verified: 0,
      verifyErrors: 0,
      verifyCostUsd: 0,
      verifyDispatching: false,
      verificationStarted: false,
      verificationCompleted: false,
      resumingVerification: false,
      pocHarnessEnabled: config.pocHarness === true,
      pocHarnessCandidates: [],
      pocHarnessQueue: [],
      pocHarnessCursor: 0,
      pocHarnessTotal: 0,
      pocHarnessInFlight: 0,
      pocHarnessGenerated: 0,
      pocHarnessSkipped: 0,
      pocHarnessErrors: 0,
      pocHarnessCostUsd: 0,
      pocHarnessDispatching: false,
      pocHarnessStarted: false,
      reportRequested: false,
      reportEmitted: false,
      refinementEnabled: resolveTaintAnalysisRefinementEnabled(config),
      refinementDeltaOnly: resolveTaintAnalysisRefinementDeltaOnly(config),
      refinementIterations: resolveTaintAnalysisRefinementIterations(config),
      refinementIteration: 0,
      refinementInFlight: false,
      dispatching: false,
      collectScanFindingEvents: !this.deps.taskRegistry && !resumeRunId,
      repoContext: undefined,
      taskOutputs: new Map<string, unknown>(),
      failedTasks: [],
      skippedByLlmRescore: 0,
      variantFindings: 0,
      variantAnalysisCostUsd: 0,
      exploitChains: [],
      chainAnalysisCostUsd: 0,
      budgetExceeded: false,
    };

    // Load organization precedents
    try {
      state.precedents = loadPrecedents(context.repoRoot);
    } catch {
      // Precedents loading is best-effort.
    }

    this.runs.set(runId, state);

    if (resumeRunId) {
      await this.resumeFromCheckpoint(state, runId, resumeRunId);
      return;
    }

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

  private async resumeFromCheckpoint(
    state: RunState,
    runId: string,
    resumeRunId: string,
  ): Promise<void> {
    let run = undefined;
    try {
      run = getRun(this.deps.db, resumeRunId);
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

    if (!run) {
      await this.bus.publish(
        createEvent("pipeline:error", runId, {
          context: state.context,
          error: `No resumable run found for id "${resumeRunId}"`,
          fatal: true,
        }),
      );
      return;
    }

    if (run.repo !== state.context.repoRoot && run.repo !== state.context.repoName) {
      await this.bus.publish(
        createEvent("pipeline:error", runId, {
          context: state.context,
          error: `Run "${resumeRunId}" belongs to repo "${run.repo}", not "${state.context.repoRoot}"`,
          fatal: true,
        }),
      );
      return;
    }

    if (run.status === "complete") {
      await this.bus.publish(
        createEvent("pipeline:error", runId, {
          context: state.context,
          error: `Run "${resumeRunId}" is already complete and cannot be resumed`,
          fatal: true,
        }),
      );
      return;
    }

    if (run.status === "error") {
      await this.bus.publish(
        createEvent("pipeline:error", runId, {
          context: state.context,
          error: `Run "${resumeRunId}" ended in error and cannot be resumed. Re-run without --resume to start fresh.`,
          fatal: true,
        }),
      );
      return;
    }

    try {
      state.scanOpts = parseScanOptsJson(run.scanOptsJson);
    } catch (error) {
      await this.bus.publish(
        createEvent("pipeline:error", runId, {
          context: state.context,
          error: `Run "${resumeRunId}" has invalid scan options checkpoint: ${toErrorMessage(error)}`,
          fatal: true,
        }),
      );
      return;
    }

    state.verifyVerdicts = new Set(
      parseVerifyVerdictsFromConfigJson(run.configJson, [...state.verifyVerdicts]),
    );
    if (run.status === "verifying" || run.status === "poc-harnessing") {
      state.verifyEnabled = true;
    }
    if (run.status === "poc-harnessing") {
      state.pocHarnessEnabled = true;
    }

    if (typeof run.contextJson === "string" && run.contextJson.trim().length > 0) {
      try {
        state.repoContext = coerceRepoContext(JSON.parse(run.contextJson));
      } catch {
        state.repoContext = undefined;
      }
    }

    if (!run.findingsJson) {
      if (run.status === "scanning") {
        state.resuming = false;
        state.scanFindings = [];
        state.collectScanFindingEvents = !this.deps.taskRegistry;

        if (this.deps.taskRegistry) {
          await this.runTaskDag(state, runId);
          return;
        }

        await this.startLegacyScan(state, runId);
        return;
      }

      await this.bus.publish(
        createEvent("pipeline:error", runId, {
          context: state.context,
          error: `Run "${resumeRunId}" has no scan checkpoint. Re-run without --resume to start fresh.`,
          fatal: true,
        }),
      );
      return;
    }

    try {
      const parsed = JSON.parse(run.findingsJson);
      state.scanFindings = coerceFindings(parsed);
      state.totalCostUsd = normalizeCostUsd(run.totalCostUsd);
    } catch (error) {
      await this.bus.publish(
        createEvent("pipeline:error", runId, {
          context: state.context,
          error: `Failed to parse findings checkpoint for run "${resumeRunId}": ${toErrorMessage(error)}`,
          fatal: true,
        }),
      );
      return;
    }

    if (run.status === "verifying") {
      await this.resumeVerificationFromCheckpoint(state, runId);
      return;
    }

    if (run.status === "poc-harnessing") {
      await this.resumePocHarnessFromCheckpoint(state, runId);
      return;
    }

    state.resuming = true;
    await this.handleScanComplete(
      createEvent("scan:complete", runId, {
        context: state.context,
        totalFindings: state.scanFindings.length,
      }),
    );
  }

  private async resumeVerificationFromCheckpoint(state: RunState, runId: string): Promise<void> {
    let verifiedFingerprints = new Set<string>();
    let triageByFingerprint = new Map<string, TriageResult>();

    try {
      verifiedFingerprints = getVerifiedFingerprints(this.deps.db);
      triageByFingerprint = getStoredTriageResults(
        this.deps.db,
        state.scanFindings.map((finding) => finding.fingerprint),
      );
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

    state.totalFindings = state.scanFindings.length;
    state.skippedLowConfidence = 0;
    state.verifyCandidates = [];
    state.verifyQueue = [];
    state.verifyCursor = 0;
    state.verifyInFlight = 0;
    state.verified = 0;
    state.verifyErrors = 0;
    state.verifyCostUsd = 0;
    state.verificationCompleted = false;
    state.resumingVerification = true;
    state.pocHarnessCandidates = [];
    state.pocHarnessQueue = [];
    state.pocHarnessCursor = 0;
    state.pocHarnessTotal = 0;
    state.pocHarnessInFlight = 0;
    state.pocHarnessGenerated = 0;
    state.pocHarnessSkipped = 0;
    state.pocHarnessErrors = 0;
    state.pocHarnessCostUsd = 0;
    state.pocHarnessDispatching = false;
    state.pocHarnessStarted = false;

    const pendingCandidates: VerificationCandidate[] = [];
    for (const finding of state.scanFindings) {
      const triageResult = triageByFingerprint.get(finding.fingerprint);
      if (!triageResult) {
        continue;
      }

      if (!shouldVerifyFinding(state, finding, triageResult)) {
        continue;
      }

      if (verifiedFingerprints.has(finding.fingerprint)) {
        continue;
      }

      pendingCandidates.push({
        finding,
        triageResult,
      });
    }

    state.verifyTotal = pendingCandidates.length;
    state.verifyQueue = pendingCandidates.map((item, idx) => ({
      ...item,
      index: idx + 1,
      total: pendingCandidates.length,
    }));

    await this.startVerification(state, runId);
  }

  private async resumePocHarnessFromCheckpoint(state: RunState, runId: string): Promise<void> {
    let triageByFingerprint = new Map<string, TriageResult>();
    let verificationByFingerprint = new Map<string, VerificationResult>();
    let pocHarnessedFingerprints = new Set<string>();

    try {
      triageByFingerprint = getStoredTriageResults(
        this.deps.db,
        state.scanFindings.map((finding) => finding.fingerprint),
      );
      verificationByFingerprint = getStoredVerificationResults(
        this.deps.db,
        state.scanFindings.map((finding) => finding.fingerprint),
      );
      pocHarnessedFingerprints = getPocHarnessedFingerprints(this.deps.db);
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

    state.totalFindings = state.scanFindings.length;
    state.skippedLowConfidence = 0;
    state.verifyCandidates = [];
    state.verifyQueue = [];
    state.verifyCursor = 0;
    state.verifyInFlight = 0;
    state.verified = 0;
    state.verifyErrors = 0;
    state.verifyCostUsd = 0;
    state.verifyDispatching = false;
    state.verificationStarted = false;
    state.verificationCompleted = true;
    state.resumingVerification = false;
    state.pocHarnessCandidates = [];
    state.pocHarnessQueue = [];
    state.pocHarnessCursor = 0;
    state.pocHarnessTotal = 0;
    state.pocHarnessInFlight = 0;
    state.pocHarnessGenerated = 0;
    state.pocHarnessSkipped = 0;
    state.pocHarnessErrors = 0;
    state.pocHarnessCostUsd = 0;
    state.pocHarnessDispatching = false;
    state.pocHarnessStarted = false;
    state.reportRequested = true;

    const pendingCandidates: PocHarnessCandidate[] = [];
    for (const finding of state.scanFindings) {
      const triageResult = triageByFingerprint.get(finding.fingerprint);
      if (!triageResult) {
        continue;
      }

      if (!shouldVerifyFinding(state, finding, triageResult)) {
        continue;
      }

      const verificationResult = verificationByFingerprint.get(finding.fingerprint);
      if (!verificationResult || !verificationResult.exploitable) {
        continue;
      }

      if (pocHarnessedFingerprints.has(finding.fingerprint)) {
        continue;
      }

      pendingCandidates.push({
        finding,
        triageResult,
        verificationResult,
      });
    }

    state.pocHarnessCandidates = pendingCandidates;
    await this.startPocHarnessGeneration(state, runId);
  }

  private async runTaskDag(state: RunState, runId: string): Promise<void> {
    if (!this.deps.taskRegistry) {
      await this.startLegacyScan(state, runId);
      return;
    }

    const enableContextExplicit = state.config.enableContextGathering !== false
      && this.deps.taskRegistry.has("context-gatherer");
    const candidateIds = normalizeTaskIds([
      ...state.scanners,
      ...(enableContextExplicit ? ["context-gatherer"] : []),
      ...(state.config.enabledTasks ?? []),
      // Auto-add task-selector when dynamic task selection is enabled
      ...(state.config.enableDynamicTaskSelection && this.deps.taskRegistry.has("task-selector")
        ? ["task-selector"]
        : []),
    ]);

    // Auto-inject all transitive dependencies for enabled tasks
    let enabledTaskIds = collectTransitiveDeps(this.deps.taskRegistry, candidateIds);

    // Respect explicit enableContextGathering: false — only remove context-gatherer
    // if no other enabled task depends on it (otherwise DAG resolution would throw).
    if (state.config.enableContextGathering === false && this.deps.taskRegistry) {
      const othersDepend = enabledTaskIds.some(
        (id) =>
          id !== "context-gatherer"
          && this.deps.taskRegistry!.has(id)
          && this.deps.taskRegistry!.get(id).dependsOn.includes("context-gatherer"),
      );
      if (!othersDepend) {
        enabledTaskIds = enabledTaskIds.filter((id) => id !== "context-gatherer");
      }
    }

    // Track already-completed tasks for dynamic re-resolution
    const completedTaskIds = new Set<string>();

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

      const resolved = await allSettledCollect(outcomes);
      const successes = resolved.filter((o) => o.kind === "complete");
      const failures = resolved.filter((o) => o.kind === "error");

      for (const f of failures) {
        const taskId = f.event.payload.taskId;
        const errMsg = f.event.payload.error;
        state.failedTasks.push(taskId);
        console.error(`[orchestrator] Task "${taskId}" failed: ${errMsg}`);
        await this.bus.publish(
          createEvent("pipeline:error", runId, {
            context: state.context,
            error: `Task "${taskId}" failed: ${errMsg}`,
            fatal: false,
          }),
        );
      }

      // Determine if this stage has any findings-producing tasks
      const stageHasFindingsProducers = group.some((taskId) => {
        const task = this.deps.taskRegistry!.get(taskId);
        return task.outputKind === "findings" || task.outputKind === "threat-model";
      });

      if (successes.length === 0 && failures.length > 0) {
        if (stageHasFindingsProducers) {
          // All findings producers failed — fatal, nothing to triage
          await this.bus.publish(
            createEvent("pipeline:error", runId, {
              context: state.context,
              error: `All tasks in stage ${stageIndex} failed: ${failures.map((f) => f.event.payload.taskId).join(", ")}`,
              fatal: true,
            }),
          );
          return;
        }
        // Non-findings stage fully failed — continue with empty upstream outputs
        console.error(`[orchestrator] Stage ${stageIndex} (non-findings) fully failed, continuing`);
      }

      for (const outcome of successes) {
        if (outcome.kind === "complete") {
          const { taskId, outputKind, output, costUsd } = outcome.event.payload;
          state.taskOutputs.set(taskId, output);
          completedTaskIds.add(taskId);

          // Accumulate scan-phase task LLM costs
          const normalizedCost = normalizeCostUsd(costUsd);
          if (normalizedCost > 0) {
            state.totalCostUsd += normalizedCost;
            try {
              updateRunCost(this.deps.db, state.checkpointRunId, normalizedCost);
            } catch { /* best-effort cost persistence */ }
          }

          if (outputKind === "findings") {
            state.scanFindings.push(...coerceFindings(output));
          } else if (outputKind === "threat-model") {
            if (isRecord(output) && Array.isArray(output["findings"])) {
              state.scanFindings.push(...coerceFindings(output["findings"]));
            }
          }
        }
      }

      // Dynamic task selection: check if any completed task produced a TaskSelectionResult
      // (duck-type check: has recommendedTasks array). If so, merge and re-resolve.
      if (state.config.enableDynamicTaskSelection) {
        const dynamicTasks = this.extractDynamicTasks(state, completedTaskIds);
        if (dynamicTasks.length > 0) {
          const newTaskIds = dynamicTasks.filter(
            (id) =>
              !enabledTaskIds.includes(id)
              && this.deps.taskRegistry!.has(id),
          );

          if (newTaskIds.length > 0) {
            console.error(
              `[orchestrator] Dynamic task selection added: ${newTaskIds.join(", ")}`,
            );
            enabledTaskIds = [
              ...enabledTaskIds,
              ...collectTransitiveDeps(this.deps.taskRegistry, newTaskIds)
                .filter((id) => !enabledTaskIds.includes(id)),
            ];

            // Re-resolve remaining stages
            try {
              const fullStages = this.deps.taskRegistry.resolveOrder(enabledTaskIds);
              // Replace remaining stages — skip stages already completed
              const remaining = fullStages.filter((stage) =>
                stage.some((id) => !completedTaskIds.has(id)),
              ).map((stage) => stage.filter((id) => !completedTaskIds.has(id)));
              stages = [
                ...stages.slice(0, stageIndex + 1),
                ...remaining,
              ];
            } catch (error) {
              console.error(
                `[orchestrator] Dynamic DAG re-resolution failed: ${toErrorMessage(error)}`,
              );
            }
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

    const gatheredContext = coerceRepoContext(state.taskOutputs.get("context-gatherer"));
    if (gatheredContext) {
      state.repoContext = gatheredContext;
      try {
        updateRunContext(this.deps.db, state.checkpointRunId, gatheredContext);
      } catch {
        // Context checkpoint persistence is best-effort.
      }
    }

    await this.bus.publish(
      createEvent("scan:complete", runId, {
        context: state.context,
        totalFindings: state.scanFindings.length,
      }),
    );
  }

  /**
   * Duck-type check: extract recommended tasks from any completed task
   * that produced a TaskSelectionResult (has `recommendedTasks` array).
   */
  private extractDynamicTasks(
    state: RunState,
    completedTaskIds: Set<string>,
  ): string[] {
    const dynamicTasks: string[] = [];
    for (const taskId of completedTaskIds) {
      const output = state.taskOutputs.get(taskId);
      if (
        isRecord(output)
        && Array.isArray(output["recommendedTasks"])
      ) {
        const recommended = output["recommendedTasks"] as unknown[];
        for (const t of recommended) {
          if (typeof t === "string" && t.trim()) {
            dynamicTasks.push(t.trim());
          }
        }
      }
    }
    return dynamicTasks;
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

    const rankedFindings = state.resuming
      ? [...state.scanFindings]
      : selectTopFindings(state.scanFindings, state.scanOpts.maxFindings);
    state.scanFindings = rankedFindings;
    state.totalFindings = rankedFindings.length;

    if (!state.resuming) {
      try {
        updateRunStatus(this.deps.db, state.checkpointRunId, "triaging");
        updateRunFindings(this.deps.db, state.checkpointRunId, rankedFindings);
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

    // Apply FP filter before triage queue
    let filteredFindings = rankedFindings;
    state.skippedByFpFilter = 0;
    if (state.config.fpFilterEnabled !== false) {
      const customExclusions = [
        ...(state.config.fpFilterCustomExclusions ?? []),
        ...(state.precedents?.hardExclusions ?? []),
      ];
      const fpFilter = new HardExclusionFilter(customExclusions);
      const filterResult = fpFilter.filterFindings(rankedFindings);
      filteredFindings = filterResult.kept;
      state.skippedByFpFilter = filterResult.excluded.length;
      if (filterResult.excluded.length > 0) {
        console.error(`[fp-filter] Excluded ${filterResult.excluded.length} findings`);
      }
    }

    // LLM rescore: two-stage filtering with cheap model
    state.skippedByLlmRescore = 0;
    if (state.config.llmRescoreEnabled) {
      const rescoreResults = await rescoreFindings(filteredFindings, {
        model: state.config.llmRescoreModel,
        threshold: state.config.llmRescoreThreshold,
        repoRoot: state.context.repoRoot,
      });
      const keptFingerprints = new Set(
        rescoreResults.filter((r) => r.keep).map((r) => r.fingerprint),
      );
      const before = filteredFindings.length;
      filteredFindings = filteredFindings.filter(
        (f) => keptFingerprints.has(f.fingerprint),
      );
      state.skippedByLlmRescore = before - filteredFindings.length;
      if (state.skippedByLlmRescore > 0) {
        console.error(`[llm-rescore] Excluded ${state.skippedByLlmRescore} findings`);
      }
    }

    // Priority sort: highest-score findings first for budget-limited runs
    if (state.config.prioritizeFindings !== false) {
      filteredFindings.sort((a, b) => b.score - a.score);
    }

    const triageCandidates = filteredFindings.filter(
      (finding) => !alreadyTriaged.has(finding.fingerprint),
    );

    state.skippedAlreadyTriaged = filteredFindings.length - triageCandidates.length;
    state.triageTotal = triageCandidates.length;
    state.triageQueue = triageCandidates.map((finding, idx) => ({
      finding,
      index: idx + 1,
      total: triageCandidates.length,
    }));
    state.queueCursor = 0;
    state.verifyCandidates = [];
    state.verifyQueue = [];
    state.verifyCursor = 0;
    state.verifyTotal = 0;
    state.verifyInFlight = 0;
    state.verified = 0;
    state.verifyErrors = 0;
    state.verifyCostUsd = 0;
    state.skippedLowConfidence = 0;
    state.verifyDispatching = false;
    state.verificationStarted = false;
    state.verificationCompleted = false;
    state.resumingVerification = false;
    state.pocHarnessEnabled = state.config.pocHarness === true;
    state.pocHarnessCandidates = [];
    state.pocHarnessQueue = [];
    state.pocHarnessCursor = 0;
    state.pocHarnessTotal = 0;
    state.pocHarnessInFlight = 0;
    state.pocHarnessGenerated = 0;
    state.pocHarnessSkipped = 0;
    state.pocHarnessErrors = 0;
    state.pocHarnessCostUsd = 0;
    state.pocHarnessDispatching = false;
    state.pocHarnessStarted = false;
    state.reportRequested = false;
    state.reportEmitted = false;
    state.refinementEnabled = resolveTaintAnalysisRefinementEnabled(state.config);
    state.refinementDeltaOnly = resolveTaintAnalysisRefinementDeltaOnly(state.config);
    state.refinementIterations = resolveTaintAnalysisRefinementIterations(state.config);
    state.refinementIteration = 0;
    state.refinementInFlight = false;

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

    await this.dispatchTriageBatch(state, runId, triageCandidates);
  }

  private async handleTriageResult(event: TriageResultEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    state.inFlight = Math.max(0, state.inFlight - 1);
    state.triaged += 1;
    const costUsd = normalizeCostUsd(event.payload.costUsd);
    state.totalCostUsd += costUsd;

    if (shouldVerifyFinding(state, event.payload.finding, event.payload.result)) {
      state.verifyCandidates.push({
        finding: event.payload.finding,
        triageResult: event.payload.result,
      });
    }

    try {
      updateRunCost(this.deps.db, state.checkpointRunId, costUsd);
    } catch {
      // Cost persistence is best-effort and should not fail the run.
    }

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
    const costUsd = normalizeCostUsd(event.payload.costUsd);
    state.totalCostUsd += costUsd;

    try {
      updateRunCost(this.deps.db, state.checkpointRunId, costUsd);
    } catch {
      // Cost persistence is best-effort and should not fail the run.
    }

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

    try {
      updateRunStatus(this.deps.db, state.checkpointRunId, "complete", {
        completedAt: event.meta.timestamp,
      });
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

    await this.bus.publish(
      createEvent("pipeline:complete", runId, {
        context: state.context,
        stats: {
          scanners: [...state.scanners],
          totalFindings: state.totalFindings,
          queuedForTriage: state.triageTotal,
          skippedAlreadyTriaged: state.skippedAlreadyTriaged,
          skippedLowConfidence: state.verifyEnabled ? state.skippedLowConfidence : undefined,
          skippedByFpFilter: state.skippedByFpFilter > 0 ? state.skippedByFpFilter : undefined,
          skippedByLlmRescore: state.skippedByLlmRescore > 0 ? state.skippedByLlmRescore : undefined,
          triaged: state.triaged,
          triageErrors: state.triageErrors,
          totalCostUsd: state.totalCostUsd,
          verified: state.verifyEnabled ? state.verified : undefined,
          verifyErrors: state.verifyEnabled ? state.verifyErrors : undefined,
          verifyCostUsd: state.verifyEnabled ? state.verifyCostUsd : undefined,
          pocHarnessGenerated: state.pocHarnessEnabled ? state.pocHarnessGenerated : undefined,
          pocHarnessSkipped: state.pocHarnessEnabled ? state.pocHarnessSkipped : undefined,
          pocHarnessErrors: state.pocHarnessEnabled ? state.pocHarnessErrors : undefined,
          pocHarnessCostUsd: state.pocHarnessEnabled ? state.pocHarnessCostUsd : undefined,
          variantFindings: state.variantFindings > 0 ? state.variantFindings : undefined,
          variantAnalysisCostUsd: state.variantAnalysisCostUsd > 0 ? state.variantAnalysisCostUsd : undefined,
          chainCount: state.exploitChains.length > 0 ? state.exploitChains.length : undefined,
          chainAnalysisCostUsd: state.chainAnalysisCostUsd > 0 ? state.chainAnalysisCostUsd : undefined,
          budgetExceeded: state.budgetExceeded || undefined,
          startedAt: state.startedAt,
          completedAt: event.meta.timestamp,
        },
      }),
    );

    this.runs.delete(runId);
  }

  private async handleTaintAnalysisRefinementResult(event: TaintAnalysisRefinementResultEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    state.refinementInFlight = false;
    state.refinementIteration = Math.max(state.refinementIteration, event.payload.iteration);

    const nonTaintAnalysis = state.scanFindings.filter((finding) => finding.scanner !== "taint-analysis-run");
    state.scanFindings = [...nonTaintAnalysis, ...event.payload.updatedFindings]
      .sort((a, b) => b.score - a.score);
    state.totalFindings = state.scanFindings.length;
    state.triaged += event.payload.deltaTriaged;
    state.triageErrors += event.payload.deltaErrors;
    state.triageTotal += event.payload.deltaFindings.length;
    state.totalCostUsd += normalizeCostUsd(event.payload.triageCostUsd);

    try {
      updateRunFindings(this.deps.db, state.checkpointRunId, state.scanFindings);
      updateRunCost(this.deps.db, state.checkpointRunId, event.payload.triageCostUsd);
    } catch {
      // Checkpoint persistence is best-effort for refinement deltas.
    }

    if (
      state.refinementIteration < state.refinementIterations
      && event.payload.deltaFindings.length > 0
      && this.shouldRunTaintAnalysisRefinement(state)
    ) {
      await this.startTaintAnalysisRefinement(state, runId);
      return;
    }

    await this.requestPostTriageFlow(state, runId);
  }

  private async handleTaintAnalysisRefinementError(event: TaintAnalysisRefinementErrorEvent): Promise<void> {
    const state = this.runs.get(event.meta.runId);
    if (!state) {
      return;
    }

    state.refinementInFlight = false;
    state.refinementIteration = Math.max(state.refinementIteration, event.payload.iteration);
    await this.requestPostTriageFlow(state, event.meta.runId);
  }

  private async handleBusHandlerError(event: BusHandlerErrorEvent): Promise<void> {
    const state = this.runs.get(event.meta.runId);
    if (!state) {
      return;
    }

    // Non-critical source events (report output, audit logging, artifact persistence)
    // should not kill the entire pipeline.
    const nonFatalSources = new Set([
      "report:requested",
      "report:complete",
      "store:upserted",
      "triage:agent-activity",
      "verification:agent-activity",
      "poc-harness:agent-activity",
    ]);
    const fatal = !nonFatalSources.has(event.payload.sourceEventType);

    await this.bus.publish(
      createEvent("pipeline:error", event.meta.runId, {
        context: state.context,
        error: `Bus handler failure on ${event.payload.sourceEventType}: ${event.payload.error}`,
        fatal,
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
        if (this.isBudgetExceeded(state)) {
          await this.emitBudgetExceeded(state, runId);
          break;
        }
        const item = state.triageQueue[state.queueCursor];
        state.queueCursor += 1;
        state.inFlight += 1;

        await this.bus.publish(
          createEvent("triage:finding-queued", runId, {
            context: state.context,
            finding: item.finding,
            repoContext: state.repoContext,
            precedents: state.precedents,
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

  private async dispatchTriageBatch(
    state: RunState,
    runId: string,
    findings: Finding[],
  ): Promise<void> {
    state.inFlight = findings.length;
    state.queueCursor = findings.length;

    await this.bus.publish(
      createEvent("triage:batch-queued", runId, {
        context: state.context,
        findings,
        repoContext: state.repoContext,
        precedents: state.precedents,
        total: findings.length,
      }),
    );

    await this.publishQueueDepth(state, runId);
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
    if (state.reportRequested || state.refinementInFlight) {
      console.error(
        `[orchestrator] finishTriageAndRequestReport skipped: reportRequested=${state.reportRequested}, refinementInFlight=${state.refinementInFlight}`,
      );
      return;
    }

    await this.bus.publish(
      createEvent("triage:complete", runId, {
        context: state.context,
        triaged: state.triaged,
        errors: state.triageErrors,
        totalCostUsd: state.totalCostUsd,
      }),
    );

    if (this.shouldRunTaintAnalysisRefinement(state)) {
      await this.startTaintAnalysisRefinement(state, runId);
      return;
    }

    await this.requestPostTriageFlow(state, runId);
  }

  private async requestPostTriageFlow(state: RunState, runId: string): Promise<void> {
    if (state.reportRequested) {
      console.error("[orchestrator] requestPostTriageFlow skipped: reportRequested=true");
      return;
    }

    // Variant analysis phase (runs before verification)
    if (state.config.variantAnalysis) {
      const confirmedTPs = this.collectConfirmedTPs(state);
      if (confirmedTPs.length > 0) {
        const model = state.config.variantAnalysisModel || state.config.model;
        await this.bus.publish(
          createEvent("variant-analysis:start", runId, {
            context: state.context,
            confirmedCount: confirmedTPs.length,
            model,
          }),
        );
        try {
          const result = await runVariantAnalysis(confirmedTPs, state.context, state.config);
          state.variantFindings = result.findings.length;
          state.variantAnalysisCostUsd = result.costUsd;
          state.totalCostUsd += result.costUsd;
          updateRunCost(this.deps.db, state.checkpointRunId, state.totalCostUsd);
        } catch (error) {
          console.error(`[orchestrator] Variant analysis error: ${toErrorMessage(error)}`);
        }
        await this.bus.publish(
          createEvent("variant-analysis:complete", runId, {
            context: state.context,
            variantFindings: state.variantFindings,
            costUsd: state.variantAnalysisCostUsd,
          }),
        );
      }
    }

    // Chain analysis phase
    if (state.config.chainAnalysis) {
      const confirmedTPs = this.collectConfirmedTPs(state);
      if (confirmedTPs.length >= 2) {
        const model = state.config.chainAnalysisModel || state.config.model;
        await this.bus.publish(
          createEvent("chain-analysis:start", runId, {
            context: state.context,
            confirmedCount: confirmedTPs.length,
            model,
          }),
        );
        try {
          const taskContext: AgentTaskContext = {
            runId,
            repoRoot: state.context.repoRoot,
            repoName: state.context.repoName,
            config: state.config,
            bus: this.bus,
            upstreamOutputs: state.taskOutputs,
          };
          const output = await chainAnalysisTask.run(
            { confirmedFindings: confirmedTPs },
            taskContext,
          );
          state.exploitChains = output.chains;
          const chainMeta = getTaskOutputMeta(output);
          if (chainMeta?.costUsd) {
            state.chainAnalysisCostUsd = chainMeta.costUsd;
            state.totalCostUsd += chainMeta.costUsd;
            updateRunCost(this.deps.db, state.checkpointRunId, state.totalCostUsd);
          }
        } catch (error) {
          console.error(`[orchestrator] Chain analysis error: ${toErrorMessage(error)}`);
        }
        await this.bus.publish(
          createEvent("chain-analysis:complete", runId, {
            context: state.context,
            chainCount: state.exploitChains.length,
            costUsd: state.chainAnalysisCostUsd,
          }),
        );
      }
    }

    state.reportRequested = true;

    if (state.verifyEnabled) {
      console.error(
        `[orchestrator] verification enabled — ${state.verifyCandidates.length} candidates, starting verification`,
      );
      await this.startVerification(state, runId);
      return;
    }

    console.error("[orchestrator] verification disabled — requesting report directly");

    await this.bus.publish(
      createEvent("report:requested", runId, {
        context: state.context,
        stats: buildReportStats(state),
        fingerprints: state.scanFindings.map((f) => f.fingerprint),
        exploitChains: state.exploitChains.length > 0 ? state.exploitChains : undefined,
      }),
    );

    state.reportEmitted = true;
  }

  private collectConfirmedTPs(state: RunState): Array<{ finding: Finding; triageResult: TriageResult }> {
    const fingerprints = state.scanFindings.map((f) => f.fingerprint);
    const triageResults = getStoredTriageResults(this.deps.db, fingerprints);
    const confirmed: Array<{ finding: Finding; triageResult: TriageResult }> = [];
    for (const finding of state.scanFindings) {
      const tr = triageResults.get(finding.fingerprint);
      if (tr && tr.verdict === "tp") {
        confirmed.push({ finding, triageResult: tr });
      }
    }
    return confirmed;
  }

  private isBudgetExceeded(state: RunState): boolean {
    const budget = state.config.costBudgetUsd;
    return typeof budget === "number" && budget > 0 && state.totalCostUsd >= budget;
  }

  private async emitBudgetExceeded(state: RunState, runId: string): Promise<void> {
    if (state.budgetExceeded) return;
    state.budgetExceeded = true;
    const budget = state.config.costBudgetUsd!;
    console.error(`[orchestrator] Budget exceeded: $${state.totalCostUsd.toFixed(4)} >= $${budget.toFixed(4)}`);
    await this.bus.publish(
      createEvent("budget:exceeded", runId, {
        context: state.context,
        totalCostUsd: state.totalCostUsd,
        budgetUsd: budget,
      }),
    );
  }

  private shouldRunTaintAnalysisRefinement(state: RunState): boolean {
    if (!state.refinementEnabled || state.refinementInFlight) {
      return false;
    }
    if (state.refinementIteration >= state.refinementIterations) {
      return false;
    }
    if (!state.taskOutputs.has("taint-analysis-label")) {
      return false;
    }
    return state.scanFindings.some((finding) => finding.scanner === "taint-analysis-run");
  }

  private async startTaintAnalysisRefinement(state: RunState, runId: string): Promise<void> {
    if (state.refinementInFlight) {
      return;
    }

    state.refinementInFlight = true;
    const nextIteration = state.refinementIteration + 1;
    const refinementModel = resolveTaintAnalysisRefinementModel(state.config);

    await this.bus.publish(
      createEvent("taint-analysis:refinement-start", runId, {
        context: state.context,
        model: refinementModel,
        iteration: nextIteration,
        totalIterations: state.refinementIterations,
        findings: [...state.scanFindings],
        labelOutput: state.taskOutputs.get("taint-analysis-label"),
        repoContext: state.repoContext,
        refinementDeltaOnly: state.refinementDeltaOnly,
      }),
    );
  }

  private async startVerification(state: RunState, runId: string): Promise<void> {
    if (state.verificationStarted || state.reportEmitted) {
      console.error(
        `[orchestrator] startVerification skipped: verificationStarted=${state.verificationStarted}, reportEmitted=${state.reportEmitted}`,
      );
      return;
    }

    state.verificationCompleted = false;

    if (!state.resumingVerification) {
      state.verifyTotal = state.verifyCandidates.length;
      state.verifyQueue = state.verifyCandidates.map((item, idx) => ({
        ...item,
        index: idx + 1,
        total: state.verifyCandidates.length,
      }));
      state.verifyCursor = 0;
    }

    if (!state.resumingVerification) {
      try {
        updateRunStatus(this.deps.db, state.checkpointRunId, "verifying");
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

    await this.bus.publish(
      createEvent("verification:start", runId, {
        context: state.context,
        findingCount: state.verifyTotal,
        model: state.config.verifyModel ?? state.config.triageModel ?? state.config.model,
      }),
    );

    state.verificationStarted = true;
    await this.publishVerificationQueueDepth(state, runId);

    if (state.verifyTotal === 0) {
      await this.finishVerificationAndRequestReport(state, runId);
      return;
    }

    await this.dispatchVerification(state, runId);
  }

  private async handleVerificationResult(event: VerificationResultEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    state.verifyInFlight = Math.max(0, state.verifyInFlight - 1);
    state.verified += 1;
    const costUsd = normalizeCostUsd(event.payload.costUsd);
    state.totalCostUsd += costUsd;
    state.verifyCostUsd += costUsd;

    if (event.payload.result.exploitable) {
      state.pocHarnessCandidates.push({
        finding: event.payload.finding,
        triageResult: event.payload.triageResult,
        verificationResult: event.payload.result,
      });
    }

    try {
      updateRunCost(this.deps.db, state.checkpointRunId, costUsd);
    } catch {
      // Cost persistence is best-effort and should not fail the run.
    }

    await this.publishVerificationQueueDepth(state, runId);

    if (this.isVerificationDone(state)) {
      await this.finishVerificationAndRequestReport(state, runId);
      return;
    }

    await this.dispatchVerification(state, runId);
  }

  private async handleVerificationError(event: VerificationErrorEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    state.verifyInFlight = Math.max(0, state.verifyInFlight - 1);
    state.verifyErrors += 1;
    const costUsd = normalizeCostUsd(event.payload.costUsd);
    state.totalCostUsd += costUsd;
    state.verifyCostUsd += costUsd;

    try {
      updateRunCost(this.deps.db, state.checkpointRunId, costUsd);
    } catch {
      // Cost persistence is best-effort and should not fail the run.
    }

    await this.publishVerificationQueueDepth(state, runId);

    if (this.isVerificationDone(state)) {
      await this.finishVerificationAndRequestReport(state, runId);
      return;
    }

    await this.dispatchVerification(state, runId);
  }

  private async dispatchVerification(state: RunState, runId: string): Promise<void> {
    if (state.verifyDispatching) {
      return;
    }

    state.verifyDispatching = true;
    try {
      const concurrency = normalizeConcurrency(state.config.verifyConcurrency ?? 1);

      while (state.verifyInFlight < concurrency && state.verifyCursor < state.verifyQueue.length) {
        if (this.isBudgetExceeded(state)) {
          await this.emitBudgetExceeded(state, runId);
          break;
        }
        const item = state.verifyQueue[state.verifyCursor];
        state.verifyCursor += 1;
        state.verifyInFlight += 1;

        await this.bus.publish(
          createEvent("verification:finding-queued", runId, {
            context: state.context,
            finding: item.finding,
            triageResult: item.triageResult,
            repoContext: state.repoContext,
            precedents: state.precedents,
            index: item.index,
            total: item.total,
          }),
        );
      }

      await this.publishVerificationQueueDepth(state, runId);
    } finally {
      state.verifyDispatching = false;
    }
  }

  private isVerificationDone(state: RunState): boolean {
    const processed = state.verified + state.verifyErrors;
    return (
      state.verifyTotal > 0
      && processed >= state.verifyTotal
      && state.verifyInFlight === 0
      && !state.reportEmitted
    );
  }

  private async finishVerificationAndRequestReport(state: RunState, runId: string): Promise<void> {
    if (state.reportEmitted || state.verificationCompleted) {
      return;
    }
    state.verificationCompleted = true;

    await this.bus.publish(
      createEvent("verification:complete", runId, {
        context: state.context,
        verified: state.verified,
        errors: state.verifyErrors,
        totalCostUsd: state.verifyCostUsd,
      }),
    );

    if (state.pocHarnessEnabled && state.pocHarnessCandidates.length > 0) {
      await this.startPocHarnessGeneration(state, runId);
      return;
    }

    await this.bus.publish(
      createEvent("report:requested", runId, {
        context: state.context,
        stats: buildReportStats(state),
        fingerprints: state.scanFindings.map((f) => f.fingerprint),
        exploitChains: state.exploitChains.length > 0 ? state.exploitChains : undefined,
      }),
    );

    state.reportRequested = true;
    state.reportEmitted = true;
  }

  private async startPocHarnessGeneration(state: RunState, runId: string): Promise<void> {
    if (state.pocHarnessStarted || state.reportEmitted) {
      return;
    }

    state.pocHarnessTotal = state.pocHarnessCandidates.length;
    state.pocHarnessQueue = state.pocHarnessCandidates.map((item, idx) => ({
      ...item,
      index: idx + 1,
      total: state.pocHarnessCandidates.length,
    }));
    state.pocHarnessCursor = 0;

    try {
      updateRunStatus(this.deps.db, state.checkpointRunId, "poc-harnessing");
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

    await this.bus.publish(
      createEvent("poc-harness:start", runId, {
        context: state.context,
        findingCount: state.pocHarnessTotal,
        model: state.config.pocHarnessModel
          ?? state.config.verifyModel
          ?? state.config.triageModel
          ?? state.config.model,
      }),
    );

    state.pocHarnessStarted = true;
    await this.publishPocHarnessQueueDepth(state, runId);

    if (state.pocHarnessTotal === 0) {
      await this.finishPocHarnessAndRequestReport(state, runId);
      return;
    }

    await this.dispatchPocHarness(state, runId);
  }

  private async handlePocHarnessResult(event: PocHarnessResultEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    state.pocHarnessInFlight = Math.max(0, state.pocHarnessInFlight - 1);
    if (event.payload.result.skipped) {
      state.pocHarnessSkipped += 1;
    } else {
      state.pocHarnessGenerated += 1;
    }
    const costUsd = normalizeCostUsd(event.payload.costUsd);
    state.totalCostUsd += costUsd;
    state.pocHarnessCostUsd += costUsd;

    try {
      updateRunCost(this.deps.db, state.checkpointRunId, costUsd);
    } catch {
      // Cost persistence is best-effort and should not fail the run.
    }

    // Queue PoC execution if enabled and harness was successfully generated
    if (
      state.config.pocExecute
      && !event.payload.result.skipped
      && event.payload.result.parsed
      && event.payload.result.scriptPath
      && event.payload.result.language
    ) {
      await this.bus.publish(
        createEvent("poc-execution:queued", runId, {
          context: state.context,
          fingerprint: event.payload.result.fingerprint,
          scriptPath: event.payload.result.scriptPath,
          language: event.payload.result.language,
        }),
      );
    }

    await this.publishPocHarnessQueueDepth(state, runId);

    if (this.isPocHarnessDone(state)) {
      await this.finishPocHarnessAndRequestReport(state, runId);
      return;
    }

    await this.dispatchPocHarness(state, runId);
  }

  private async handlePocHarnessError(event: PocHarnessErrorEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    state.pocHarnessInFlight = Math.max(0, state.pocHarnessInFlight - 1);
    state.pocHarnessErrors += 1;
    const costUsd = normalizeCostUsd(event.payload.costUsd);
    state.totalCostUsd += costUsd;
    state.pocHarnessCostUsd += costUsd;

    try {
      updateRunCost(this.deps.db, state.checkpointRunId, costUsd);
    } catch {
      // Cost persistence is best-effort and should not fail the run.
    }

    await this.publishPocHarnessQueueDepth(state, runId);

    if (this.isPocHarnessDone(state)) {
      await this.finishPocHarnessAndRequestReport(state, runId);
      return;
    }

    await this.dispatchPocHarness(state, runId);
  }

  private async dispatchPocHarness(state: RunState, runId: string): Promise<void> {
    if (state.pocHarnessDispatching) {
      return;
    }

    state.pocHarnessDispatching = true;
    try {
      const concurrency = normalizeConcurrency(state.config.pocHarnessConcurrency ?? 1);

      while (
        state.pocHarnessInFlight < concurrency
        && state.pocHarnessCursor < state.pocHarnessQueue.length
      ) {
        if (this.isBudgetExceeded(state)) {
          await this.emitBudgetExceeded(state, runId);
          break;
        }
        const item = state.pocHarnessQueue[state.pocHarnessCursor];
        state.pocHarnessCursor += 1;
        state.pocHarnessInFlight += 1;

        await this.bus.publish(
          createEvent("poc-harness:finding-queued", runId, {
            context: state.context,
            finding: item.finding,
            triageResult: item.triageResult,
            verificationResult: item.verificationResult,
            repoContext: state.repoContext,
            index: item.index,
            total: item.total,
          }),
        );
      }

      await this.publishPocHarnessQueueDepth(state, runId);
    } finally {
      state.pocHarnessDispatching = false;
    }
  }

  private isPocHarnessDone(state: RunState): boolean {
    const processed = state.pocHarnessGenerated + state.pocHarnessSkipped + state.pocHarnessErrors;
    return (
      state.pocHarnessTotal > 0
      && processed >= state.pocHarnessTotal
      && state.pocHarnessInFlight === 0
      && !state.reportEmitted
    );
  }

  private async finishPocHarnessAndRequestReport(state: RunState, runId: string): Promise<void> {
    if (state.reportEmitted) {
      return;
    }

    await this.bus.publish(
      createEvent("poc-harness:complete", runId, {
        context: state.context,
        generated: state.pocHarnessGenerated,
        skipped: state.pocHarnessSkipped,
        errors: state.pocHarnessErrors,
        totalCostUsd: state.pocHarnessCostUsd,
      }),
    );

    await this.bus.publish(
      createEvent("report:requested", runId, {
        context: state.context,
        stats: buildReportStats(state),
        fingerprints: state.scanFindings.map((f) => f.fingerprint),
        exploitChains: state.exploitChains.length > 0 ? state.exploitChains : undefined,
      }),
    );

    state.reportRequested = true;
    state.reportEmitted = true;
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

  private async publishVerificationQueueDepth(state: RunState, runId: string): Promise<void> {
    const queued = Math.max(0, state.verifyQueue.length - state.verifyCursor);
    const processed = state.verified + state.verifyErrors;

    await this.bus.publish(
      createEvent("verification:queue-depth", runId, {
        context: state.context,
        queued,
        inFlight: state.verifyInFlight,
        processed,
        total: state.verifyTotal,
      }),
    );
  }

  private async publishPocHarnessQueueDepth(state: RunState, runId: string): Promise<void> {
    const queued = Math.max(0, state.pocHarnessQueue.length - state.pocHarnessCursor);
    const processed = state.pocHarnessGenerated + state.pocHarnessSkipped + state.pocHarnessErrors;

    await this.bus.publish(
      createEvent("poc-harness:queue-depth", runId, {
        context: state.context,
        queued,
        inFlight: state.pocHarnessInFlight,
        processed,
        total: state.pocHarnessTotal,
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

function buildReportStats(state: RunState): Partial<PipelineStats> {
  let extractionDegradation: PipelineStats["extractionDegradation"];
  let tiPriorDegraded: boolean | undefined;
  const preflightOutput = state.taskOutputs.get("taint-analysis-preflight");
  if (isRecord(preflightOutput)) {
    if (
      isRecord(preflightOutput["extractionDegradation"])
      && typeof preflightOutput["extractionDegradation"]["status"] === "string"
      && preflightOutput["extractionDegradation"]["status"] !== "ok"
    ) {
      const deg = preflightOutput["extractionDegradation"];
      extractionDegradation = {
        status: deg["status"] as string,
        reasons: Array.isArray(deg["reasons"]) ? (deg["reasons"] as unknown[]).filter((r): r is string => typeof r === "string") : [],
      };
    }
    if (preflightOutput["tiPriorDegraded"] === true) {
      tiPriorDegraded = true;
    }
  }

  let stitchDegradation: PipelineStats["stitchDegradation"];
  const stitchOutput = state.taskOutputs.get("taint-analysis-stitch");
  const stitchMeta = getTaskOutputMeta(stitchOutput);
  if (stitchMeta?.degradation && stitchMeta.degradation.type === "stitch-degradation") {
    stitchDegradation = {
      type: stitchMeta.degradation.type,
      reason: stitchMeta.degradation.reason,
      message: stitchMeta.degradation.message,
    };
  }

  return {
    scanners: [...state.scanners],
    totalFindings: state.totalFindings,
    queuedForTriage: state.triageTotal,
    skippedAlreadyTriaged: state.skippedAlreadyTriaged,
    skippedLowConfidence: state.verifyEnabled ? state.skippedLowConfidence : undefined,
    skippedByFpFilter: state.skippedByFpFilter > 0 ? state.skippedByFpFilter : undefined,
    skippedByLlmRescore: state.skippedByLlmRescore > 0 ? state.skippedByLlmRescore : undefined,
    triaged: state.triaged,
    triageErrors: state.triageErrors,
    totalCostUsd: state.totalCostUsd,
    verified: state.verifyEnabled ? state.verified : undefined,
    verifyErrors: state.verifyEnabled ? state.verifyErrors : undefined,
    verifyCostUsd: state.verifyEnabled ? state.verifyCostUsd : undefined,
    pocHarnessGenerated: state.pocHarnessEnabled ? state.pocHarnessGenerated : undefined,
    pocHarnessSkipped: state.pocHarnessEnabled ? state.pocHarnessSkipped : undefined,
    pocHarnessErrors: state.pocHarnessEnabled ? state.pocHarnessErrors : undefined,
    pocHarnessCostUsd: state.pocHarnessEnabled ? state.pocHarnessCostUsd : undefined,
    variantFindings: state.variantFindings > 0 ? state.variantFindings : undefined,
    variantAnalysisCostUsd: state.variantAnalysisCostUsd > 0 ? state.variantAnalysisCostUsd : undefined,
    chainCount: state.exploitChains.length > 0 ? state.exploitChains.length : undefined,
    chainAnalysisCostUsd: state.chainAnalysisCostUsd > 0 ? state.chainAnalysisCostUsd : undefined,
    budgetExceeded: state.budgetExceeded || undefined,
    failedTasks: state.failedTasks.length > 0 ? [...state.failedTasks] : undefined,
    extractionDegradation,
    stitchDegradation,
    tiPriorDegraded,
    startedAt: state.startedAt,
    completedAt: new Date().toISOString(),
  };
}

function resolveTaintAnalysisConfig(config: KuzushiConfig): Record<string, unknown> {
  const raw = config.scannerConfig["taint-analysis"];
  return isRecord(raw) ? raw : {};
}

function resolveTaintAnalysisRefinementEnabled(config: KuzushiConfig): boolean {
  const taintAnalysis = resolveTaintAnalysisConfig(config);
  return taintAnalysis["refinementEnabled"] === true;
}

function resolveTaintAnalysisRefinementDeltaOnly(config: KuzushiConfig): boolean {
  const taintAnalysis = resolveTaintAnalysisConfig(config);
  if (typeof taintAnalysis["refinementDeltaOnly"] === "boolean") {
    return taintAnalysis["refinementDeltaOnly"];
  }
  return true;
}

function resolveTaintAnalysisRefinementIterations(config: KuzushiConfig): number {
  const taintAnalysis = resolveTaintAnalysisConfig(config);
  const raw = Number(taintAnalysis["refinementIterations"]);
  if (!Number.isFinite(raw) || raw < 1) {
    return 1;
  }
  return Math.floor(raw);
}

function resolveTaintAnalysisRefinementModel(config: KuzushiConfig): string {
  const taintAnalysis = resolveTaintAnalysisConfig(config);
  if (typeof taintAnalysis["refinementModel"] === "string" && taintAnalysis["refinementModel"].trim()) {
    return taintAnalysis["refinementModel"].trim();
  }
  return config.triageModel ?? config.model;
}

function normalizeConcurrency(raw: number): number {
  if (!Number.isFinite(raw) || raw < 1) {
    return 1;
  }

  return Math.floor(raw);
}

function resolveVerifyVerdicts(raw: Verdict[] | undefined): Verdict[] {
  const defaults: Verdict[] = ["tp"];
  if (!Array.isArray(raw) || raw.length === 0) {
    return defaults;
  }

  const unique = new Set<Verdict>();
  for (const verdict of raw) {
    if (verdict === "tp" || verdict === "fp" || verdict === "needs_review") {
      unique.add(verdict);
    }
  }

  return unique.size > 0 ? [...unique] : defaults;
}

function parseVerifyVerdictsFromConfigJson(raw: string, fallback: Verdict[]): Verdict[] {
  try {
    const parsed = JSON.parse(raw);
    if (!isRecord(parsed)) {
      return fallback;
    }

    return resolveVerifyVerdicts(asVerdictArray(parsed["verifyVerdicts"]) ?? fallback);
  } catch {
    return fallback;
  }
}

function parseScanOptsJson(raw: string): ScanOpts {
  const parsed = JSON.parse(raw);
  if (!isRecord(parsed)) {
    throw new Error("scan opts payload is not an object");
  }

  const severity = asStringArray(parsed["severity"]);
  const excludePatterns = asStringArray(parsed["excludePatterns"]);
  const fresh = asBoolean(parsed["fresh"]);

  if (!severity || !excludePatterns || fresh === null) {
    throw new Error("scan opts payload is missing required fields");
  }

  const scannersValue = parsed["scanners"];
  let scanners: string[] | undefined;
  if (scannersValue != null) {
    const parsedScanners = asStringArray(scannersValue);
    if (!parsedScanners) {
      throw new Error("scan opts payload has invalid scanners");
    }
    scanners = parsedScanners;
  }

  const maxFindingsValue = parsed["maxFindings"];
  let maxFindings: number | undefined;
  if (maxFindingsValue !== undefined) {
    const parsedMax = asNumber(maxFindingsValue);
    if (parsedMax === null) {
      throw new Error("scan opts payload has invalid maxFindings");
    }
    maxFindings = Math.floor(parsedMax);
  }

  return {
    severity,
    maxFindings,
    excludePatterns,
    scanners,
    fresh,
  };
}

function shouldVerifyFinding(
  state: RunState,
  finding: Finding,
  triageResult: TriageResult,
): boolean {
  if (!state.verifyEnabled) {
    return false;
  }

  if (!state.verifyVerdicts.has(triageResult.verdict)) {
    return false;
  }

  if (!isScannerVerificationEnabled(state.config, finding.scanner)) {
    return false;
  }

  const minConfidence = state.config.verifyMinConfidence ?? 0;
  if (triageResult.confidence < minConfidence) {
    state.skippedLowConfidence += 1;
    return false;
  }

  return true;
}

const SCANNER_ID_TO_CONFIG_KEY: Record<string, string> = {
  "crypto-misuse-detect": "crypto-misuse",
  "auth-access-detect": "auth-access",
  "race-condition-detect": "race-condition",
  "invariant-check": "invariant-analysis",
  "threat-model-stride": "threat-model",
  "threat-model-pasta": "threat-model",
  "taint-analysis-run": "taint-analysis",
};

function isScannerVerificationEnabled(config: KuzushiConfig, scannerId: string): boolean {
  const configKey = SCANNER_ID_TO_CONFIG_KEY[scannerId] ?? scannerId;
  const scannerCfg = config.scannerConfig[configKey];
  if (!isRecord(scannerCfg)) {
    return true;
  }

  const verify = scannerCfg["verify"];
  if (typeof verify === "boolean") {
    return verify;
  }

  return true;
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
  const evidence = asNullableString(item["evidence"]);
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
    evidence,
    scannerConfidence,
    subcategory,
    likelihood,
    impact,
    cwe,
    score,
  };
}

function asLabelCountMap(value: unknown): Record<string, number> {
  if (!isRecord(value)) {
    return {};
  }

  const out: Record<string, number> = {};
  for (const [key, raw] of Object.entries(value)) {
    if (typeof raw !== "number" || !Number.isFinite(raw)) {
      continue;
    }
    out[key] = raw;
  }

  return out;
}

function asString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  return value;
}

function asNullableString(value: unknown): string | null | undefined {
  if (typeof value === "string") {
    return value;
  }

  if (value === null) {
    return null;
  }

  return undefined;
}

function asNumber(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return null;
  }

  return value;
}

function asBoolean(value: unknown): boolean | null {
  if (typeof value !== "boolean") {
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

function asVerdictArray(value: unknown): Verdict[] | null {
  if (!Array.isArray(value)) {
    return null;
  }

  const verdicts: Verdict[] = [];
  for (const item of value) {
    if (item === "tp" || item === "fp" || item === "needs_review") {
      verdicts.push(item);
      continue;
    }
    return null;
  }

  return verdicts;
}

function collectTransitiveDeps(registry: TaskRegistry, candidateIds: string[]): string[] {
  const all = new Set(candidateIds);
  const queue = [...candidateIds];

  while (queue.length > 0) {
    const id = queue.pop()!;
    if (!registry.has(id)) continue;
    for (const dep of registry.get(id).dependsOn) {
      if (!all.has(dep) && registry.has(dep)) {
        all.add(dep);
        queue.push(dep);
      }
    }
  }

  return normalizeTaskIds([...all]);
}
