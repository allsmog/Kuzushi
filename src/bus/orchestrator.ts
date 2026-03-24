import type Database from "better-sqlite3";
import { normalizeTaskIds } from "../agents/registry.js";
import type { TaskRegistry } from "../agents/registry.js";
import type { TaskContext as AgentTaskContext } from "../agents/types.js";
import { chainAnalysisTask } from "../agents/tasks/chain-analysis.js";
import { quickClassifierTask } from "../agents/tasks/quick-classifier.js";
import { reachabilityCheckTask } from "../agents/tasks/reachability-check.js";
import { callGraphAssistTask } from "../agents/tasks/call-graph-assist.js";
import { SELECTABLE_TASK_IDS } from "../agents/tasks/task-selector.js";
import type { Finding } from "../scanners/types.js";
import { HardExclusionFilter } from "../scanners/fp-filter.js";
import { rescoreFindings } from "../scanners/llm-rescore.js";
import {
  applyRescoreResults,
  capFindingsForTriage,
  clusterFindings,
  getRankingScore,
  selectFindingsForRescore,
} from "../scanners/normalization.js";
import type { ScannerRegistry } from "../scanners/registry.js";
import {
  computeRunMetrics,
  type StageTimestamps,
  type StageCosts,
} from "../scoring/run-metrics.js";
import { resolveCapabilityConfigKey } from "../capabilities.js";
import {
  getActionableFindings,
  getPocHarnessedFingerprints,
  getStoredTriageResults,
  getStoredVerificationResults,
  getRun,
  getTriagedFingerprints,
  getVerifiedFingerprints,
  updateRunCost,
  updateRunContext,
  updateRunFindings,
  updateRunMetrics,
  updateRunStatus,
} from "../store.js";
import type {
  DynamicAnalysisRun,
  EnrichedRepoContext,
  ExploitChain,
  KuzushiConfig,
  PocHarnessResult,
  RepoContext,
  ScanOpts,
  TriageResult,
  VerificationResult,
  Verdict,
} from "../types.js";
import { evaluateQualityGates, type QualityGateResult } from "../quality-gate.js";
import { coerceContextEnrichment, coerceRepoContext } from "../repo-context.js";
import { loadPrecedents, type Precedents } from "../precedents.js";
import { getTaskOutputMeta } from "../task-output-meta.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../utils.js";
import { safeJsonParse } from "../utils/safe-json.js";
import { FindingSchema, formatZodErrors } from "../schemas.js";
import { getLogger } from "../logger.js";
import { runVariantAnalysis } from "./workers/variant-analysis-worker.js";
import type {
  BusHandlerErrorEvent,
  DynamicAnalysisErrorEvent,
  DynamicAnalysisResultEvent,
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
import { executeAgentTask } from "./task-execution.js";
import { PipelineHookChain } from "../hooks/chain.js";
import type { HookContext } from "../hooks/types.js";
import { loadHooksFromFile } from "../hooks/loader.js";
import {
  collectTransitiveDeps,
  injectThreatModelPolicyCandidates,
  resolveOrderWithPolicyEdges,
} from "./orchestrator/task-policy.js";
import {
  dispatchPocHarness as dispatchPocHarnessQueue,
  handlePocHarnessErrorState,
  handlePocHarnessResultState,
  isPocHarnessDone as isPocHarnessQueueDone,
  publishPocQueueDepth,
} from "./orchestrator/poc-dispatcher.js";
import {
  dispatchTriage as dispatchTriageQueue,
  handleTriageError as handleTriageErrorState,
  handleTriageResult as handleTriageResultState,
  isTriageDone as isTriageQueueDone,
  publishTriageQueueDepth,
} from "./orchestrator/triage-dispatcher.js";
import {
  dispatchVerification as dispatchVerificationQueue,
  handleVerificationErrorState,
  handleVerificationResultState,
  isVerificationDone as isVerificationQueueDone,
  publishVerifyQueueDepth,
} from "./orchestrator/verification-dispatcher.js";
import type {
  DynamicAnalysisCandidate,
  OrchestratorDeps,
  PocHarnessCandidate,
  QueuedDynamicAnalysis,
  RunState,
  VerificationCandidate,
} from "./orchestrator/types.js";

/** Scanners whose findings come from static analysis tools, not LLM assessment. */
const NON_LLM_SCANNERS = new Set(["semgrep", "codeql"]);
const log = getLogger("orchestrator");

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

  private draining = false;

  constructor(
    private readonly bus: MessageBus,
    private readonly deps: OrchestratorDeps,
  ) {
    this.registerHandlers();
  }

  /**
   * Drain all in-flight work: stop dispatching new items
   * and wait for current in-flight items to complete (with timeout).
   */
  async drain(timeoutMs: number = 10_000): Promise<void> {
    this.draining = true;
    const deadline = Date.now() + timeoutMs;

    for (const [runId, state] of this.runs) {
      // Wait for all in-flight queues to reach 0
      while (
        (state.inFlight > 0 || state.verifyInFlight > 0 || state.pocHarnessInFlight > 0 || state.dynamicInFlight > 0)
        && Date.now() < deadline
      ) {
        await new Promise((r) => setTimeout(r, 100));
      }

      // Persist interrupted state
      try {
        updateRunStatus(this.deps.db, state.checkpointRunId, "error");
      } catch {
        // Best-effort persistence during shutdown.
      }
    }

    this.draining = false;
  }

  private buildHookContext(state: RunState): HookContext {
    return {
      repo: state.context.repoRoot,
      config: state.config as unknown as Record<string, unknown>,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Retrieve the pipeline hook chain and context for a given run.
   * Used by the triage worker to apply beforeTriage/afterTriage hooks.
   */
  getRunHooks(runId: string): { hookChain: PipelineHookChain; hookContext: HookContext } | undefined {
    const state = this.runs.get(runId);
    if (!state?.hookChain) {
      return undefined;
    }
    return {
      hookChain: state.hookChain,
      hookContext: this.buildHookContext(state),
    };
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

    this.bus.subscribe<DynamicAnalysisResultEvent>("dynamic:result", async (event) => {
      await this.handleDynamicAnalysisResult(event);
    });

    this.bus.subscribe<DynamicAnalysisErrorEvent>("dynamic:error", async (event) => {
      await this.handleDynamicAnalysisError(event);
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
      skippedByClassifier: 0,
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
      enrichedRepoContext: undefined,
      taskOutputs: new Map<string, unknown>(),
      failedTasks: [],
      skippedByLlmRescore: 0,
      softSuppressedFindings: 0,
      corroboratedClusters: 0,
      variantAnalysisCompleted: false,
      variantFindings: 0,
      variantAnalysisCostUsd: 0,
      exploitChains: [],
      chainAnalysisCostUsd: 0,
      budgetExceeded: false,
      budgetWarningEmitted: false,
      deadLetterFindings: [],
      triageAttempts: new Map(),
      verifyAttempts: new Map(),
      autoPassedFingerprints: new Set(),
      // ── Dynamic analysis phase ──
      dynamicAnalysisEnabled: config.dynamicAnalysisEnabled === true,
      dynamicCandidates: [],
      dynamicQueue: [],
      dynamicCursor: 0,
      dynamicTotal: 0,
      dynamicInFlight: 0,
      dynamicConfirmed: 0,
      dynamicInteresting: 0,
      dynamicRejected: 0,
      dynamicErrors: 0,
      dynamicCostUsd: 0,
      dynamicDispatching: false,
      dynamicStarted: false,
      dynamicCompleted: false,
      dynamicAttempts: new Map(),
      stageTimestamps: {
        pipelineStart: event.meta.timestamp,
        pipelineEnd: "",
        scanStart: event.meta.timestamp,
      },
    };

    // Load organization precedents
    try {
      state.precedents = loadPrecedents(context.repoRoot);
    } catch {
      // Precedents loading is best-effort.
    }

    // Load pipeline hooks if configured and external hooks are enabled
    if (config.enableExternalHooks && config.hooks?.files?.length) {
      try {
        const hookObjects = await Promise.all(
          config.hooks.files.map((file) => loadHooksFromFile(file, context.repoRoot)),
        );
        state.hookChain = new PipelineHookChain(hookObjects);
        log.info(`Loaded ${hookObjects.length} pipeline hook file(s)`);
      } catch (error) {
        await this.bus.publish(
          createEvent("pipeline:error", runId, {
            context,
            error: `Failed to load pipeline hooks: ${toErrorMessage(error)}`,
            fatal: true,
          }),
        );
        return;
      }
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
    // Invoke beforeScan hook
    if (state.hookChain) {
      try {
        await state.hookChain.beforeScan(this.buildHookContext(state));
      } catch (error) {
        log.warn(`[hooks] beforeScan hook error: ${toErrorMessage(error)}`);
      }
    }

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
      const parsedContext = safeJsonParse<unknown>(run.contextJson, undefined);
      if (parsedContext !== undefined) {
        state.repoContext = coerceRepoContext(parsedContext);
        state.enrichedRepoContext = coerceContextEnrichment(parsedContext);
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
      const parsed = safeJsonParse<unknown>(run.findingsJson);
      state.scanFindings = clusterFindings(coerceFindings(parsed)).findings;
      state.totalFindings = state.scanFindings.length;
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
    const enableContextEnrichment = state.config.enableContextEnrichment === true
      && this.deps.taskRegistry.has("context-enricher");
    // When enabledTasks is empty, enable ALL registered tasks.
    // When set to ["*"], also enable all tasks (explicit opt-in to full suite).
    // When explicitly set to specific task IDs, use those as the base set.
    // Note: when dynamic selection is active, task-selector may add tasks beyond the base set.
    const explicitTasks = state.config.enabledTasks ?? [];
    const allRegisteredTasks = this.deps.taskRegistry ? this.deps.taskRegistry.ids() : [];
    const useAllTasks = explicitTasks.length === 1 && explicitTasks[0] === "*";

    const dynamicSelectionActive = state.config.enableDynamicTaskSelection === true
      && this.deps.taskRegistry.has("task-selector");

    let baseTaskIds: string[];
    if (useAllTasks) {
      // User said "run everything" — bypass dynamic selection filtering
      baseTaskIds = allRegisteredTasks;
    } else if (explicitTasks.length === 0) {
      if (dynamicSelectionActive) {
        // Exclude selectable tasks — task-selector will add the relevant ones
        baseTaskIds = allRegisteredTasks.filter(id => !SELECTABLE_TASK_IDS.has(id));
      } else {
        baseTaskIds = allRegisteredTasks;
      }
    } else {
      baseTaskIds = explicitTasks;
    }

    const candidateIds = injectThreatModelPolicyCandidates(this.deps.taskRegistry, [
      ...state.scanners,
      ...(enableContextExplicit ? ["context-gatherer"] : []),
      ...(enableContextEnrichment ? ["context-enricher"] : []),
      ...baseTaskIds,
      ...(dynamicSelectionActive ? ["task-selector"] : []),
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
      } else if (dynamicSelectionActive) {
        log.info(
          "[orchestrator] enableContextGathering: false ignored — task-selector requires context-gatherer",
        );
      }
    }

    // Track already-completed tasks for dynamic re-resolution
    const completedTaskIds = new Set<string>();
    const dynamicTasksProcessed = new Set<string>();
    let taskSelectorFallbackApplied = false;

    let stages: string[][];
    try {
      stages = resolveOrderWithPolicyEdges(this.deps.taskRegistry, enabledTaskIds);
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

    // Invoke beforeScan hook before DAG execution
    if (state.hookChain) {
      try {
        await state.hookChain.beforeScan(this.buildHookContext(state));
      } catch (error) {
        log.warn(`[hooks] beforeScan hook error: ${toErrorMessage(error)}`);
      }
    }

    for (let stageIndex = 0; stageIndex < stages.length; stageIndex += 1) {
      const group = stages[stageIndex];

      // Evaluate conditions: split group into tasks to run vs skip
      const tasksToRun: string[] = [];
      const tasksToSkip: string[] = [];
      for (const taskId of group) {
        const task = this.deps.taskRegistry.get(taskId);
        if (task.condition && !task.condition(state.taskOutputs, state.config)) {
          tasksToSkip.push(taskId);
        } else {
          tasksToRun.push(taskId);
        }
      }

      // Emit skip events for conditionally skipped tasks
      for (const taskId of tasksToSkip) {
        log.info(`Task "${taskId}" skipped: condition returned false`);
        await this.bus.publish(
          createEvent("task:skipped", runId, {
            context: state.context,
            taskId,
            reason: "condition returned false",
          }),
        );
        completedTaskIds.add(taskId);
      }

      if (tasksToRun.length === 0) {
        // All tasks in stage were skipped — emit stage:complete and continue
        await this.bus.publish(
          createEvent("stage:complete", runId, {
            context: state.context,
            stageIndex,
            taskIds: [...group],
          }),
        );
        continue;
      }

      const outcomes = tasksToRun.map((taskId) => this.waitForTaskOutcome(runId, taskId));

      for (const taskId of tasksToRun) {
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
        completedTaskIds.add(taskId); // prevent re-scheduling in re-resolved stages
        log.warn(`Task "${taskId}" failed: ${errMsg}`);
        await this.bus.publish(
          createEvent("pipeline:error", runId, {
            context: state.context,
            error: `Task "${taskId}" failed: ${errMsg}`,
            fatal: false,
          }),
        );
      }

      // Determine if the actually-dispatched tasks include findings producers
      // (exclude condition-skipped tasks — their absence is intentional)
      const stageHasFindingsProducers = tasksToRun.some((taskId) => {
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
        log.warn(`Stage ${stageIndex} (non-findings) fully failed, continuing`);
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
        const dynamicTasks = this.extractDynamicTasks(state, completedTaskIds, dynamicTasksProcessed);
        if (dynamicTasks.length > 0) {
          const newTaskIds = dynamicTasks.filter(
            (id) =>
              !enabledTaskIds.includes(id)
              && this.deps.taskRegistry!.has(id),
          );

          if (newTaskIds.length > 0) {
            log.info(`Dynamic task selection added: ${newTaskIds.join(", ")}`);
            const candidateIds = injectThreatModelPolicyCandidates(this.deps.taskRegistry, [
              ...enabledTaskIds,
              ...collectTransitiveDeps(this.deps.taskRegistry, newTaskIds)
                .filter((id) => !enabledTaskIds.includes(id)),
            ]);

            // Re-resolve remaining stages — only commit enabledTaskIds on success
            try {
              const fullStages = resolveOrderWithPolicyEdges(this.deps.taskRegistry, candidateIds);
              enabledTaskIds = candidateIds;
              // Replace remaining stages — skip stages already completed
              const remaining = fullStages.filter((stage) =>
                stage.some((id) => !completedTaskIds.has(id)),
              ).map((stage) => stage.filter((id) => !completedTaskIds.has(id)));
              stages = [
                ...stages.slice(0, stageIndex + 1),
                ...remaining,
              ];
            } catch (error) {
              log.warn(`Dynamic DAG re-resolution failed: ${toErrorMessage(error)}`);
            }
          }
        }
      }

      // Fallback: after task-selector has settled (succeeded or failed), if no
      // non-failed selectable tasks are enabled, re-add all selectable tasks so
      // the pipeline doesn't produce zero detection results.
      if (dynamicSelectionActive && !taskSelectorFallbackApplied) {
        const selectorSettled = completedTaskIds.has("task-selector");
        const hasSelectableTasks = enabledTaskIds.some(
          id => SELECTABLE_TASK_IDS.has(id) && !state.failedTasks.includes(id),
        );

        if (selectorSettled && !hasSelectableTasks) {
          const selectorFailed = state.failedTasks.includes("task-selector");
          const reason = selectorFailed ? "failed" : "recommended no selectable tasks";
          const fallbackIds = [...SELECTABLE_TASK_IDS].filter(
            id => !enabledTaskIds.includes(id) && this.deps.taskRegistry!.has(id),
          );
          if (fallbackIds.length > 0) {
            log.warn(`task-selector ${reason} — falling back to all selectable tasks: ${fallbackIds.join(", ")}`);
            const candidateIds = injectThreatModelPolicyCandidates(this.deps.taskRegistry, [
              ...enabledTaskIds,
              ...collectTransitiveDeps(this.deps.taskRegistry, fallbackIds)
                .filter(id => !enabledTaskIds.includes(id)),
            ]);
            try {
              const fullStages = resolveOrderWithPolicyEdges(this.deps.taskRegistry, candidateIds);
              enabledTaskIds = candidateIds;
              taskSelectorFallbackApplied = true;
              const remaining = fullStages
                .filter(stage => stage.some(id => !completedTaskIds.has(id)))
                .map(stage => stage.filter(id => !completedTaskIds.has(id)));
              stages = [...stages.slice(0, stageIndex + 1), ...remaining];
            } catch (error) {
              log.warn(`Fallback DAG re-resolution failed: ${toErrorMessage(error)}`);
            }
          } else {
            // All selectable tasks already in enabledTaskIds (or none registered) — no retry needed
            taskSelectorFallbackApplied = true;
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

      // Budget guard: stop DAG execution if budget is exceeded after this stage
      if (this.isBudgetExceeded(state)) {
        await this.emitBudgetExceeded(state, runId);
        break;
      }
    }

    const gatheredContext = coerceRepoContext(state.taskOutputs.get("context-gatherer"));
    if (gatheredContext) {
      state.repoContext = gatheredContext;
    }

    const enrichedContext = coerceContextEnrichment(state.taskOutputs.get("context-enricher"));
    if (enrichedContext) {
      state.enrichedRepoContext = enrichedContext;
    }

    if (state.repoContext || state.enrichedRepoContext) {
      try {
        updateRunContext(this.deps.db, state.checkpointRunId, {
          base: state.repoContext,
          enrichment: state.enrichedRepoContext,
        });
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
    processedTaskIds: Set<string>,
  ): string[] {
    const dynamicTasks: string[] = [];
    for (const taskId of completedTaskIds) {
      if (processedTaskIds.has(taskId)) continue;
      const output = state.taskOutputs.get(taskId);
      if (
        isRecord(output)
        && Array.isArray(output["recommendedTasks"])
      ) {
        processedTaskIds.add(taskId);
        const recommended = output["recommendedTasks"] as unknown[];
        for (const t of recommended) {
          if (typeof t === "string" && t.trim()) {
            dynamicTasks.push(t.trim());
          }
        }
      } else {
        // No output or wrong shape (e.g., failed task) — mark as processed
        // to avoid re-scanning on every subsequent stage.
        processedTaskIds.add(taskId);
      }
    }
    return normalizeTaskIds(dynamicTasks);
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

    state.stageTimestamps.scanEnd = event.meta.timestamp;

    const clustered = clusterFindings(state.scanFindings);
    state.scanFindings = clustered.findings;
    state.totalFindings = clustered.findings.length;
    state.corroboratedClusters = clustered.corroboratedClusters;

    try {
      if (!state.resuming) {
        updateRunStatus(this.deps.db, state.checkpointRunId, "triaging");
      }
      updateRunFindings(this.deps.db, state.checkpointRunId, state.scanFindings);
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

    // Apply hard/soft filtering after clustering so corroborating evidence is preserved.
    let filteredFindings = [...state.scanFindings];
    state.skippedByFpFilter = 0;
    state.softSuppressedFindings = 0;
    if (state.config.fpFilterEnabled !== false) {
      const customExclusions = [
        ...(state.config.fpFilterCustomExclusions ?? []),
        ...(state.precedents?.hardExclusions ?? []),
      ];
      const fpFilter = new HardExclusionFilter(customExclusions);
      const filterResult = fpFilter.filterFindings(state.scanFindings);
      filteredFindings = filterResult.kept;
      state.skippedByFpFilter = filterResult.hardExcluded.length;
      state.softSuppressedFindings = filterResult.softSuppressed.length;
      if (filterResult.hardExcluded.length > 0) {
        log.info(`[fp-filter] Excluded ${filterResult.hardExcluded.length} findings`);
      }
    }

    filteredFindings.sort((a, b) => getRankingScore(b) - getRankingScore(a));

    state.skippedByClassifier = 0;
    state.skippedByLlmRescore = 0;
    if (state.config.enableClassifier === true) {
      try {
        const classifierContext: AgentTaskContext = {
          runId,
          repoRoot: state.context.repoRoot,
          scanPath: state.context.scanPath,
          repoName: state.context.repoName,
          config: state.config,
          runtime: this.deps.runtime,
          bus: this.bus,
          upstreamOutputs: new Map(state.taskOutputs),
        };
        const executed = await executeAgentTask(
          quickClassifierTask,
          filteredFindings,
          classifierContext,
          {},
        );
        const classifiedFindings = coerceQuickClassifierFindings(executed.output);
        state.skippedByClassifier = Math.max(0, filteredFindings.length - classifiedFindings.length);
        filteredFindings = classifiedFindings;
        const classifierCostUsd = normalizeCostUsd(executed.costUsd);
        if (classifierCostUsd > 0) {
          state.totalCostUsd += classifierCostUsd;
          try {
            updateRunCost(this.deps.db, state.checkpointRunId, classifierCostUsd);
          } catch {
            // Best-effort cost persistence for classifier calls.
          }
        }
        if (state.skippedByClassifier > 0) {
          log.info(`[quick-classifier] Excluded ${state.skippedByClassifier} findings`);
        }
      } catch (error) {
        log.warn(`[quick-classifier] Failed open: ${toErrorMessage(error)}`);
      }
    } else if (state.config.llmRescoreEnabled) {
      const rescoreWindow = selectFindingsForRescore(filteredFindings, state.scanOpts.maxFindings);
      const rescoredFingerprints = new Set(rescoreWindow.map((finding) => finding.fingerprint));
      const untouched = filteredFindings.filter(
        (finding) => !rescoredFingerprints.has(finding.fingerprint),
      );
      const rescoreResults = await rescoreFindings(rescoreWindow, {
        model: state.config.llmRescoreModel,
        threshold: state.config.llmRescoreThreshold,
        repoRoot: state.context.repoRoot,
        runtime: this.deps.runtime,
      });
      const applied = applyRescoreResults(rescoreWindow, rescoreResults);
      filteredFindings = [...applied.findings, ...untouched]
        .sort((a, b) => getRankingScore(b) - getRankingScore(a));
      state.skippedByLlmRescore = applied.skippedByLlmRescore;
      if (state.skippedByLlmRescore > 0) {
        log.info(`[llm-rescore] Excluded ${state.skippedByLlmRescore} findings`);
      }
    }

    // Reachability-assisted ranking: penalize unreachable findings before final sort
    if (state.config.callGraphAssistEnabled === true && filteredFindings.length > 0) {
      try {
        const reachabilityContext: AgentTaskContext = {
          runId,
          repoRoot: state.context.repoRoot,
          scanPath: state.context.scanPath,
          repoName: state.context.repoName,
          config: state.config,
          runtime: this.deps.runtime,
          bus: this.bus,
          upstreamOutputs: new Map(state.taskOutputs),
        };
        const executed = await executeAgentTask(
          reachabilityCheckTask,
          filteredFindings,
          reachabilityContext,
          {},
        );
        const enriched = executed.output;
        if (Array.isArray(enriched) && enriched.length > 0) {
          filteredFindings = enriched as Finding[];
        }
        const reachCostUsd = normalizeCostUsd(executed.costUsd);
        if (reachCostUsd > 0) {
          state.totalCostUsd += reachCostUsd;
          try {
            updateRunCost(this.deps.db, state.checkpointRunId, reachCostUsd);
          } catch {
            // Best-effort cost persistence.
          }
        }
      } catch (error) {
        log.warn(`[reachability-check] Failed open: ${toErrorMessage(error)}`);
      }

      // Call-graph-assist: enrich high-score findings with call-chain evidence
      try {
        const cgContext: AgentTaskContext = {
          runId,
          repoRoot: state.context.repoRoot,
          scanPath: state.context.scanPath,
          repoName: state.context.repoName,
          config: state.config,
          runtime: this.deps.runtime,
          bus: this.bus,
          upstreamOutputs: new Map(state.taskOutputs),
        };
        const cgExecuted = await executeAgentTask(
          callGraphAssistTask,
          filteredFindings,
          cgContext,
          {},
        );
        const cgEnriched = cgExecuted.output;
        if (Array.isArray(cgEnriched) && cgEnriched.length > 0) {
          filteredFindings = cgEnriched as Finding[];
        }
        const cgCostUsd = normalizeCostUsd(cgExecuted.costUsd);
        if (cgCostUsd > 0) {
          state.totalCostUsd += cgCostUsd;
          try {
            updateRunCost(this.deps.db, state.checkpointRunId, cgCostUsd);
          } catch {
            // Best-effort cost persistence.
          }
        }
      } catch (error) {
        log.warn(`[call-graph-assist] Failed open: ${toErrorMessage(error)}`);
      }
    }

    if (state.config.prioritizeFindings === false) {
      filteredFindings = [...filteredFindings];
    } else {
      filteredFindings.sort((a, b) => getRankingScore(b) - getRankingScore(a));
    }

    // Invoke afterScan hook — allows hooks to filter/enrich findings
    if (state.hookChain) {
      try {
        filteredFindings = await state.hookChain.afterScan(
          this.buildHookContext(state),
          filteredFindings,
        );
      } catch (error) {
        log.warn(`[hooks] afterScan hook error: ${toErrorMessage(error)}`);
      }
    }

    state.scanFindings = filteredFindings;
    state.totalFindings = filteredFindings.length;

    const pendingFindings = filteredFindings.filter(
      (finding) => !alreadyTriaged.has(finding.fingerprint),
    );
    let triageCandidates = capFindingsForTriage(pendingFindings, state.scanOpts.maxFindings);

    // PR 5: Auto-pass high-confidence agentic findings when enabled
    const autoPassFindings: Finding[] = [];
    if (state.config.skipTriageForHighConfidenceAgentic) {
      triageCandidates = triageCandidates.filter((finding) => {
        if (
          !NON_LLM_SCANNERS.has(finding.scanner)
          && finding.scannerConfidence === "HIGH"
          && finding.score >= 8
        ) {
          autoPassFindings.push(finding);
          return false;
        }
        return true;
      });
    }

    // Track auto-passed fingerprints so handleTriageResult can skip counter manipulation
    state.autoPassedFingerprints = new Set(autoPassFindings.map((f) => f.fingerprint));

    state.skippedAlreadyTriaged = filteredFindings.length - pendingFindings.length;
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

    state.stageTimestamps.triageStart = new Date().toISOString();

    await this.bus.publish(
      createEvent("triage:start", runId, {
        context: state.context,
        findingCount: triageCandidates.length,
        model: state.config.triageModel ?? state.config.model,
      }),
    );

    await this.publishQueueDepth(state, runId);

    if (triageCandidates.length === 0 && autoPassFindings.length === 0) {
      await this.finishTriageAndRequestReport(state, runId);
      return;
    }

    // Dispatch real triage FIRST — before emitting auto-pass events
    if (triageCandidates.length > 0) {
      await this.dispatchTriageBatch(state, runId, triageCandidates);
    }

    // Emit synthetic triage results for auto-passed findings AFTER dispatch.
    // handleTriageResult detects these via autoPassedFingerprints and skips
    // counter manipulation (inFlight/triaged), only pushing to verifyCandidates.
    for (const [idx, finding] of autoPassFindings.entries()) {
      await this.bus.publish(
        createEvent("triage:result", runId, {
          context: state.context,
          finding,
          result: {
            fingerprint: finding.fingerprint,
            verdict: "tp" as const,
            confidence: 0.9,
            rationale: "Auto-passed: high-confidence LLM-generated finding (skipTriageForHighConfidenceAgentic)",
            verificationSteps: ["Finding was auto-triaged based on high agentic scanner confidence"],
            fixPatch: null,
          },
          costUsd: 0,
          attempts: 0,
          index: triageCandidates.length + idx + 1,
          total: triageCandidates.length + autoPassFindings.length,
        }),
      );
    }

    // If only auto-pass findings existed (no real candidates), finish triage now
    if (triageCandidates.length === 0) {
      await this.finishTriageAndRequestReport(state, runId);
    }
  }

  private async handleTriageResult(event: TriageResultEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    // Auto-passed findings: only push to verify candidates, skip counter manipulation
    // to avoid corrupting inFlight/triaged and re-entrant dispatch.
    if (state.autoPassedFingerprints.has(event.payload.finding.fingerprint)) {
      if (shouldVerifyFinding(state, event.payload.finding, event.payload.result)) {
        state.verifyCandidates.push({
          finding: event.payload.finding,
          triageResult: event.payload.result,
        });
      }
      return;
    }

    handleTriageResultState(
      state,
      runId,
      event.payload.finding,
      event.payload.result,
      event.payload.costUsd,
      shouldVerifyFinding,
      this.deps,
    );

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

    handleTriageErrorState(
      state,
      event.payload.error,
      event.payload.finding,
      event.payload.costUsd,
      event.payload.attempts,
      event.payload.index,
      event.payload.total,
      this.deps,
    );

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

    // Evaluate quality gates if configured
    let qualityGateResult: QualityGateResult | undefined;
    if (state.config.qualityGates) {
      const fingerprints = state.scanFindings.map((f) => f.fingerprint);
      const findings = getActionableFindings(this.deps.db, state.context.repoName, {
        includeFalsePositives: true,
        fingerprints,
      });
      qualityGateResult = evaluateQualityGates(findings, state.config.qualityGates);

      if (!qualityGateResult.passed) {
        process.exitCode = 1;
      }
    }

    // Compute final run metrics for the pipeline:complete event
    state.stageTimestamps.pipelineEnd = event.meta.timestamp;
    const triageCost = state.totalCostUsd - state.verifyCostUsd - state.pocHarnessCostUsd - state.dynamicCostUsd - state.variantAnalysisCostUsd - state.chainAnalysisCostUsd;
    const finalMetrics = computeRunMetrics(
      state.scanFindings,
      state.stageTimestamps,
      {
        triage: Math.max(0, triageCost),
        verify: state.verifyCostUsd,
        pocHarness: state.pocHarnessCostUsd,
        dynamicAnalysis: state.dynamicCostUsd,
        variantAnalysis: state.variantAnalysisCostUsd,
      },
    );

    // Persist metrics to database
    try {
      updateRunMetrics(this.deps.db, state.checkpointRunId, finalMetrics);
    } catch {
      // Metrics persistence is best-effort.
    }

    const pipelineStats = {
      scanners: [...state.scanners],
      totalFindings: state.totalFindings,
      queuedForTriage: state.triageTotal,
      skippedAlreadyTriaged: state.skippedAlreadyTriaged,
      skippedLowConfidence: state.verifyEnabled ? state.skippedLowConfidence : undefined,
      skippedByFpFilter: state.skippedByFpFilter > 0 ? state.skippedByFpFilter : undefined,
      skippedByClassifier: state.skippedByClassifier > 0 ? state.skippedByClassifier : undefined,
      softSuppressedFindings: state.softSuppressedFindings > 0 ? state.softSuppressedFindings : undefined,
      skippedByLlmRescore: state.skippedByLlmRescore > 0 ? state.skippedByLlmRescore : undefined,
      corroboratedClusters: state.corroboratedClusters > 0 ? state.corroboratedClusters : undefined,
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
      deadLetterCount: state.deadLetterFindings.length > 0 ? state.deadLetterFindings.length : undefined,
      qualityGateResult,
      runMetrics: finalMetrics,
      startedAt: state.startedAt,
      completedAt: event.meta.timestamp,
    };

    // Invoke afterAll hook before emitting pipeline:complete
    if (state.hookChain) {
      try {
        await state.hookChain.afterAll(this.buildHookContext(state), {
          findings: state.scanFindings,
          stats: pipelineStats as unknown as Record<string, unknown>,
        });
      } catch (error) {
        log.warn(`[hooks] afterAll hook error: ${toErrorMessage(error)}`);
      }
    }

    await this.bus.publish(
      createEvent("pipeline:complete", runId, {
        context: state.context,
        stats: pipelineStats,
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
      "dynamic:agent-activity",
      "budget:check",
      "budget:warning",
      "llm:call-start",
      "llm:call-complete",
      "llm:call-error",
      "llm:retry",
      "retry:attempt",
      "retry:exhausted",
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
    await dispatchTriageQueue(
      state,
      runId,
      this.bus,
      this.isBudgetExceeded.bind(this),
      this.emitBudgetCheck.bind(this),
      this.emitBudgetExceeded.bind(this),
      this.publishQueueDepth.bind(this),
    );
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
        enrichedContext: state.enrichedRepoContext,
        precedents: state.precedents,
        total: findings.length,
      }),
    );

    await this.publishQueueDepth(state, runId);
  }

  private isTriageDone(state: RunState): boolean {
    return isTriageQueueDone(state);
  }

  private async finishTriageAndRequestReport(state: RunState, runId: string): Promise<void> {
    if (state.reportRequested || state.refinementInFlight) {
      log.info(
        `finishTriageAndRequestReport skipped: reportRequested=${state.reportRequested}, refinementInFlight=${state.refinementInFlight}`,
      );
      return;
    }

    state.stageTimestamps.triageEnd = new Date().toISOString();

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
      log.info("requestPostTriageFlow skipped: reportRequested=true");
      return;
    }

    if (!state.verifyEnabled) {
      await this.runVariantAnalysisPhase(state, runId);
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
            runtime: this.deps.runtime,
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
            updateRunCost(this.deps.db, state.checkpointRunId, chainMeta.costUsd);
          }
        } catch (error) {
          log.warn(`Chain analysis error: ${toErrorMessage(error)}`);
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
      log.info(`verification enabled — ${state.verifyCandidates.length} candidates, starting verification`);
      await this.startVerification(state, runId);
      return;
    }

    log.info("verification disabled — requesting report directly");

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

  private collectVariantAnalysisSeeds(
    state: RunState,
  ): Array<{ finding: Finding; triageResult: TriageResult }> {
    const fingerprints = state.scanFindings.map((finding) => finding.fingerprint);
    const triageResults = getStoredTriageResults(this.deps.db, fingerprints);
    const verificationResults = state.verifyEnabled
      ? getStoredVerificationResults(this.deps.db, fingerprints)
      : new Map<string, VerificationResult>();

    const seeds: Array<{ finding: Finding; triageResult: TriageResult }> = [];
    for (const finding of state.scanFindings) {
      const triageResult = triageResults.get(finding.fingerprint);
      if (!triageResult || triageResult.verdict !== "tp") {
        continue;
      }

      if (state.verifyEnabled) {
        const verificationResult = verificationResults.get(finding.fingerprint);
        if (!verificationResult?.exploitable) {
          continue;
        }
      } else if (triageResult.confidence < 0.9) {
        continue;
      }

      seeds.push({ finding, triageResult });
    }

    return seeds;
  }

  private async runVariantAnalysisPhase(state: RunState, runId: string): Promise<void> {
    if (!state.config.variantAnalysis || state.variantAnalysisCompleted) {
      return;
    }
    state.variantAnalysisCompleted = true;

    const confirmedTPs = this.collectVariantAnalysisSeeds(state);
    if (confirmedTPs.length === 0) {
      return;
    }

    const model = state.config.variantAnalysisModel || state.config.model;
    await this.bus.publish(
      createEvent("variant-analysis:start", runId, {
        context: state.context,
        confirmedCount: confirmedTPs.length,
        model,
      }),
    );

    try {
      const result = await runVariantAnalysis(confirmedTPs, state.context, {
        ...state.config,
        variantAnalysisMaxFindings: Math.min(state.config.variantAnalysisMaxFindings ?? 5, 5),
      }, this.deps.runtime);
      const normalizedVariants = await this.normalizeFindingsForVariantAnalysis(state, result.findings);
      state.variantFindings = normalizedVariants.length;
      state.variantAnalysisCostUsd = result.costUsd;
      state.totalCostUsd += result.costUsd;
      updateRunCost(this.deps.db, state.checkpointRunId, result.costUsd);
    } catch (error) {
      log.warn(`Variant analysis error: ${toErrorMessage(error)}`);
    }

    await this.bus.publish(
      createEvent("variant-analysis:complete", runId, {
        context: state.context,
        variantFindings: state.variantFindings,
        costUsd: state.variantAnalysisCostUsd,
      }),
    );
  }

  private async normalizeFindingsForVariantAnalysis(
    state: RunState,
    findings: Finding[],
  ): Promise<Finding[]> {
    let normalized = clusterFindings(findings).findings;
    if (normalized.length === 0) {
      return normalized;
    }

    if (state.config.fpFilterEnabled !== false) {
      const customExclusions = [
        ...(state.config.fpFilterCustomExclusions ?? []),
        ...(state.precedents?.hardExclusions ?? []),
      ];
      normalized = new HardExclusionFilter(customExclusions).filterFindings(normalized).kept;
    }

    normalized.sort((a, b) => getRankingScore(b) - getRankingScore(a));

    if (state.config.llmRescoreEnabled) {
      const rescoreWindow = selectFindingsForRescore(normalized, state.scanOpts.maxFindings);
      const rescoredFingerprints = new Set(rescoreWindow.map((finding) => finding.fingerprint));
      const untouched = normalized.filter((finding) => !rescoredFingerprints.has(finding.fingerprint));
      const rescoreResults = await rescoreFindings(rescoreWindow, {
        model: state.config.llmRescoreModel,
        threshold: state.config.llmRescoreThreshold,
        repoRoot: state.context.repoRoot,
        runtime: this.deps.runtime,
      });
      normalized = [...applyRescoreResults(rescoreWindow, rescoreResults).findings, ...untouched]
        .sort((a, b) => getRankingScore(b) - getRankingScore(a));
    }

    return normalized;
  }

  private isBudgetExceeded(state: RunState): boolean {
    const budget = state.config.costBudgetUsd;
    return typeof budget === "number" && budget > 0 && state.totalCostUsd >= budget;
  }

  /**
   * Emit budget:check (always) and budget:warning (at 80%+) observability events.
   * Call this whenever cost changes and a budget is configured.
   */
  private async emitBudgetCheck(state: RunState, runId: string): Promise<void> {
    const budget = state.config.costBudgetUsd;
    if (typeof budget !== "number" || budget <= 0) return;

    const percentUsed = (state.totalCostUsd / budget) * 100;

    try {
      await this.bus.publish(
        createEvent("budget:check", runId, {
          currentSpend: state.totalCostUsd,
          maxBudget: budget,
          percentUsed,
        }),
      );

      if (percentUsed >= 80 && !state.budgetWarningEmitted) {
        state.budgetWarningEmitted = true;
        await this.bus.publish(
          createEvent("budget:warning", runId, {
            currentSpend: state.totalCostUsd,
            maxBudget: budget,
            percentUsed,
          }),
        );
      }
    } catch {
      // Non-fatal: observability emission should never break orchestration
    }
  }

  private async emitBudgetExceeded(state: RunState, runId: string): Promise<void> {
    if (state.budgetExceeded) return;
    state.budgetExceeded = true;
    const budget = state.config.costBudgetUsd!;
    log.warn(`Budget exceeded: $${state.totalCostUsd.toFixed(4)} >= $${budget.toFixed(4)}`);
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
      log.info(
        `startVerification skipped: verificationStarted=${state.verificationStarted}, reportEmitted=${state.reportEmitted}`,
      );
      return;
    }

    state.verificationCompleted = false;

    if (!state.resumingVerification) {
      // Rank candidates: highest-score first, triage confidence as tiebreaker,
      // presence of structured evidence (taintPath) as final tiebreaker.
      const ranked = [...state.verifyCandidates].sort((a, b) => {
        const scoreA = getRankingScore(a.finding);
        const scoreB = getRankingScore(b.finding);
        if (scoreB !== scoreA) return scoreB - scoreA;
        if (b.triageResult.confidence !== a.triageResult.confidence) {
          return b.triageResult.confidence - a.triageResult.confidence;
        }
        const evidenceA = a.finding.taintPath?.length ? 1 : 0;
        const evidenceB = b.finding.taintPath?.length ? 1 : 0;
        return evidenceB - evidenceA;
      });

      state.verifyTotal = ranked.length;
      state.verifyQueue = ranked.map((item, idx) => ({
        ...item,
        index: idx + 1,
        total: ranked.length,
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

    state.stageTimestamps.verifyStart = new Date().toISOString();

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

    handleVerificationResultState(state, event, this.deps);

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

    handleVerificationErrorState(state, event, this.deps);

    await this.publishVerificationQueueDepth(state, runId);

    if (this.isVerificationDone(state)) {
      await this.finishVerificationAndRequestReport(state, runId);
      return;
    }

    await this.dispatchVerification(state, runId);
  }

  private async dispatchVerification(state: RunState, runId: string): Promise<void> {
    await dispatchVerificationQueue(
      state,
      runId,
      this.bus,
      this.isBudgetExceeded.bind(this),
      this.emitBudgetCheck.bind(this),
      this.emitBudgetExceeded.bind(this),
      this.publishVerificationQueueDepth.bind(this),
    );
  }

  private isVerificationDone(state: RunState): boolean {
    return isVerificationQueueDone(state);
  }

  private async finishVerificationAndRequestReport(state: RunState, runId: string): Promise<void> {
    if (state.reportEmitted || state.verificationCompleted) {
      return;
    }
    state.verificationCompleted = true;
    state.stageTimestamps.verifyEnd = new Date().toISOString();

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

    // Gate: dynamic analysis when PoC harness is disabled
    if (state.dynamicAnalysisEnabled && !this.isBudgetExceeded(state)) {
      const candidates = this.selectDynamicAnalysisCandidates(state);
      if (candidates.length > 0) {
        state.dynamicCandidates = candidates;
        await this.startDynamicAnalysis(state, runId);
        return;
      }
    }

    await this.runVariantAnalysisPhase(state, runId);

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

    state.stageTimestamps.pocStart = new Date().toISOString();

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

    handlePocHarnessResultState(state, event, this.deps);

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

    handlePocHarnessErrorState(state, event, this.deps);

    await this.publishPocHarnessQueueDepth(state, runId);

    if (this.isPocHarnessDone(state)) {
      await this.finishPocHarnessAndRequestReport(state, runId);
      return;
    }

    await this.dispatchPocHarness(state, runId);
  }

  private async dispatchPocHarness(state: RunState, runId: string): Promise<void> {
    await dispatchPocHarnessQueue(
      state,
      runId,
      this.bus,
      this.isBudgetExceeded.bind(this),
      this.emitBudgetCheck.bind(this),
      this.emitBudgetExceeded.bind(this),
      this.publishPocHarnessQueueDepth.bind(this),
    );
  }

  private isPocHarnessDone(state: RunState): boolean {
    return isPocHarnessQueueDone(state);
  }

  private async finishPocHarnessAndRequestReport(state: RunState, runId: string): Promise<void> {
    if (state.reportEmitted) {
      return;
    }

    state.stageTimestamps.pocEnd = new Date().toISOString();

    await this.bus.publish(
      createEvent("poc-harness:complete", runId, {
        context: state.context,
        generated: state.pocHarnessGenerated,
        skipped: state.pocHarnessSkipped,
        errors: state.pocHarnessErrors,
        totalCostUsd: state.pocHarnessCostUsd,
      }),
    );

    // Gate: dynamic analysis after PoC harness
    if (state.dynamicAnalysisEnabled && !this.isBudgetExceeded(state)) {
      const candidates = this.selectDynamicAnalysisCandidates(state);
      if (candidates.length > 0) {
        state.dynamicCandidates = candidates;
        await this.startDynamicAnalysis(state, runId);
        return;
      }
    }

    await this.runVariantAnalysisPhase(state, runId);

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
    await publishTriageQueueDepth(state, runId, this.bus);
  }

  private async publishVerificationQueueDepth(state: RunState, runId: string): Promise<void> {
    await publishVerifyQueueDepth(state, runId, this.bus);
  }

  private async publishPocHarnessQueueDepth(state: RunState, runId: string): Promise<void> {
    await publishPocQueueDepth(state, runId, this.bus);
  }

  // ── Dynamic Analysis Phase ─────────────────────────────────────────────

  private selectDynamicAnalysisCandidates(state: RunState): DynamicAnalysisCandidate[] {
    const maxCandidates = state.config.dynamicMaxCandidates ?? 20;
    const minScore = state.config.dynamicMinScore ?? 7;
    const triageResults = getStoredTriageResults(this.deps.db, state.scanFindings.map((f) => f.fingerprint));
    const verificationResults = getStoredVerificationResults(this.deps.db, state.scanFindings.map((f) => f.fingerprint));

    const candidates: DynamicAnalysisCandidate[] = [];

    for (const finding of state.scanFindings) {
      const triageResult = triageResults.get(finding.fingerprint);
      if (!triageResult || triageResult.verdict === "fp") continue;

      const verificationResult = verificationResults.get(finding.fingerprint);

      // Compute proof value based on evidence
      let proofValue = 0;
      if (finding.taintPath && finding.taintPath.length > 0) {
        proofValue += finding.taintPath.length * 2;
      }
      if (finding.corroboratingSignals && finding.corroboratingSignals.length > 0) {
        proofValue += finding.corroboratingSignals.length * 1.5;
      }
      if (verificationResult) {
        proofValue += 3;
      }

      const score = finding.adjustedScore ?? finding.score;

      // Priority 1: Inconclusive/low-confidence verified findings with taintPath
      if (
        verificationResult
        && (!verificationResult.exploitable || (verificationResult.confidence ?? 0) < 0.6)
        && finding.taintPath
        && finding.taintPath.length > 0
      ) {
        candidates.push({ finding, triageResult, verificationResult, score, proofValue });
        continue;
      }

      // Priority 2: Strong taint-analysis findings
      if (
        finding.scanner === "taint-analysis-run"
        && score >= minScore
        && finding.taintPath
        && finding.taintPath.length > 0
      ) {
        candidates.push({ finding, triageResult, verificationResult, score, proofValue });
        continue;
      }

      // Priority 3: Corroborated CodeQL or agentic findings
      if (
        (finding.scanner === "codeql" || finding.scanner === "agentic")
        && finding.corroboratingSignals
        && finding.corroboratingSignals.length >= 1
      ) {
        candidates.push({ finding, triageResult, verificationResult, score, proofValue });
        continue;
      }

      // Priority 4: Semgrep only if corroborated or critical
      if (
        finding.scanner === "semgrep"
        && (
          (finding.corroboratingSignals && finding.corroboratingSignals.length >= 1)
          || finding.severity === "ERROR"
        )
      ) {
        candidates.push({ finding, triageResult, verificationResult, score, proofValue });
        continue;
      }
    }

    // Sort by (score + proofValue) descending, cap at maxCandidates
    candidates.sort((a, b) => (b.score + b.proofValue) - (a.score + a.proofValue));
    return candidates.slice(0, maxCandidates);
  }

  private async startDynamicAnalysis(state: RunState, runId: string): Promise<void> {
    if (state.dynamicStarted || state.reportEmitted) {
      return;
    }

    state.dynamicTotal = state.dynamicCandidates.length;
    state.dynamicQueue = state.dynamicCandidates.map((item, idx) => ({
      ...item,
      index: idx + 1,
      total: state.dynamicCandidates.length,
    }));
    state.dynamicCursor = 0;

    try {
      updateRunStatus(this.deps.db, state.checkpointRunId, "dynamic-analyzing");
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

    state.stageTimestamps.dynamicStart = new Date().toISOString();

    await this.bus.publish(
      createEvent("dynamic:start", runId, {
        context: state.context,
        findingCount: state.dynamicTotal,
        model: state.config.pocHarnessModel ?? state.config.model,
      }),
    );

    state.dynamicStarted = true;
    await this.dispatchDynamicAnalysis(state, runId);
  }

  private async handleDynamicAnalysisResult(event: DynamicAnalysisResultEvent): Promise<void> {
    const { runId } = event.meta;
    const state = this.runs.get(runId);
    if (!state) return;

    state.dynamicInFlight -= 1;
    const costUsd = normalizeCostUsd(event.payload.costUsd);
    state.dynamicCostUsd += costUsd;
    state.totalCostUsd += costUsd;
    updateRunCost(this.deps.db, state.checkpointRunId, costUsd);

    const status = event.payload.result.status;
    if (status === "confirmed") state.dynamicConfirmed += 1;
    else if (status === "interesting") state.dynamicInteresting += 1;
    else if (status === "rejected") state.dynamicRejected += 1;

    await this.publishDynamicAnalysisQueueDepth(state, runId);

    if (this.isDynamicAnalysisDone(state)) {
      await this.finishDynamicAnalysisAndContinue(state, runId);
    } else {
      await this.dispatchDynamicAnalysis(state, runId);
    }
  }

  private async handleDynamicAnalysisError(event: DynamicAnalysisErrorEvent): Promise<void> {
    const { runId } = event.meta;
    const state = this.runs.get(runId);
    if (!state) return;

    state.dynamicInFlight -= 1;
    state.dynamicErrors += 1;
    const costUsd = normalizeCostUsd(event.payload.costUsd);
    state.dynamicCostUsd += costUsd;
    state.totalCostUsd += costUsd;
    updateRunCost(this.deps.db, state.checkpointRunId, costUsd);

    await this.publishDynamicAnalysisQueueDepth(state, runId);

    if (this.isDynamicAnalysisDone(state)) {
      await this.finishDynamicAnalysisAndContinue(state, runId);
    } else {
      await this.dispatchDynamicAnalysis(state, runId);
    }
  }

  private async dispatchDynamicAnalysis(state: RunState, runId: string): Promise<void> {
    if (state.dynamicDispatching || state.reportEmitted) return;
    state.dynamicDispatching = true;

    try {
      // Dynamic analysis executes real harnesses — default to conservative concurrency of 1
      const concurrency = normalizeConcurrency(1);

      while (
        state.dynamicInFlight < concurrency
        && state.dynamicCursor < state.dynamicQueue.length
      ) {
        await this.emitBudgetCheck(state, runId);
        if (this.isBudgetExceeded(state)) {
          await this.emitBudgetExceeded(state, runId);
          break;
        }
        const item = state.dynamicQueue[state.dynamicCursor];
        state.dynamicCursor += 1;
        state.dynamicInFlight += 1;

        await this.bus.publish(
          createEvent("dynamic:finding-queued", runId, {
            context: state.context,
            finding: item.finding,
            triageResult: item.triageResult,
            verificationResult: item.verificationResult,
            pocHarnessResult: item.pocHarnessResult,
            repoContext: state.repoContext,
            index: item.index,
            total: item.total,
          }),
        );
      }

      await this.publishDynamicAnalysisQueueDepth(state, runId);
    } finally {
      state.dynamicDispatching = false;
    }
  }

  private isDynamicAnalysisDone(state: RunState): boolean {
    const processed = state.dynamicConfirmed + state.dynamicInteresting + state.dynamicRejected + state.dynamicErrors;
    return (
      state.dynamicTotal > 0
      && processed >= state.dynamicTotal
      && state.dynamicInFlight === 0
      && !state.reportEmitted
    );
  }

  private async finishDynamicAnalysisAndContinue(state: RunState, runId: string): Promise<void> {
    if (state.reportEmitted || state.dynamicCompleted) {
      return;
    }
    state.dynamicCompleted = true;
    state.stageTimestamps.dynamicEnd = new Date().toISOString();

    await this.bus.publish(
      createEvent("dynamic:complete", runId, {
        context: state.context,
        confirmed: state.dynamicConfirmed,
        interesting: state.dynamicInteresting,
        rejected: state.dynamicRejected,
        errors: state.dynamicErrors,
        totalCostUsd: state.dynamicCostUsd,
      }),
    );

    await this.runVariantAnalysisPhase(state, runId);

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

  private async publishDynamicAnalysisQueueDepth(state: RunState, runId: string): Promise<void> {
    const queued = Math.max(0, state.dynamicQueue.length - state.dynamicCursor);
    const processed = state.dynamicConfirmed + state.dynamicInteresting + state.dynamicRejected + state.dynamicErrors;

    await this.bus.publish(
      createEvent("dynamic:queue-depth", runId, {
        context: state.context,
        queued,
        inFlight: state.dynamicInFlight,
        processed,
        total: state.dynamicTotal,
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

  const completedAt = new Date().toISOString();
  state.stageTimestamps.pipelineEnd = completedAt;

  // Compute aggregate run metrics
  const triageCost = state.totalCostUsd - state.verifyCostUsd - state.pocHarnessCostUsd - state.dynamicCostUsd - state.variantAnalysisCostUsd - state.chainAnalysisCostUsd;
  const costs: StageCosts = {
    triage: Math.max(0, triageCost),
    verify: state.verifyCostUsd,
    pocHarness: state.pocHarnessCostUsd,
    dynamicAnalysis: state.dynamicCostUsd,
    variantAnalysis: state.variantAnalysisCostUsd,
  };

  const runMetrics = computeRunMetrics(
    state.scanFindings,
    state.stageTimestamps,
    costs,
  );

  return {
    scanners: [...state.scanners],
    totalFindings: state.totalFindings,
    queuedForTriage: state.triageTotal,
    skippedAlreadyTriaged: state.skippedAlreadyTriaged,
    skippedLowConfidence: state.verifyEnabled ? state.skippedLowConfidence : undefined,
    skippedByFpFilter: state.skippedByFpFilter > 0 ? state.skippedByFpFilter : undefined,
    skippedByClassifier: state.skippedByClassifier > 0 ? state.skippedByClassifier : undefined,
    softSuppressedFindings: state.softSuppressedFindings > 0 ? state.softSuppressedFindings : undefined,
    skippedByLlmRescore: state.skippedByLlmRescore > 0 ? state.skippedByLlmRescore : undefined,
    corroboratedClusters: state.corroboratedClusters > 0 ? state.corroboratedClusters : undefined,
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
    dynamicConfirmed: state.dynamicAnalysisEnabled ? state.dynamicConfirmed : undefined,
    dynamicInteresting: state.dynamicAnalysisEnabled ? state.dynamicInteresting : undefined,
    dynamicRejected: state.dynamicAnalysisEnabled ? state.dynamicRejected : undefined,
    dynamicErrors: state.dynamicAnalysisEnabled ? state.dynamicErrors : undefined,
    dynamicCostUsd: state.dynamicAnalysisEnabled ? state.dynamicCostUsd : undefined,
    variantFindings: state.variantFindings > 0 ? state.variantFindings : undefined,
    variantAnalysisCostUsd: state.variantAnalysisCostUsd > 0 ? state.variantAnalysisCostUsd : undefined,
    chainCount: state.exploitChains.length > 0 ? state.exploitChains.length : undefined,
    chainAnalysisCostUsd: state.chainAnalysisCostUsd > 0 ? state.chainAnalysisCostUsd : undefined,
    budgetExceeded: state.budgetExceeded || undefined,
    failedTasks: state.failedTasks.length > 0 ? [...state.failedTasks] : undefined,
    extractionDegradation,
    stitchDegradation,
    tiPriorDegraded,
    runMetrics,
    startedAt: state.startedAt,
    completedAt,
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
  const parsed = safeJsonParse<unknown>(raw, null);
  if (!isRecord(parsed)) {
    return fallback;
  }

  return resolveVerifyVerdicts(asVerdictArray(parsed["verifyVerdicts"]) ?? fallback);
}

function parseScanOptsJson(raw: string): ScanOpts {
  const parsed = safeJsonParse<unknown>(raw);
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

function isScannerVerificationEnabled(config: KuzushiConfig, scannerId: string): boolean {
  const configKey = resolveCapabilityConfigKey(scannerId);
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

function coerceQuickClassifierFindings(value: unknown): Finding[] {
  if (!isRecord(value)) {
    return [];
  }
  return coerceFindings(value["findings"]);
}

function coerceFinding(item: Record<string, unknown>): Finding | null {
  const result = FindingSchema.safeParse(item);
  if (!result.success) {
    const errors = formatZodErrors(result.error.issues);
    const fingerprint = typeof item["fingerprint"] === "string" ? item["fingerprint"] : "<unknown>";
    log.warn(
      `Skipping malformed finding (${fingerprint}): ${errors.map((e) => `${e.path}: ${e.message}`).join("; ")}`,
    );
    return null;
  }

  return result.data;
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
