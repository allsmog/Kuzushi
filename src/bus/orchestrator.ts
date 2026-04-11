import type Database from "better-sqlite3";
import { normalizeTaskIds } from "../agents/registry.js";
import type { TaskRegistry } from "../agents/registry.js";
import type { TaskContext as AgentTaskContext } from "../agents/types.js";
import { chainAnalysisTask } from "../agents/tasks/chain-analysis.js";
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
import { resolveCapabilityConfigKey, normalizeTaskCapabilityIds } from "../capabilities.js";
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
  resolveInitialTaskPlan,
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
import {
  deduplicateByPattern,
  gateVerificationCandidates,
  registerVerifiedPattern,
  type VerifyGateResult,
} from "./orchestrator/verify-gate.js";
import { cheapVerifyCandidates } from "./orchestrator/cheap-verify.js";
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

function isHighConfidenceAgenticFinding(finding: Finding): boolean {
  return (
    !NON_LLM_SCANNERS.has(finding.scanner)
    && finding.scannerConfidence === "HIGH"
    && finding.score >= 8
  );
}

/** Check if a finding has evidence from multi-strategy analysis. */
function hasMultiStrategyEvidence(finding: Finding): boolean {
  return (finding.engineProvenance ?? []).some(
    (e) => typeof e.detail === "string" && e.detail.startsWith("strategy:"),
  );
}
const log = getLogger("orchestrator");

/** CWE classes that are auth/logic bugs — not pattern-matchable by Semgrep. Skip rule gen. */
const SKIP_RULE_GEN_CWES = new Set(["285", "862", "863", "639", "284", "269", "915"]);

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
      // Clean up batch files on fatal error
      if (state) {
        try {
          const { cleanupBatchFiles } = await import("../agent-runtime/batch-files.js");
          cleanupBatchFiles(state.context.repoRoot, event.meta.runId);
        } catch { /* best-effort */ }
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
      skippedByScoreFilter: 0,
      verifyGateAutoAccepted: 0,
      verifyGateSkipped: 0,
      verifyGateCostUsd: 0,
      verifiedPatterns: new Map<string, string>(),
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
      verifyDispatchedFingerprints: new Set(),
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
      autoPatchEnabled: config.autoPatchEnabled === true,
      patchCandidates: new Set(),
      patchQueue: [],
      patchCursor: 0,
      patchInFlight: 0,
      patchCompleted: 0,
      patchVerified: 0,
      patchFailed: 0,
      patchCostUsd: 0,
      patchErrors: 0,
      patchDispatching: false,
      patchStarted: false,
      generatedRules: [],
      ruleSweepCompleted: false,
      ruleSweepFindings: 0,
      stageTimestamps: {
        pipelineStart: event.meta.timestamp,
        pipelineEnd: "",
        scanStart: event.meta.timestamp,
      },
    };

    // Inject monorepo shared context into task outputs so downstream tasks
    // (threat-model-randori, context-enricher, etc.) can read it via upstreamOutputs.
    if (event.payload.monorepoContext) {
      state.taskOutputs.set("monorepo-context", event.payload.monorepoContext);
    }

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

    // Set up patch dispatching if auto-patch is enabled
    if (state.autoPatchEnabled) {
      const { setupPatchDispatching } = await import("./orchestrator/patch-dispatcher.js");
      setupPatchDispatching(this.bus, state, this.deps.db);
    }

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
    state.verifyDispatchedFingerprints = new Set();
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

    const gatedCandidates = await this.runVerifyGateOnCandidates(pendingCandidates, state, runId);

    state.verifyTotal = gatedCandidates.length;
    state.verifyQueue = gatedCandidates.map((item, idx) => ({
      ...item,
      index: idx + 1,
      total: gatedCandidates.length,
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
    const taskPlan = resolveInitialTaskPlan(this.deps.taskRegistry, state.scanners, state.config);
    const dynamicSelectionActive = taskPlan.dynamicSelectionActive;
    let enabledTaskIds = [...taskPlan.enabledTaskIds];

    if (taskPlan.contextGatheringForced) {
      log.info(
        "[orchestrator] enableContextGathering: false ignored — task-selector requires context-gatherer",
      );
    }

    // Track already-completed tasks for dynamic re-resolution
    const completedTaskIds = new Set<string>();
    const taskRetryCount = new Map<string, number>();
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

      // Retry failed tasks up to 5 times before giving up
      const MAX_TASK_RETRIES = 5;
      let retryableFailures = failures;
      for (let retryAttempt = 1; retryAttempt <= MAX_TASK_RETRIES && retryableFailures.length > 0; retryAttempt++) {
        const retryIds = retryableFailures
          .map((f) => f.event.payload.taskId)
          .filter((id) => id !== "task-selector" && (taskRetryCount.get(id) ?? 0) < MAX_TASK_RETRIES);
        if (retryIds.length === 0) break;

        log.info(`Retry attempt ${retryAttempt}/${MAX_TASK_RETRIES} for ${retryIds.length} task(s): ${retryIds.join(", ")}`);
        for (const id of retryIds) taskRetryCount.set(id, (taskRetryCount.get(id) ?? 0) + 1);

        const retryOutcomes = retryIds.map((taskId) => this.waitForTaskOutcome(runId, taskId));
        for (const taskId of retryIds) {
          const task = this.deps.taskRegistry!.get(taskId);
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

        const retryResolved = await allSettledCollect(retryOutcomes);
        const retrySuccesses = retryResolved.filter((o) => o.kind === "complete");
        const retryFinalFailures = retryResolved.filter((o) => o.kind === "error");

        for (const s of retrySuccesses) {
          successes.push(s);
          log.info(`Task "${s.event.payload.taskId}" succeeded on retry attempt ${retryAttempt}`);
        }

        retryableFailures = retryFinalFailures;
      }

      for (const f of retryableFailures) {
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

      if (successes.length === 0 && retryableFailures.length > 0) {
        if (stageHasFindingsProducers) {
          // All findings producers failed (including retries) — fatal, nothing to triage
          await this.bus.publish(
            createEvent("pipeline:error", runId, {
              context: state.context,
              error: `All tasks in stage ${stageIndex} failed: ${retryableFailures.map((f) => f.event.payload.taskId).join(", ")}`,
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
            // Fire budget events after each task so budget:warning/exceeded are
            // emitted promptly, not just at end-of-stage.
            await this.emitBudgetCheck(state, runId);
            if (this.isBudgetExceeded(state)) {
              await this.emitBudgetExceeded(state, runId);
            }
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
          // Resolve capability IDs (e.g. "taint-analysis") to task IDs (e.g. "taint-cwe-select", "taint-iris")
          const resolved = normalizeTaskCapabilityIds(dynamicTasks);
          const newTaskIds = resolved.filter(
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

    // Location-based dedup: merge findings at the same file:line into one,
    // keeping the highest-scored and attaching others as corroborating signals.
    // Prevents 11x triage/verification for the same code location.
    state.scanFindings = deduplicateByLocation(clustered.findings);
    state.totalFindings = state.scanFindings.length;
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

    state.skippedByLlmRescore = 0;
    if (state.config.llmRescoreEnabled) {
      const rescoreWindow = selectFindingsForRescore(filteredFindings, state.scanOpts.maxFindings);
      const rescoredFingerprints = new Set(rescoreWindow.map((finding) => finding.fingerprint));
      const untouched = filteredFindings.filter(
        (finding) => !rescoredFingerprints.has(finding.fingerprint),
      );
      const rescoreResults = await rescoreFindings(rescoreWindow, {
        model: state.config.llmRescoreModel,
        threshold: state.config.llmRescoreThreshold,
        repoRoot: state.context.scanPath ?? state.context.repoRoot,
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
          projectRoot: state.context.repoRoot,
          workRoot: state.context.scanPath ?? state.context.repoRoot,
          repoRoot: state.context.scanPath ?? state.context.repoRoot,
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
          projectRoot: state.context.repoRoot,
          workRoot: state.context.scanPath ?? state.context.repoRoot,
          repoRoot: state.context.scanPath ?? state.context.repoRoot,
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

    // Pre-triage score gate: drop findings below triageMinScore before any LLM call.
    const minScore = state.config.triageMinScore;
    let pendingAboveThreshold = pendingFindings;
    if (typeof minScore === "number" && minScore > 0) {
      pendingAboveThreshold = pendingFindings.filter((f) => getRankingScore(f) >= minScore);
      state.skippedByScoreFilter = pendingFindings.length - pendingAboveThreshold.length;
      if (state.skippedByScoreFilter > 0) {
        log.info(`[score-gate] Dropped ${state.skippedByScoreFilter} findings below score ${minScore}`);
      }
    }

    let triageCandidates = capFindingsForTriage(
      pendingAboveThreshold,
      state.config.triageMaxFindings ?? state.scanOpts.maxFindings,
    );

    if (state.config.skipTriageForHighConfidenceAgentic) {
      log.warn(
        "skipTriageForHighConfidenceAgentic no longer skips triage; prioritizing matching findings instead.",
      );
      const prioritized = triageCandidates.filter(isHighConfidenceAgenticFinding);
      const remaining = triageCandidates.filter((finding) => !isHighConfidenceAgenticFinding(finding));
      triageCandidates = [...prioritized, ...remaining];
    }

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
    state.verifyDispatchedFingerprints = new Set();
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
        skippedAlreadyTriaged: state.skippedAlreadyTriaged,
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

    handleTriageResultState(
      state,
      runId,
      event.payload.finding,
      event.payload.result,
      event.payload.costUsd,
      shouldVerifyFinding,
      this.deps,
    );

    // Pipeline: if the finding was added to verifyCandidates by handleTriageResultState,
    // immediately queue it for verification while triage continues.
    // When the verification gate is enabled, skip pipelining so all candidates go through
    // the gate in a single batch after triage completes (the gate needs the full picture).
    if (
      state.config.verifyGateEnabled !== true
      && state.verifyCandidates.length > 0
      && state.verifyCandidates[state.verifyCandidates.length - 1].finding.fingerprint
        === event.payload.finding.fingerprint
    ) {
      await this.pipelineVerifyCandidate(state, runId, event.payload.finding, event.payload.result);
    }

    // Auto-rule generation: fire-and-forget for TP findings with strategy evidence
    if (
      state.config.multiStrategyAutoRuleGeneration
      && event.payload.result.verdict !== "fp"
      && hasMultiStrategyEvidence(event.payload.finding)
      && !state.generatingRuleFingerprints?.has(event.payload.finding.fingerprint)
    ) {
      if (!state.generatingRuleFingerprints) state.generatingRuleFingerprints = new Set();
      state.generatingRuleFingerprints.add(event.payload.finding.fingerprint);
      this.generateAutoRule(state, runId, event.payload.finding).catch((err) => {
        log.warn(`Auto-rule generation failed: ${toErrorMessage(err)}`);
      });
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
    const finalMetrics = buildRunMetrics(this.deps.db, state);

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
      skippedByScoreFilter: state.skippedByScoreFilter > 0 ? state.skippedByScoreFilter : undefined,
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

    // Store HEAD ref for incremental scanning on next run
    if (state.config.incrementalCache !== false) {
      try {
        const { storeHeadRef } = await import("../incremental.js");
        storeHeadRef(this.deps.db, runId, state.context.repoRoot);
      } catch {
        /* best-effort */
      }
    }

    // Clean up batch files created by session-based queries
    try {
      const { cleanupBatchFiles } = await import("../agent-runtime/batch-files.js");
      cleanupBatchFiles(state.context.repoRoot, runId);
    } catch {
      /* best-effort */
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

  private async generateAutoRule(state: RunState, runId: string, finding: Finding): Promise<void> {
    const { generateRule, validateRule } = await import("../strategies/auto-rule.js");
    const { persistRule, removeRule } = await import("../strategies/rule-persistence.js");
    const evidence = (finding.engineProvenance ?? [])
      .filter((e) => typeof e.detail === "string" && e.detail.startsWith("strategy:"))
      .map((e) => ({ kind: "reasoning-chain" as const, description: e.detail }));
    const rule = await generateRule(finding, evidence.length > 0 ? evidence : undefined, {
      runId,
      projectRoot: state.context.repoRoot,
      workRoot: state.context.scanPath ?? state.context.repoRoot,
      repoRoot: state.context.scanPath ?? state.context.repoRoot,
      scanPath: state.context.scanPath,
      repoName: state.context.repoName,
      config: state.config,
      runtime: this.deps.runtime,
      bus: this.bus,
      upstreamOutputs: state.taskOutputs,
    });
    if (!rule) return;

    // Persist to disk for use in subsequent scans
    const filePath = persistRule(state.context.repoRoot, rule);

    // Validate the rule catches the original finding; remove if it doesn't
    let ruleValid = true;
    if (filePath) {
      try {
        ruleValid = await validateRule(
          filePath,
          finding.filePath,
          finding.startLine,
          state.context.repoRoot,
        );
        if (!ruleValid) {
          log.warn(`Generated rule failed validation — removing: ${filePath}`);
          removeRule(filePath);
        }
      } catch (err) {
        log.warn(`Rule validation error: ${toErrorMessage(err)}`);
      }
    }

    if (ruleValid) {
      state.generatedRules.push(rule);
      await this.bus.publish(createEvent("auto-rule:generated", runId, {
        context: state.context,
        rule,
        sourceFinding: {
          fingerprint: finding.fingerprint,
          filePath: finding.filePath,
          startLine: finding.startLine,
        },
      }));

      // Generalize the rule for broader sweep when variant rule sweep is enabled
      if (state.config.variantRuleSweepEnabled) {
        try {
          const { generateGeneralizedRule } = await import("../strategies/auto-rule.js");
          const taskContext = {
            runId,
            projectRoot: state.context.repoRoot,
            workRoot: state.context.scanPath ?? state.context.repoRoot,
            repoRoot: state.context.scanPath ?? state.context.repoRoot,
            scanPath: state.context.scanPath,
            repoName: state.context.repoName,
            config: state.config,
            runtime: this.deps.runtime,
            bus: this.bus,
            upstreamOutputs: state.taskOutputs,
          };
          const generalized = await generateGeneralizedRule(rule, finding, taskContext);
          if (generalized) {
            // Use distinct vulnClass to avoid filename collision with the original rule
            const genWithSuffix = { ...generalized, vulnClass: `${generalized.vulnClass}-generalized` };
            const genPath = persistRule(state.context.repoRoot, genWithSuffix);
            if (genPath) {
              const genValid = await validateRule(
                genPath,
                finding.filePath,
                finding.startLine,
                state.context.repoRoot,
              );
              if (!genValid) {
                removeRule(genPath);
              } else {
                state.generatedRules.push(generalized);
              }
            }
          }
        } catch (err) {
          log.warn(`Generalized rule generation error: ${toErrorMessage(err)}`);
        }
      }
    }
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
      await this.runRuleSweepPhase(state, runId);
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
            projectRoot: state.context.repoRoot,
            workRoot: state.context.scanPath ?? state.context.repoRoot,
            repoRoot: state.context.scanPath ?? state.context.repoRoot,
            scanPath: state.context.scanPath,
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
        stats: buildReportStats(this.deps.db, state),
        fingerprints: state.scanFindings.map((f) => f.fingerprint),
        exploitChains: state.exploitChains.length > 0 ? state.exploitChains : undefined,
        reportMode: state.context.reportMode,
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

  /**
   * Rule sweep phase: re-scan the codebase with custom rules generated during
   * this pipeline run. Only runs when variantRuleSweepEnabled is true and rules
   * were actually generated.
   */
  private async runRuleSweepPhase(state: RunState, runId: string): Promise<void> {
    if (!state.config.variantRuleSweepEnabled || state.ruleSweepCompleted) {
      return;
    }
    state.ruleSweepCompleted = true;

    if (state.generatedRules.length === 0) {
      return;
    }

    const { loadCustomRulesDir } = await import("../strategies/rule-persistence.js");
    const customDir = loadCustomRulesDir(state.context.repoRoot);
    if (!customDir) {
      return;
    }

    log.info(`[rule-sweep] Scanning with ${state.generatedRules.length} custom rules from ${customDir}`);

    try {
      const { runSemgrep } = await import("../scanners/run-semgrep.js");
      const { selectFindings } = await import("../scanners/normalize-findings.js");

      const sweepOutput = await runSemgrep(
        state.context.repoRoot,
        {
          excludePatterns: state.config.excludePatterns ?? [],
          severity: state.config.severity ?? ["ERROR", "WARNING"],
          fresh: false,
        },
        "semgrep",
        customDir,
      );

      // Convert Semgrep results through the standard finding normalization pipeline
      const sweepFindings = selectFindings(
        { findings: sweepOutput.results.map((r) => ({
          ruleId: r.check_id,
          filePath: r.path,
          startLine: r.start.line,
          severity: r.extra?.severity ?? "WARNING",
          message: r.extra?.message ?? "Custom rule match",
          confidence: r.extra?.metadata?.confidence ?? "MEDIUM",
          subcategory: r.extra?.metadata?.subcategory ?? ["vuln"],
          likelihood: r.extra?.metadata?.likelihood ?? "MEDIUM",
          impact: r.extra?.metadata?.impact ?? "MEDIUM",
          cwe: r.extra?.metadata?.cwe ?? [],
          evidence: r.extra?.lines ?? "",
        })), costUsd: 0 },
        state.context.repoRoot,
        state.context.repoName,
        "HEAD",
        "rule-sweep",
        state.config.variantAnalysisMaxFindings ?? 10,
      );

      // Filter out findings already in the scan — check both fingerprint and
      // location (filePath:startLine) since different scanners use incompatible
      // fingerprint schemes and a sweep finding at the same location as an
      // existing finding is a duplicate.
      const existingFps = new Set(state.scanFindings.map((f) => f.fingerprint));
      const existingLocations = new Set(state.scanFindings.map((f) => `${f.filePath}:${f.startLine}`));
      const newFindings = sweepFindings.filter(
        (f) => !existingFps.has(f.fingerprint) && !existingLocations.has(`${f.filePath}:${f.startLine}`),
      );

      if (newFindings.length > 0) {
        state.ruleSweepFindings = newFindings.length;
        state.scanFindings.push(...newFindings);
        log.info(`[rule-sweep] Found ${newFindings.length} new findings from custom rules`);

        // Persist sweep findings to DB so they appear in reports and survive resume.
        // Tagged with needs_review verdict since they haven't been triaged.
        if (this.deps.db) {
          const { upsertFinding } = await import("../store.js");
          for (const f of newFindings) {
            upsertFinding(this.deps.db, f, {
              fingerprint: f.fingerprint,
              verdict: "needs_review" as const,
              confidence: 0.5,
              rationale: "Discovered by rule sweep — pending triage",
              verificationSteps: [],
              fixPatch: null,
              triageCostUsd: 0,
            }, state.context.repoName, "HEAD");
          }
        }
      }
    } catch (error) {
      log.warn(`[rule-sweep] Error: ${toErrorMessage(error)}`);
    }
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
        repoRoot: state.context.scanPath ?? state.context.repoRoot,
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
    // Support both old pipeline (taint-analysis-label/run) and new IRIS pipeline (taint-cwe-select/iris)
    const hasLabelContext = state.taskOutputs.has("taint-analysis-label")
      || state.taskOutputs.has("taint-cwe-select");
    if (!hasLabelContext) {
      return false;
    }
    return state.scanFindings.some(
      (finding) => finding.scanner === "taint-analysis-run" || finding.scanner === "taint-iris",
    );
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
        labelOutput: state.taskOutputs.get("taint-analysis-label") ?? state.taskOutputs.get("taint-cwe-select"),
        repoContext: state.repoContext,
        refinementDeltaOnly: state.refinementDeltaOnly,
      }),
    );
  }

  /**
   * Pipeline a single verification candidate while triage is still in progress.
   * Adds the finding to the verify queue and dispatches immediately, respecting
   * concurrency limits. Tracks dispatched fingerprints to avoid double-dispatch
   * when startVerification runs after triage completes.
   */
  private async pipelineVerifyCandidate(
    state: RunState,
    runId: string,
    finding: Finding,
    triageResult: TriageResult,
  ): Promise<void> {
    // Guard: only pipeline when verification is enabled and not yet formally started
    // (startVerification handles dispatch after triage completes)
    if (!state.verifyEnabled || state.verificationStarted || state.reportEmitted) {
      return;
    }

    const fp = finding.fingerprint;
    if (state.verifyDispatchedFingerprints.has(fp)) {
      return;
    }

    state.verifyDispatchedFingerprints.add(fp);
    state.verifyTotal += 1;
    state.verifyQueue.push({
      finding,
      triageResult,
      index: state.verifyTotal,
      total: state.verifyTotal, // Will be updated by startVerification for final count
    });

    // Set the DB status to "verifying" on the first pipelined candidate
    if (state.verifyTotal === 1) {
      state.stageTimestamps.verifyStart = new Date().toISOString();
      try {
        updateRunStatus(this.deps.db, state.checkpointRunId, "verifying");
      } catch {
        // Status persistence is best-effort.
      }
    }

    await this.dispatchVerification(state, runId);
  }

  /**
   * Run the verification gate pipeline on a set of candidates:
   * 1. Pattern dedup — auto-accept findings matching already-verified sink patterns
   * 2. LLM gate — cheap Haiku call to decide verify / auto-accept / skip
   * 3. Cheap verify — single-turn Sonnet call for borderline cases
   *
   * Returns the filtered candidates that need full multi-turn verification.
   */
  private async runVerifyGateOnCandidates(
    candidates: VerificationCandidate[],
    state: RunState,
    runId: string,
  ): Promise<VerificationCandidate[]> {
    if (state.config.verifyGateEnabled === false || candidates.length === 0) {
      return candidates;
    }

    try {
      log.info(`Running verification gate on ${candidates.length} candidate(s)`);

      // Step 1: Pattern dedup — auto-accept findings matching verified sink patterns
      const { remaining: afterDedup, autoAccepted: dedupAccepted } =
        deduplicateByPattern(candidates, state);

      for (const result of dedupAccepted) {
        state.verifyGateAutoAccepted += 1;
        const candidate = candidates.find((c) => c.finding.fingerprint === result.fingerprint)!;
        await this.emitSyntheticVerification(state, runId, candidate, result.reason);
      }

      if (dedupAccepted.length > 0) {
        log.info(`Pattern dedup: ${dedupAccepted.length} auto-accepted, ${afterDedup.length} remaining`);
      }

      if (afterDedup.length === 0) return [];

      // Step 2: LLM gate
      const gateResults = await gateVerificationCandidates(
        afterDedup,
        {
          model: state.config.verifyGateModel,
          runtime: this.deps.runtime,
          repoRoot: state.context.scanPath ?? state.context.repoRoot,
        },
      );

      const gateMap = new Map<string, VerifyGateResult>();
      for (const gr of gateResults) gateMap.set(gr.fingerprint, gr);

      const toVerify: VerificationCandidate[] = [];
      const accepted: VerificationCandidate[] = [];
      const toCheapVerify: VerificationCandidate[] = [];
      for (const candidate of afterDedup) {
        const gate = gateMap.get(candidate.finding.fingerprint);
        if (!gate || gate.decision === "verify") {
          toVerify.push(candidate);
        } else if (gate.decision === "auto_accept") {
          accepted.push(candidate);
          state.verifyGateAutoAccepted += 1;
        } else if (gate.decision === "cheap_verify") {
          toCheapVerify.push(candidate);
        } else {
          state.verifyGateSkipped += 1;
        }
      }

      for (const candidate of accepted) {
        const gate = gateMap.get(candidate.finding.fingerprint);
        await this.emitSyntheticVerification(
          state, runId, candidate,
          gate?.reason ?? "Auto-accepted by verification gate",
        );
      }

      // Step 3: Cheap single-turn verification for borderline cases
      if (toCheapVerify.length > 0) {
        log.info(`Running cheap verification on ${toCheapVerify.length} candidate(s)`);
        const cheapResults = await cheapVerifyCandidates(
          toCheapVerify,
          {
            model: state.config.verifyModel ?? state.config.model,
            runtime: this.deps.runtime,
            repoRoot: state.context.scanPath ?? state.context.repoRoot,
          },
        );

        for (const cr of cheapResults) {
          const candidate = toCheapVerify.find((c) => c.finding.fingerprint === cr.fingerprint)!;
          state.verifyCostUsd += cr.costUsd;
          state.totalCostUsd += cr.costUsd;
          await this.bus.publish(
            createEvent("verification:result", runId, {
              context: state.context,
              finding: candidate.finding,
              triageResult: candidate.triageResult,
              result: cr.verification,
              costUsd: cr.costUsd,
              index: 0,
              total: 0,
            }),
          );
        }
      }

      const skipped = afterDedup.length - toVerify.length - accepted.length - toCheapVerify.length;
      log.info(
        `Verification gate: ${toVerify.length} full-verify, ${toCheapVerify.length} cheap-verify, `
        + `${accepted.length} auto-accepted, ${skipped} skipped`
        + (dedupAccepted.length > 0 ? ` (+ ${dedupAccepted.length} pattern-deduped)` : ""),
      );

      return toVerify;
    } catch (error) {
      log.warn(`Verification gate failed, proceeding with all candidates: ${toErrorMessage(error)}`);
      return candidates;
    }
  }

  private async emitSyntheticVerification(
    state: RunState,
    runId: string,
    candidate: VerificationCandidate,
    reason: string,
  ): Promise<void> {
    await this.bus.publish(
      createEvent("verification:result", runId, {
        context: state.context,
        finding: candidate.finding,
        triageResult: candidate.triageResult,
        result: {
          fingerprint: candidate.finding.fingerprint,
          exploitable: true,
          pocPayload: null,
          pocDescription: reason,
          attackVector: null,
          preconditions: [],
          confidence: candidate.triageResult.confidence,
          proofLevel: 1,
          proofVerdict: "exploited" as const,
          verifyCostUsd: 0,
        },
        costUsd: 0,
        index: 0,
        total: 0,
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
      // Filter out candidates already pipelined during triage
      const remaining = state.verifyCandidates.filter(
        (c) => !state.verifyDispatchedFingerprints.has(c.finding.fingerprint),
      );

      // Rank remaining candidates: highest-score first, triage confidence as tiebreaker,
      // presence of structured evidence (taintPath) as final tiebreaker.
      const ranked = remaining.sort((a, b) => {
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

      const gatedCandidates = await this.runVerifyGateOnCandidates(ranked, state, runId);

      // Append newly ranked candidates to the existing queue (pipelined items are already there)
      const pipelinedCount = state.verifyDispatchedFingerprints.size;
      const finalTotal = pipelinedCount + gatedCandidates.length;
      for (const [idx, item] of gatedCandidates.entries()) {
        state.verifyQueue.push({
          ...item,
          index: pipelinedCount + idx + 1,
          total: finalTotal,
        });
      }
      state.verifyTotal = finalTotal;
      // Don't reset verifyCursor — pipelined dispatch already advanced it
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

    if (!state.stageTimestamps.verifyStart) {
      state.stageTimestamps.verifyStart = new Date().toISOString();
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

    // Pipelined verifications may have already completed before startVerification ran.
    // Now that verificationStarted is true, check if we're already done.
    if (this.isVerificationDone(state)) {
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

    // Register verified exploitable patterns for sink-dedup on subsequent candidates
    if (event.payload.result.exploitable) {
      registerVerifiedPattern(
        state.verifiedPatterns,
        event.payload.finding,
        event.payload.triageResult,
      );
    }

    // Auto-rule generation: fire-and-forget for verified exploitable findings.
    // Skip auth/logic CWEs that can't be pattern-matched by Semgrep.
    const ruleGenConfidence = event.payload.result.compositeConfidence ?? event.payload.result.confidence;
    const findingCwes = event.payload.finding.cwe ?? [];
    const isAuthLogicCwe = findingCwes.some((c) => SKIP_RULE_GEN_CWES.has(c.replace(/^CWE-/, "")));
    if (
      state.config.autoRuleGeneration
      && event.payload.result.exploitable
      && typeof ruleGenConfidence === "number"
      && ruleGenConfidence >= 0.7
      && !isAuthLogicCwe
      && !state.generatingRuleFingerprints?.has(event.payload.finding.fingerprint)
    ) {
      if (!state.generatingRuleFingerprints) state.generatingRuleFingerprints = new Set();
      state.generatingRuleFingerprints.add(event.payload.finding.fingerprint);
      this.generateAutoRule(state, runId, event.payload.finding).catch((err) => {
        log.warn(`Post-verification rule generation failed: ${toErrorMessage(err)}`);
      });
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
    await this.runRuleSweepPhase(state, runId);

    await this.bus.publish(
      createEvent("report:requested", runId, {
        context: state.context,
        stats: buildReportStats(this.deps.db, state),
        fingerprints: state.scanFindings.map((f) => f.fingerprint),
        exploitChains: state.exploitChains.length > 0 ? state.exploitChains : undefined,
        reportMode: state.context.reportMode,
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
    await this.runRuleSweepPhase(state, runId);

    await this.bus.publish(
      createEvent("report:requested", runId, {
        context: state.context,
        stats: buildReportStats(this.deps.db, state),
        fingerprints: state.scanFindings.map((f) => f.fingerprint),
        exploitChains: state.exploitChains.length > 0 ? state.exploitChains : undefined,
        reportMode: state.context.reportMode,
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
        (finding.scanner === "taint-iris" || finding.scanner === "taint-analysis-run")
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
    await this.runRuleSweepPhase(state, runId);

    await this.bus.publish(
      createEvent("report:requested", runId, {
        context: state.context,
        stats: buildReportStats(this.deps.db, state),
        fingerprints: state.scanFindings.map((f) => f.fingerprint),
        exploitChains: state.exploitChains.length > 0 ? state.exploitChains : undefined,
        reportMode: state.context.reportMode,
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

/**
 * Merge findings at the same file:line into one entry, keeping the highest-scored
 * and attaching others as corroborating signals. Prevents N-way triage/verification
 * for findings from different scanners at the same code location.
 *
 * Threat-model findings (scanner starts with "threat-model-") use a scanner-scoped
 * key so they survive alongside detector findings at the same location. This
 * preserves the STRIDE/PASTA context that would otherwise be lost as a bare
 * corroborating signal.
 */
function deduplicateByLocation(findings: Finding[]): Finding[] {
  const byLocation = new Map<string, Finding[]>();
  for (const f of findings) {
    // Threat-model findings get a scanner-scoped key so they don't merge
    // with detector findings at the same location.
    const key = isThreatModelScanner(f.scanner)
      ? `tm:${f.scanner}:${f.filePath}:${f.startLine}`
      : `${f.filePath}:${f.startLine}`;
    const group = byLocation.get(key);
    if (group) {
      group.push(f);
    } else {
      byLocation.set(key, [f]);
    }
  }

  const deduped: Finding[] = [];
  for (const group of byLocation.values()) {
    if (group.length === 1) {
      deduped.push(group[0]);
      continue;
    }
    // Sort by score descending — keep highest as primary
    group.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
    const primary = group[0];
    const others = group.slice(1);

    // Attach others as corroborating signals
    const existing = primary.corroboratingSignals ?? [];
    const newSignals = others.map((f) => ({
      scanner: f.scanner,
      fingerprint: f.fingerprint,
      ruleId: f.ruleId,
      filePath: f.filePath,
      startLine: f.startLine,
      cwe: f.cwe,
      score: f.score ?? 0,
    }));
    primary.corroboratingSignals = [...existing, ...newSignals];
    deduped.push(primary);
  }

  // Cross-reference: attach bidirectional corroborating signals between
  // threat-model findings and detector findings at the same file:line.
  const detectorByLoc = new Map<string, Finding>();
  const threatModelByLoc = new Map<string, Finding[]>();
  for (const f of deduped) {
    const loc = `${f.filePath}:${f.startLine}`;
    if (isThreatModelScanner(f.scanner)) {
      const group = threatModelByLoc.get(loc) ?? [];
      group.push(f);
      threatModelByLoc.set(loc, group);
    } else {
      detectorByLoc.set(loc, f);
    }
  }
  for (const [loc, tmFindings] of threatModelByLoc) {
    const detector = detectorByLoc.get(loc);
    if (!detector) continue;
    const detectorSignal = {
      scanner: detector.scanner,
      fingerprint: detector.fingerprint,
      ruleId: detector.ruleId,
      filePath: detector.filePath,
      startLine: detector.startLine,
      cwe: detector.cwe,
      score: detector.score ?? 0,
    };
    for (const tm of tmFindings) {
      // Attach detector as corroborating signal on threat-model finding
      tm.corroboratingSignals = [...(tm.corroboratingSignals ?? []), detectorSignal];
      // Attach threat-model as corroborating signal on detector finding
      detector.corroboratingSignals = [...(detector.corroboratingSignals ?? []), {
        scanner: tm.scanner,
        fingerprint: tm.fingerprint,
        ruleId: tm.ruleId,
        filePath: tm.filePath,
        startLine: tm.startLine,
        cwe: tm.cwe,
        score: tm.score ?? 0,
      }];
    }
  }

  if (deduped.length < findings.length) {
    log.info(`[location-dedup] Merged ${findings.length} findings into ${deduped.length} (${findings.length - deduped.length} duplicates absorbed as corroborating signals)`);
  }

  return deduped;
}

function isThreatModelScanner(scanner: string): boolean {
  return scanner.startsWith("threat-model-");
}

export function registerOrchestrator(
  bus: MessageBus,
  deps: OrchestratorDeps,
): PipelineOrchestrator {
  return new PipelineOrchestrator(bus, deps);
}

function buildReportStats(
  db: Database.Database,
  state: RunState,
): Partial<PipelineStats> {
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

  const runMetrics = buildRunMetrics(db, state);

  return {
    scanners: [...state.scanners],
    totalFindings: state.totalFindings,
    queuedForTriage: state.triageTotal,
    skippedAlreadyTriaged: state.skippedAlreadyTriaged,
    skippedLowConfidence: state.verifyEnabled ? state.skippedLowConfidence : undefined,
    skippedByFpFilter: state.skippedByFpFilter > 0 ? state.skippedByFpFilter : undefined,
    skippedByScoreFilter: state.skippedByScoreFilter > 0 ? state.skippedByScoreFilter : undefined,
    softSuppressedFindings: state.softSuppressedFindings > 0 ? state.softSuppressedFindings : undefined,
    skippedByLlmRescore: state.skippedByLlmRescore > 0 ? state.skippedByLlmRescore : undefined,
    corroboratedClusters: state.corroboratedClusters > 0 ? state.corroboratedClusters : undefined,
    triaged: state.triaged,
    triageErrors: state.triageErrors,
    totalCostUsd: state.totalCostUsd,
    verified: state.verifyEnabled ? state.verified : undefined,
    verifyErrors: state.verifyEnabled ? state.verifyErrors : undefined,
    verifyCostUsd: state.verifyEnabled ? state.verifyCostUsd : undefined,
    verifyGateAutoAccepted: state.verifyGateAutoAccepted > 0 ? state.verifyGateAutoAccepted : undefined,
    verifyGateSkipped: state.verifyGateSkipped > 0 ? state.verifyGateSkipped : undefined,
    verifyGateCostUsd: state.verifyGateCostUsd > 0 ? state.verifyGateCostUsd : undefined,
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
    ruleSweepFindings: state.ruleSweepFindings > 0 ? state.ruleSweepFindings : undefined,
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

function buildRunMetrics(
  db: Database.Database,
  state: RunState,
) {
  const triageCost = state.totalCostUsd - state.verifyCostUsd - state.pocHarnessCostUsd - state.dynamicCostUsd - state.variantAnalysisCostUsd - state.chainAnalysisCostUsd;
  const costs: StageCosts = {
    triage: Math.max(0, triageCost),
    verify: state.verifyCostUsd,
    pocHarness: state.pocHarnessCostUsd,
    dynamicAnalysis: state.dynamicCostUsd,
    variantAnalysis: state.variantAnalysisCostUsd,
  };

  let findings: Finding[] = state.scanFindings;
  try {
    findings = getActionableFindings(db, state.context.repoName, {
      includeFalsePositives: true,
      fingerprints: state.scanFindings.map((finding) => finding.fingerprint),
    }) as unknown as Finding[];
  } catch (error) {
    log.warn(`Falling back to in-memory findings for run metrics: ${toErrorMessage(error)}`);
  }

  return computeRunMetrics(
    findings,
    state.stageTimestamps,
    costs,
    {
      corroboratedClusters: state.corroboratedClusters,
      verified: state.verifyEnabled ? state.verified : 0,
      verifyErrors: state.verifyEnabled ? state.verifyErrors : 0,
      pocHarnessGenerated: state.pocHarnessEnabled ? state.pocHarnessGenerated : 0,
      pocHarnessSkipped: state.pocHarnessEnabled ? state.pocHarnessSkipped : 0,
      pocHarnessErrors: state.pocHarnessEnabled ? state.pocHarnessErrors : 0,
    },
  );
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
