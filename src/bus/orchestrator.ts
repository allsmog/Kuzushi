import type Database from "better-sqlite3";
import { callGraphAssistTask } from "../agents/tasks/call-graph-assist.js";
import { chainAnalysisTask } from "../agents/tasks/chain-analysis.js";
import { reachabilityCheckTask } from "../agents/tasks/reachability-check.js";
import { resolveStageModel } from "../agents/tasks/runtime-overrides.js";
import { SELECTABLE_TASK_IDS } from "../agents/tasks/task-selector.js";
import type { DagRunContext as AgentDagRunContext, DagNodeImpl } from "../agents/types.js";
import { normalizeTaskCapabilityIds, resolveCapabilityConfigKey } from "../capabilities.js";
import { PipelineHookChain } from "../hooks/chain.js";
import { loadHooksFromFile } from "../hooks/loader.js";
import type { HookContext } from "../hooks/types.js";
import { getLogger } from "../logger.js";
import { normalizeDagIds } from "../modules/dag-registry.js";
import { loadPrecedents } from "../precedents.js";
import { evaluateQualityGates, type QualityGateResult } from "../quality-gate.js";
import { coerceContextEnrichment, coerceRepoContext } from "../repo-context.js";
import { DesignDecisionClassifier } from "../scanners/design-decision-classifier.js";
import { HardExclusionFilter } from "../scanners/fp-filter.js";
import { rescoreFindings } from "../scanners/llm-rescore.js";
import {
  applyRescoreResults,
  capFindingsForTriage,
  clusterFindings,
  getRankingScore,
  selectFindingsForRescore,
} from "../scanners/normalization.js";
import type { Finding } from "../scanners/types.js";
import { FindingSchema, formatZodErrors } from "../schemas.js";
import { computeRunMetrics, type StageCosts } from "../scoring/run-metrics.js";
import {
  getActionableFindings,
  getPocHarnessedFingerprints,
  getRun,
  getStoredTriageResults,
  getStoredVerificationResults,
  getTriagedFingerprints,
  getVerifiedFingerprints,
  hasRunCheckpoint,
} from "../store.js";
import { attachTaskOutputMeta, getTaskOutputMeta } from "../task-output-meta.js";
import type {
  KuzushiConfig,
  ScanOpts,
  TriageResult,
  Verdict,
  VerificationResult,
} from "../types.js";
import { safeJsonParse } from "../utils/safe-json.js";
import { isRecord, normalizeCostUsd, toErrorMessage } from "../utils.js";
import type {
  BusHandlerErrorEvent,
  DynamicAnalysisErrorEvent,
  DynamicAnalysisResultEvent,
  PipelineErrorEvent,
  PipelineStartEvent,
  PipelineStats,
  PocHarnessErrorEvent,
  PocHarnessResultEvent,
  ReportCompleteEvent,
  ScanCompleteEvent,
  ScanFindingEvent,
  TaintAnalysisRefinementErrorEvent,
  TaintAnalysisRefinementResultEvent,
  TaskCompleteEvent,
  TaskErrorEvent,
  TriageErrorEvent,
  TriageResultEvent,
  VerificationErrorEvent,
  VerificationResultEvent,
} from "./events.js";
import { createEvent } from "./helpers.js";
import { cheapVerifyCandidates } from "./orchestrator/cheap-verify.js";
import {
  dispatchPocHarness as dispatchPocHarnessQueue,
  handlePocHarnessErrorState,
  handlePocHarnessResultState,
  isPocHarnessDone as isPocHarnessQueueDone,
  publishPocQueueDepth,
} from "./orchestrator/poc-dispatcher.js";
import { createScanFindingsStore } from "./orchestrator/scan-findings-store.js";
import {
  collectTransitiveDeps,
  injectThreatModelPolicyCandidates,
  resolveInitialTaskPlan,
  resolveOrderWithPolicyEdges,
} from "./orchestrator/task-policy.js";
import {
  dispatchTriage as dispatchTriageQueue,
  handleTriageError as handleTriageErrorState,
  handleTriageResult as handleTriageResultState,
  isTriageDone as isTriageQueueDone,
  publishTriageQueueDepth,
} from "./orchestrator/triage-dispatcher.js";
import type {
  DynamicAnalysisCandidate,
  OrchestratorDeps,
  PocHarnessCandidate,
  RunState,
  VerificationCandidate,
} from "./orchestrator/types.js";
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
import { wrapRuntimeWithActivityForwarding } from "./runtime-forwarding.js";
import type { MessageBus } from "./types.js";
import { runVariantAnalysis } from "./workers/variant-analysis-worker.js";

/** Scanners whose findings come from static analysis tools, not LLM assessment. */
const NON_LLM_SCANNERS = new Set(["semgrep", "codeql"]);

function isHighConfidenceAgenticFinding(finding: Finding): boolean {
  return (
    !NON_LLM_SCANNERS.has(finding.taskId) &&
    finding.scannerConfidence === "HIGH" &&
    finding.score >= 8
  );
}

/** Check if a finding has evidence from multi-strategy analysis. */
function hasMultiStrategyEvidence(finding: Finding): boolean {
  return (finding.engineProvenance ?? []).some(
    (e) => typeof e.detail === "string" && e.detail.startsWith("strategy:"),
  );
}
const log = getLogger("orchestrator");
const CONTEXT_GATHERER_ID = "context:context-gatherer";
const CONTEXT_ENRICHER_ID = "context:context-enricher";
const TASK_SELECTOR_ID = "pipeline:task-selector";

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
    const deadline = Date.now() + timeoutMs;

    for (const [_runId, state] of this.runs) {
      // Wait for all in-flight queues to reach 0
      while (
        (state.inFlight > 0 ||
          state.verifyInFlight > 0 ||
          state.pocHarnessInFlight > 0 ||
          state.dynamicInFlight > 0) &&
        Date.now() < deadline
      ) {
        await new Promise((r) => setTimeout(r, 100));
      }

      // Persist interrupted state
      try {
        const status = hasRunCheckpoint(this.deps.db, state.checkpointRunId)
          ? "interrupted"
          : "aborted";
        await this.bus.publish(
          createEvent("run:status", state.checkpointRunId, {
            context: state.context,
            status,
          }),
        );
      } catch {
        // Best-effort persistence during shutdown.
      }
    }
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
  getRunHooks(
    runId: string,
  ): { hookChain: PipelineHookChain; hookContext: HookContext } | undefined {
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

    this.bus.subscribe<TaintAnalysisRefinementResultEvent>(
      "taint-analysis:refinement-result",
      async (event) => {
        await this.handleTaintAnalysisRefinementResult(event);
      },
    );

    this.bus.subscribe<TaintAnalysisRefinementErrorEvent>(
      "taint-analysis:refinement-error",
      async (event) => {
        await this.handleTaintAnalysisRefinementError(event);
      },
    );

    this.bus.subscribe<BusHandlerErrorEvent>("bus:handler-error", async (event) => {
      await this.handleBusHandlerError(event);
    });

    this.bus.subscribe<PipelineErrorEvent>("pipeline:error", async (event) => {
      if (!event.payload.fatal) {
        return;
      }
      const fatalRunId = event.meta.runId;
      const state = this.runs.get(fatalRunId);
      const _checkpointRunId = state?.checkpointRunId ?? fatalRunId;
      try {
        if (state) {
          await this.bus.publish(
            createEvent("run:status", fatalRunId, { context: state.context, status: "error" }),
          );
        }
      } catch {
        // Best-effort status persistence for fatal run failures.
      }
      // Clean up batch files on fatal error
      if (state) {
        try {
          const { cleanupBatchFiles } = await import("../agent-runtime/batch-files.js");
          cleanupBatchFiles(state.context.repoRoot, event.meta.runId);
        } catch {
          /* best-effort */
        }
      }
      this.runs.delete(event.meta.runId);
    });
  }

  private async handlePipelineStart(event: PipelineStartEvent): Promise<void> {
    const runId = event.meta.runId;
    const { context, config, scanOpts, resumeRunId, seedTaskOutputs } = event.payload;

    const tasks = normalizeDagIds(
      scanOpts.tasks ?? config.tasks ?? ["semgrep"],
      this.deps.dagRegistry,
    );

    const state: RunState = {
      context,
      checkpointRunId: resumeRunId ?? runId,
      resuming: false,
      config,
      scanOpts,
      tasks,
      startedAt: event.meta.timestamp,
      scanFindings: createScanFindingsStore({
        backend: config.scanFindingsBackend,
        db: this.deps.db,
        runId: resumeRunId ?? runId,
      }),
      totalFindings: 0,
      skippedAlreadyTriaged: 0,
      skippedLowConfidence: 0,
      skippedByFpFilter: 0,
      skippedByScoreFilter: 0,
      autoClassifiedByDesign: 0,
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
      collectScanFindingEvents: false,
      repoContext: undefined,
      enrichedRepoContext: undefined,
      taskOutputs: new Map<string, unknown>(seedTaskOutputs ?? []),
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

    // Load operator scan context for prompt injection
    try {
      const { loadOperatorScanContext, formatOperatorContextForPrompt } = await import(
        "../operator-context.js"
      );
      const opCtx = loadOperatorScanContext(context.repoRoot);
      if (opCtx) {
        state.operatorContext = formatOperatorContextForPrompt(opCtx);
      }
    } catch {
      // Non-fatal: operator context loading failure shouldn't break pipeline
    }

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

    // Invoke beforeScan hook
    if (state.hookChain) {
      try {
        await state.hookChain.beforeScan(this.buildHookContext(state));
      } catch (error) {
        log.warn(`[hooks] beforeScan hook error: ${toErrorMessage(error)}`);
      }
    }

    await this.runTaskDag(state, runId);
  }

  private async resumeFromCheckpoint(
    state: RunState,
    runId: string,
    resumeRunId: string,
  ): Promise<void> {
    let run: ReturnType<typeof getRun>;
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

    if (run.status === "error" || run.status === "aborted") {
      await this.bus.publish(
        createEvent("pipeline:error", runId, {
          context: state.context,
          error: `Run "${resumeRunId}" ended as ${run.status} and cannot be resumed. Re-run without --resume to start fresh.`,
          fatal: true,
        }),
      );
      return;
    }

    if (!hasRunCheckpoint(this.deps.db, resumeRunId)) {
      await this.bus.publish(
        createEvent("pipeline:error", runId, {
          context: state.context,
          error: `Run "${resumeRunId}" has no checkpoint. Re-run without --resume to start fresh.`,
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

    const storedConfig = safeJsonParse<unknown>(run.configJson, null);
    if (isRecord(storedConfig)) {
      state.config = {
        ...state.config,
        ...(storedConfig as Partial<KuzushiConfig>),
      };
    }
    state.verifyEnabled = state.config.verify === true;
    state.pocHarnessEnabled = state.config.pocHarness === true;
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
        state.scanFindings.clear();
        state.collectScanFindingEvents = false;
        await this.runTaskDag(state, runId);
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
      state.scanFindings.replace(clusterFindings(coerceFindings(parsed)).findings);
      state.totalFindings = state.scanFindings.count();
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
        totalFindings: state.scanFindings.count(),
      }),
    );
  }

  private async resumeVerificationFromCheckpoint(state: RunState, runId: string): Promise<void> {
    let verifiedFingerprints = new Set<string>();
    let triageByFingerprint = new Map<string, TriageResult>();

    try {
      verifiedFingerprints = getVerifiedFingerprints(this.deps.db);
      triageByFingerprint = getStoredTriageResults(this.deps.db, state.scanFindings.fingerprints());
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

    state.totalFindings = state.scanFindings.count();
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
    for (const finding of state.scanFindings.iterate()) {
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
      const fingerprints = state.scanFindings.fingerprints();
      triageByFingerprint = getStoredTriageResults(this.deps.db, fingerprints);
      verificationByFingerprint = getStoredVerificationResults(this.deps.db, fingerprints);
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

    state.totalFindings = state.scanFindings.count();
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
    for (const finding of state.scanFindings.iterate()) {
      const triageResult = triageByFingerprint.get(finding.fingerprint);
      if (!triageResult) {
        continue;
      }

      if (!shouldVerifyFinding(state, finding, triageResult)) {
        continue;
      }

      const verificationResult = verificationByFingerprint.get(finding.fingerprint);
      if (!verificationResult?.exploitable) {
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
    let taskPlan: ReturnType<typeof resolveInitialTaskPlan>;
    try {
      taskPlan = resolveInitialTaskPlan(this.deps.dagRegistry, state.tasks, state.config, {
        disabledTasks: state.scanOpts.disabledTasks,
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
    const dynamicSelectionActive = taskPlan.dynamicSelectionActive;
    const disabledTaskIds = new Set(taskPlan.disabledTaskIds);
    let enabledTaskIds = [...taskPlan.enabledTaskIds];

    if (taskPlan.contextGatheringForced) {
      log.info(
        "[orchestrator] enableContextGathering: false ignored — task-selector requires context-gatherer",
      );
    }

    // Track already-completed tasks for dynamic re-resolution
    const completedTaskIds = new Set<string>(
      [...state.taskOutputs.keys()].filter((taskId) => this.deps.dagRegistry!.has(taskId)),
    );
    const taskRetryCount = new Map<string, number>();
    const dynamicTasksProcessed = new Set<string>();
    let taskSelectorFallbackApplied = false;

    let stages: string[][];
    try {
      stages = resolveOrderWithPolicyEdges(this.deps.dagRegistry, enabledTaskIds);
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
      const pendingGroup = group.filter((taskId) => !completedTaskIds.has(taskId));
      if (pendingGroup.length === 0) {
        await this.bus.publish(
          createEvent("stage:complete", runId, {
            context: state.context,
            stageIndex,
            taskIds: [...group],
          }),
        );
        continue;
      }

      // Evaluate conditions: split group into tasks to run vs skip
      const tasksToRun: string[] = [];
      const tasksToSkip: string[] = [];
      for (const taskId of pendingGroup) {
        const task = this.deps.dagRegistry.get(taskId);
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

      const upstreamSnapshot = new Map(state.taskOutputs);
      await Promise.all(
        tasksToRun.map((taskId) => {
          const task = this.deps.dagRegistry.get(taskId);
          return this.bus.publish(
            createEvent("task:start", runId, {
              context: state.context,
              taskId,
              outputKind: task.outputKind,
              input: state.scanOpts,
              upstreamOutputs: upstreamSnapshot,
            }),
          );
        }),
      );

      const resolved = await allSettledCollect(outcomes);
      const successes = resolved.filter((o) => o.kind === "complete");
      const failures = resolved.filter((o) => o.kind === "error");

      // Retry failed tasks up to 5 times before giving up
      const MAX_TASK_RETRIES = 5;
      let retryableFailures = failures;
      for (
        let retryAttempt = 1;
        retryAttempt <= MAX_TASK_RETRIES && retryableFailures.length > 0;
        retryAttempt++
      ) {
        const retryIds = retryableFailures
          .map((f) => f.event.payload.taskId)
          .filter(
            (id) => id !== TASK_SELECTOR_ID && (taskRetryCount.get(id) ?? 0) < MAX_TASK_RETRIES,
          );
        if (retryIds.length === 0) break;

        log.info(
          `Retry attempt ${retryAttempt}/${MAX_TASK_RETRIES} for ${retryIds.length} task(s): ${retryIds.join(", ")}`,
        );
        for (const id of retryIds) taskRetryCount.set(id, (taskRetryCount.get(id) ?? 0) + 1);

        const retryOutcomes = retryIds.map((taskId) => this.waitForTaskOutcome(runId, taskId));
        const retryUpstreamSnapshot = new Map(state.taskOutputs);
        await Promise.all(
          retryIds.map((taskId) => {
            const task = this.deps.dagRegistry!.get(taskId);
            return this.bus.publish(
              createEvent("task:start", runId, {
                context: state.context,
                taskId,
                outputKind: task.outputKind,
                input: state.scanOpts,
                upstreamOutputs: retryUpstreamSnapshot,
              }),
            );
          }),
        );

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
        const task = this.deps.dagRegistry!.get(taskId);
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
          const { taskId, outputKind, output, costUsd, degradation } = outcome.event.payload;
          const outputForState = degradation
            ? attachTaskOutputMeta(output, {
                costUsd: normalizeCostUsd(costUsd),
                degradation,
              })
            : output;
          state.taskOutputs.set(taskId, outputForState);
          completedTaskIds.add(taskId);

          // Accumulate scan-phase task LLM costs
          const normalizedCost = normalizeCostUsd(costUsd);
          if (normalizedCost > 0) {
            state.totalCostUsd += normalizedCost;
            try {
              await this.bus.publish(
                createEvent("run:cost", state.checkpointRunId, {
                  context: state.context,
                  costUsd: normalizedCost,
                }),
              );
            } catch {
              /* best-effort cost persistence */
            }
            // Fire budget events after each task so budget:warning/exceeded are
            // emitted promptly, not just at end-of-stage.
            await this.emitBudgetCheck(state, runId);
            if (this.isBudgetExceeded(state)) {
              await this.emitBudgetExceeded(state, runId);
            }
          }

          if (outputKind === "findings") {
            state.scanFindings.addAll(coerceFindings(output));
          } else if (outputKind === "threat-model") {
            if (isRecord(output) && Array.isArray(output["findings"])) {
              state.scanFindings.addAll(coerceFindings(output["findings"]));
            }
          }
        }
      }

      // Dynamic task selection: check if any completed task produced a TaskSelectionResult
      // (duck-type check: has recommendedTasks array). If so, merge and re-resolve.
      if (state.config.enableDynamicTaskSelection) {
        const dynamicTasks = this.extractDynamicTasks(
          state,
          completedTaskIds,
          dynamicTasksProcessed,
        );
        if (dynamicTasks.length > 0) {
          // Resolve capability IDs (e.g. "taint-analysis") to task IDs (e.g. "taint-cwe-select", "taint-iris")
          const resolved = normalizeDagIds(
            normalizeTaskCapabilityIds(dynamicTasks),
            this.deps.dagRegistry,
          );
          const newTaskIds = resolved.filter(
            (id) =>
              !enabledTaskIds.includes(id) &&
              this.deps.dagRegistry!.has(id) &&
              !disabledTaskIds.has(id),
          );

          if (newTaskIds.length > 0) {
            log.info(`Dynamic task selection added: ${newTaskIds.join(", ")}`);
            const candidateIds = injectThreatModelPolicyCandidates(this.deps.dagRegistry, [
              ...enabledTaskIds,
              ...collectTransitiveDeps(this.deps.dagRegistry, newTaskIds).filter(
                (id) => !enabledTaskIds.includes(id),
              ),
            ]).filter((id) => !disabledTaskIds.has(id));

            // Re-resolve remaining stages — only commit enabledTaskIds on success
            try {
              const fullStages = resolveOrderWithPolicyEdges(this.deps.dagRegistry, candidateIds);
              enabledTaskIds = candidateIds;
              // Replace remaining stages — skip stages already completed
              const remaining = fullStages
                .filter((stage) => stage.some((id) => !completedTaskIds.has(id)))
                .map((stage) => stage.filter((id) => !completedTaskIds.has(id)));
              stages = [...stages.slice(0, stageIndex + 1), ...remaining];
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
        const selectorSettled = completedTaskIds.has(TASK_SELECTOR_ID);
        const hasSelectableTasks = enabledTaskIds.some(
          (id) => SELECTABLE_TASK_IDS.has(id) && !state.failedTasks.includes(id),
        );

        if (selectorSettled && !hasSelectableTasks) {
          const selectorFailed = state.failedTasks.includes(TASK_SELECTOR_ID);
          const reason = selectorFailed ? "failed" : "recommended no selectable tasks";
          const fallbackIds = [...SELECTABLE_TASK_IDS].filter(
            (id) =>
              !enabledTaskIds.includes(id) &&
              this.deps.dagRegistry!.has(id) &&
              !disabledTaskIds.has(id),
          );
          if (fallbackIds.length > 0) {
            log.warn(
              `task-selector ${reason} — falling back to all selectable tasks: ${fallbackIds.join(", ")}`,
            );
            const candidateIds = injectThreatModelPolicyCandidates(this.deps.dagRegistry, [
              ...enabledTaskIds,
              ...collectTransitiveDeps(this.deps.dagRegistry, fallbackIds).filter(
                (id) => !enabledTaskIds.includes(id),
              ),
            ]).filter((id) => !disabledTaskIds.has(id));
            try {
              const fullStages = resolveOrderWithPolicyEdges(this.deps.dagRegistry, candidateIds);
              enabledTaskIds = candidateIds;
              taskSelectorFallbackApplied = true;
              const remaining = fullStages
                .filter((stage) => stage.some((id) => !completedTaskIds.has(id)))
                .map((stage) => stage.filter((id) => !completedTaskIds.has(id)));
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

    const gatheredContext = coerceRepoContext(state.taskOutputs.get(CONTEXT_GATHERER_ID));
    if (gatheredContext) {
      state.repoContext = gatheredContext;
    }

    const enrichedContext = coerceContextEnrichment(state.taskOutputs.get(CONTEXT_ENRICHER_ID));
    if (enrichedContext) {
      state.enrichedRepoContext = enrichedContext;
    }

    if (state.repoContext || state.enrichedRepoContext) {
      try {
        await this.bus.publish(
          createEvent("run:context-checkpoint", state.checkpointRunId, {
            context: state.context,
            repoContext: { base: state.repoContext, enrichment: state.enrichedRepoContext },
          }),
        );
      } catch {
        // Context checkpoint persistence is best-effort.
      }
    }

    await this.bus.publish(
      createEvent("scan:complete", runId, {
        context: state.context,
        totalFindings: state.scanFindings.count(),
      }),
    );
  }

  private async persistPendingScanOnlyFindings(
    state: RunState,
    findings: Finding[],
  ): Promise<void> {
    if (!this.deps.db || findings.length === 0) {
      return;
    }

    const { upsertFinding } = await import("../store.js");
    for (const finding of findings) {
      upsertFinding(
        this.deps.db,
        finding,
        {
          fingerprint: finding.fingerprint,
          verdict: "needs_review",
          confidence: 0.5,
          rationale: "Captured in scan-only mode — pending triage",
          verificationSteps: [],
          fixPatch: null,
          triageCostUsd: 0,
        },
        state.context.repoName,
        "HEAD",
      );
    }
  }

  private async requestScanOnlyReport(state: RunState, runId: string): Promise<void> {
    if (state.reportRequested) {
      return;
    }

    state.reportRequested = true;

    await this.bus.publish(
      createEvent("report:requested", runId, {
        context: state.context,
        stats: buildReportStats(this.deps.db, state),
        fingerprints: state.scanFindings.fingerprints(),
        exploitChains: undefined,
        reportMode: state.context.reportMode,
      }),
    );

    state.reportEmitted = true;
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
      if (isRecord(output) && Array.isArray(output["recommendedTasks"])) {
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
    return normalizeDagIds(dynamicTasks, this.deps.dagRegistry);
  }

  private waitForTaskOutcome(runId: string, taskId: string): Promise<TaskOutcome> {
    const complete = this.bus
      .waitFor<TaskCompleteEvent>(
        "task:complete",
        (event) => event.meta.runId === runId && event.payload.taskId === taskId,
      )
      .then((event) => ({ kind: "complete" as const, event }));

    const error = this.bus
      .waitFor<TaskErrorEvent>(
        "task:error",
        (event) => event.meta.runId === runId && event.payload.taskId === taskId,
      )
      .then((event) => ({ kind: "error" as const, event }));

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

    // Soft cap on raw findings (#34): once over the threshold, drop
    // new ones and emit a single warning so operators see the cap
    // engaged. Running detectors don't get killed — their post-cap
    // output simply doesn't accumulate. Distinct from `maxFindings`
    // which gates triage downstream.
    const cap = state.scanOpts.maxRawFindings;
    if (typeof cap === "number" && cap > 0 && state.scanFindings.count() >= cap) {
      if (!state.maxRawFindingsWarned) {
        state.maxRawFindingsWarned = true;
        log.warn(
          `--max-raw-findings ${cap} reached — dropping additional scan:finding events. ` +
            "Detectors continue running but their post-cap output is discarded.",
        );
      }
      return;
    }

    state.scanFindings.add(event.payload.finding);
  }

  private async handleScanComplete(event: ScanCompleteEvent): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }
    const scanOnly = state.context.postProcessMode === "scan-only";

    state.stageTimestamps.scanEnd = event.meta.timestamp;

    const clustered = clusterFindings(state.scanFindings.toArray());

    // Location-based dedup: merge findings at the same file:line into one,
    // keeping the highest-scored and attaching others as corroborating signals.
    // Prevents 11x triage/verification for the same code location.
    state.scanFindings.replace(deduplicateByLocation(clustered.findings));
    state.totalFindings = state.scanFindings.count();
    state.corroboratedClusters = clustered.corroboratedClusters;

    try {
      if (!state.resuming && !scanOnly) {
        await this.bus.publish(
          createEvent("run:status", state.checkpointRunId, {
            context: state.context,
            status: "triaging",
          }),
        );
      }
      await this.bus.publish(
        createEvent("run:findings-checkpoint", state.checkpointRunId, {
          context: state.context,
          findings: state.scanFindings.toArray(),
        }),
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
    let filteredFindings = state.scanFindings.toArray();
    state.skippedByFpFilter = 0;
    state.softSuppressedFindings = 0;
    if (state.config.fpFilterEnabled !== false) {
      const customExclusions = [
        ...(state.config.fpFilterCustomExclusions ?? []),
        ...(state.precedents?.hardExclusions ?? []),
      ];
      const fpFilter = new HardExclusionFilter(customExclusions);
      const filterResult = fpFilter.filterFindings(state.scanFindings.toArray());
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
        model: resolveStageModel(state.config, "llm-rescore"),
        threshold: state.config.llmRescoreThreshold,
        repoRoot: state.context.scanPath ?? state.context.repoRoot,
        runtime: this.deps.runtime,
        concurrency: state.config.triageConcurrency,
      });
      const applied = applyRescoreResults(rescoreWindow, rescoreResults);
      filteredFindings = [...applied.findings, ...untouched].sort(
        (a, b) => getRankingScore(b) - getRankingScore(a),
      );
      state.skippedByLlmRescore = applied.skippedByLlmRescore;
      if (state.skippedByLlmRescore > 0) {
        log.info(`[llm-rescore] Excluded ${state.skippedByLlmRescore} findings`);
      }
    }

    // Reachability-assisted ranking: penalize unreachable findings before final sort
    if (state.config.callGraphAssistEnabled === true && filteredFindings.length > 0) {
      filteredFindings = await this.runPostScanTask({
        state,
        runId,
        taskId: "reachability-check",
        detail: "ranking by reachability",
        task: reachabilityCheckTask,
        input: filteredFindings,
      });

      // Call-graph-assist: enrich high-score findings with call-chain evidence
      filteredFindings = await this.runPostScanTask({
        state,
        runId,
        taskId: "call-graph-assist",
        detail: "tracing call chains",
        task: callGraphAssistTask,
        input: filteredFindings,
      });
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

    state.scanFindings.replace(filteredFindings);
    state.totalFindings = filteredFindings.length;

    const pendingFindings = filteredFindings.filter(
      (finding) => !alreadyTriaged.has(finding.fingerprint),
    );

    state.skippedAlreadyTriaged = filteredFindings.length - pendingFindings.length;

    if (scanOnly) {
      await this.persistPendingScanOnlyFindings(state, pendingFindings);
      await this.requestScanOnlyReport(state, runId);
      return;
    }

    // Pre-triage score gate: drop findings below triageMinScore before any LLM call.
    const minScore = state.config.triageMinScore;
    let pendingAboveThreshold = pendingFindings;
    if (typeof minScore === "number" && minScore > 0) {
      pendingAboveThreshold = pendingFindings.filter((f) => getRankingScore(f) >= minScore);
      state.skippedByScoreFilter = pendingFindings.length - pendingAboveThreshold.length;
      if (state.skippedByScoreFilter > 0) {
        log.info(
          `[score-gate] Dropped ${state.skippedByScoreFilter} findings below score ${minScore}`,
        );
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
      const remaining = triageCandidates.filter(
        (finding) => !isHighConfidenceAgenticFinding(finding),
      );
      triageCandidates = [...prioritized, ...remaining];
    }

    // Auto-classify design-decision findings before LLM triage.
    let autoClassifiedResults: Array<{
      finding: Finding;
      result: import("../types.js").TriageResult;
    }> = [];
    if (state.config.designDecisionClassifier !== false) {
      const classifier = new DesignDecisionClassifier();
      const classification = classifier.classify(triageCandidates);
      autoClassifiedResults = classification.autoClassified;
      triageCandidates = classification.remaining;
      state.autoClassifiedByDesign = autoClassifiedResults.length;
      if (autoClassifiedResults.length > 0) {
        log.info(
          `[design-decision] Auto-classified ${autoClassifiedResults.length} findings as by_design`,
        );
      }
    }

    state.triageTotal = triageCandidates.length + autoClassifiedResults.length;
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
        model: resolveStageModel(state.config, "triage"),
        skippedAlreadyTriaged: state.skippedAlreadyTriaged,
      }),
    );

    await this.publishQueueDepth(state, runId);

    // Emit triage:result for auto-classified design-decision findings (zero LLM cost).
    for (const { finding, result } of autoClassifiedResults) {
      await this.bus.publish(
        createEvent("triage:result", runId, {
          context: state.context,
          finding,
          result,
          costUsd: 0,
          attempts: 0,
          index: 0,
          total: 0,
        }),
      );
    }

    if (triageCandidates.length === 0) {
      await this.finishTriageAndRequestReport(state, runId);
      return;
    }

    await this.dispatchTriageBatch(state, runId, triageCandidates);
  }

  /**
   * Run a post-DAG ranking helper (`reachability-check`, `call-graph-assist`)
   * with full UI lifecycle events so the operator sees a sub-task row in the
   * scan stage and the "tasks running" counter stays accurate. These tasks
   * intentionally bypass the scan-worker `task:start` dispatch path because
   * they need `state.scanFindings` after cluster + dedup + filter + LLM
   * rescore — too late to participate in the regular DAG.
   *
   * Failure is best-effort: a thrown error is reported via
   * `scan:post-task-complete{error}` and the original input findings are
   * returned, matching the previous catch-and-continue behaviour.
   */
  private async runPostScanTask(args: {
    state: RunState;
    runId: string;
    taskId: string;
    detail?: string;
    task: DagNodeImpl;
    input: Finding[];
  }): Promise<Finding[]> {
    const { state, runId, taskId, detail, task, input } = args;
    const startedAt = Date.now();
    let costUsd = 0;
    let errorMessage: string | undefined;
    let result: Finding[] = input;

    await this.bus.publish(
      createEvent("scan:post-task-start", runId, {
        context: state.context,
        taskId,
        ...(detail ? { detail } : {}),
      }),
    );

    try {
      const taskContext: AgentDagRunContext = {
        runId,
        projectRoot: state.context.repoRoot,
        workRoot: state.context.scanPath ?? state.context.repoRoot,
        repoRoot: state.context.scanPath ?? state.context.repoRoot,
        scanPath: state.context.scanPath,
        repoName: state.context.repoName,
        config: state.config,
        runtime: wrapRuntimeWithActivityForwarding(
          this.deps.runtime,
          this.bus,
          taskId,
          runId,
          "scan",
        ),
        bus: this.bus,
        upstreamOutputs: new Map(state.taskOutputs),
      };
      if (task.init) {
        await task.init({});
      }
      const output = await task.run(input, taskContext);
      if (Array.isArray(output) && output.length > 0) {
        result = output as Finding[];
      }
      costUsd = normalizeCostUsd(getTaskOutputMeta(output)?.costUsd);
      if (costUsd > 0) {
        state.totalCostUsd += costUsd;
        try {
          await this.bus.publish(
            createEvent("run:cost", state.checkpointRunId, {
              context: state.context,
              costUsd,
            }),
          );
        } catch {
          // Best-effort cost persistence.
        }
      }
    } catch (error) {
      errorMessage = toErrorMessage(error);
      log.warn(`[${taskId}] Failed open: ${errorMessage}`);
    }

    await this.bus.publish(
      createEvent("scan:post-task-complete", runId, {
        context: state.context,
        taskId,
        durationMs: Date.now() - startedAt,
        ...(costUsd > 0 ? { costUsd } : {}),
        ...(errorMessage ? { error: errorMessage } : {}),
      }),
    );

    return result;
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
      state.config.verifyGateEnabled !== true &&
      state.verifyCandidates.length > 0 &&
      state.verifyCandidates[state.verifyCandidates.length - 1].finding.fingerprint ===
        event.payload.finding.fingerprint
    ) {
      await this.pipelineVerifyCandidate(state, runId, event.payload.finding, event.payload.result);
    }

    // Auto-rule generation: fire-and-forget for TP findings with strategy evidence
    if (
      state.config.multiStrategyAutoRuleGeneration &&
      event.payload.result.verdict !== "fp" &&
      hasMultiStrategyEvidence(event.payload.finding) &&
      !state.generatingRuleFingerprints?.has(event.payload.finding.fingerprint)
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
      await this.bus.publish(
        createEvent("run:status", state.checkpointRunId, {
          context: state.context,
          status: "complete",
          extra: { completedAt: event.meta.timestamp },
        }),
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

    // Evaluate quality gates if configured
    let qualityGateResult: QualityGateResult | undefined;
    if (state.config.qualityGates) {
      const fingerprints = state.scanFindings.fingerprints();
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
      await this.bus.publish(
        createEvent("run:metrics", state.checkpointRunId, {
          context: state.context,
          metrics: finalMetrics,
        }),
      );
    } catch {
      // Metrics persistence is best-effort.
    }

    // Auto-generate operator scan context if none exists (first run)
    try {
      const {
        loadOperatorScanContext,
        saveOperatorScanContext,
        generateOperatorContextFromOutputs,
      } = await import("../operator-context.js");
      if (!loadOperatorScanContext(state.context.repoRoot)) {
        const opCtx = generateOperatorContextFromOutputs({
          repoContext: state.repoContext,
          enrichedContext: state.enrichedRepoContext
            ? {
                base: state.repoContext ?? {
                  languages: [],
                  frameworks: [],
                  authPatterns: [],
                  sanitizationLibs: [],
                  ormOrDb: [],
                  entryPoints: [],
                },
                enrichment: state.enrichedRepoContext,
              }
            : undefined,
          appModel: state.taskOutputs.get("app-model-build") as
            | import("../types.js").ApplicationModel
            | undefined,
          threatModel: state.taskOutputs.get("threat-model-randori") as
            | import("../agents/tasks/threat-modeling/types.js").ThreatModelDocument
            | undefined,
        });
        saveOperatorScanContext(state.context.repoRoot, opCtx);
      }
    } catch {
      // Non-fatal: auto-generation failure shouldn't break pipeline
    }

    const pipelineStats: PipelineStats = {
      tasks: [...state.tasks],
      totalFindings: state.totalFindings,
      queuedForTriage: state.triageTotal,
      skippedAlreadyTriaged: state.skippedAlreadyTriaged,
      skippedLowConfidence: state.verifyEnabled ? state.skippedLowConfidence : undefined,
      skippedByFpFilter: state.skippedByFpFilter > 0 ? state.skippedByFpFilter : undefined,
      skippedByScoreFilter: state.skippedByScoreFilter > 0 ? state.skippedByScoreFilter : undefined,
      autoClassifiedByDesign:
        state.autoClassifiedByDesign > 0 ? state.autoClassifiedByDesign : undefined,
      softSuppressedFindings:
        state.softSuppressedFindings > 0 ? state.softSuppressedFindings : undefined,
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
      variantAnalysisCostUsd:
        state.variantAnalysisCostUsd > 0 ? state.variantAnalysisCostUsd : undefined,
      chainCount: state.exploitChains.length > 0 ? state.exploitChains.length : undefined,
      chainAnalysisCostUsd: state.chainAnalysisCostUsd > 0 ? state.chainAnalysisCostUsd : undefined,
      budgetExceeded: state.budgetExceeded || undefined,
      failedTasks: state.failedTasks.length > 0 ? [...state.failedTasks] : undefined,
      deadLetterCount:
        state.deadLetterFindings.length > 0 ? state.deadLetterFindings.length : undefined,
      qualityGateResult,
      runMetrics: finalMetrics,
      startedAt: state.startedAt,
      completedAt: event.meta.timestamp,
    };
    const reportStats = buildReportStats(this.deps.db, state);
    if (reportStats.legacyIrisDegradation) {
      pipelineStats.legacyIrisDegradation = reportStats.legacyIrisDegradation;
    }
    if (reportStats.stitchDegradation) {
      pipelineStats.stitchDegradation = reportStats.stitchDegradation;
    }
    if (reportStats.extractionDegradation) {
      pipelineStats.extractionDegradation = reportStats.extractionDegradation;
    }

    // Invoke afterAll hook before emitting pipeline:complete
    if (state.hookChain) {
      try {
        await state.hookChain.afterAll(this.buildHookContext(state), {
          findings: state.scanFindings.toArray(),
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

  private async handleTaintAnalysisRefinementResult(
    event: TaintAnalysisRefinementResultEvent,
  ): Promise<void> {
    const runId = event.meta.runId;
    const state = this.runs.get(runId);
    if (!state) {
      return;
    }

    state.refinementInFlight = false;
    state.refinementIteration = Math.max(state.refinementIteration, event.payload.iteration);

    const nonTaintAnalysis = state.scanFindings
      .toArray()
      .filter((finding) => finding.taskId !== "taint-analysis-run");
    const merged = [...nonTaintAnalysis, ...event.payload.updatedFindings].sort(
      (a, b) => b.score - a.score,
    );
    state.scanFindings.replace(merged);
    state.totalFindings = state.scanFindings.count();
    state.triaged += event.payload.deltaTriaged;
    state.triageErrors += event.payload.deltaErrors;
    state.triageTotal += event.payload.deltaFindings.length;
    state.totalCostUsd += normalizeCostUsd(event.payload.triageCostUsd);

    try {
      await this.bus.publish(
        createEvent("run:findings-checkpoint", state.checkpointRunId, {
          context: state.context,
          findings: state.scanFindings.toArray(),
        }),
      );
      await this.bus.publish(
        createEvent("run:cost", state.checkpointRunId, {
          context: state.context,
          costUsd: event.payload.triageCostUsd,
        }),
      );
    } catch {
      // Checkpoint persistence is best-effort for refinement deltas.
    }

    if (
      state.refinementIteration < state.refinementIterations &&
      event.payload.deltaFindings.length > 0 &&
      this.shouldRunTaintAnalysisRefinement(state)
    ) {
      await this.startTaintAnalysisRefinement(state, runId);
      return;
    }

    await this.requestPostTriageFlow(state, runId);
  }

  private async handleTaintAnalysisRefinementError(
    event: TaintAnalysisRefinementErrorEvent,
  ): Promise<void> {
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
      "carlini-threat-hunt:agent-activity",
      // Triage assertions are informational quality scoring; a DB error
      // in their persistence path must never tear down the run.
      "triage:assertions",
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
        operatorContext: state.operatorContext,
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
      await this.bus.publish(
        createEvent("auto-rule:generated", runId, {
          context: state.context,
          rule,
          sourceFinding: {
            fingerprint: finding.fingerprint,
            filePath: finding.filePath,
            startLine: finding.startLine,
          },
        }),
      );

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
            const genWithSuffix = {
              ...generalized,
              vulnClass: `${generalized.vulnClass}-generalized`,
            };
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
    state.triageQueue = [];

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
        const model = resolveStageModel(state.config, "chain-analysis");
        await this.bus.publish(
          createEvent("chain-analysis:start", runId, {
            context: state.context,
            confirmedCount: confirmedTPs.length,
            model,
          }),
        );
        try {
          const taskContext: AgentDagRunContext = {
            runId,
            projectRoot: state.context.repoRoot,
            workRoot: state.context.scanPath ?? state.context.repoRoot,
            repoRoot: state.context.scanPath ?? state.context.repoRoot,
            scanPath: state.context.scanPath,
            repoName: state.context.repoName,
            config: state.config,
            runtime: wrapRuntimeWithActivityForwarding(
              this.deps.runtime,
              this.bus,
              "chain-analysis",
              runId,
              "scan",
            ),
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
            await this.bus.publish(
              createEvent("run:cost", state.checkpointRunId, {
                context: state.context,
                costUsd: chainMeta.costUsd,
              }),
            );
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
      log.info(
        `verification enabled — ${state.verifyCandidates.length} candidates, starting verification`,
      );
      await this.startVerification(state, runId);
      return;
    }

    log.info("verification disabled — requesting report directly");

    await this.bus.publish(
      createEvent("report:requested", runId, {
        context: state.context,
        stats: buildReportStats(this.deps.db, state),
        fingerprints: state.scanFindings.fingerprints(),
        exploitChains: state.exploitChains.length > 0 ? state.exploitChains : undefined,
        reportMode: state.context.reportMode,
      }),
    );

    state.reportEmitted = true;
  }

  private collectConfirmedTPs(
    state: RunState,
  ): Array<{ finding: Finding; triageResult: TriageResult }> {
    const fingerprints = state.scanFindings.fingerprints();
    const triageResults = getStoredTriageResults(this.deps.db, fingerprints);
    const confirmed: Array<{ finding: Finding; triageResult: TriageResult }> = [];
    for (const finding of state.scanFindings.iterate()) {
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
    const fingerprints = state.scanFindings.fingerprints();
    const triageResults = getStoredTriageResults(this.deps.db, fingerprints);
    const verificationResults = state.verifyEnabled
      ? getStoredVerificationResults(this.deps.db, fingerprints)
      : new Map<string, VerificationResult>();

    const seeds: Array<{ finding: Finding; triageResult: TriageResult }> = [];
    for (const finding of state.scanFindings.iterate()) {
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

    const model = resolveStageModel(state.config, "variant-analysis");
    await this.bus.publish(
      createEvent("variant-analysis:start", runId, {
        context: state.context,
        confirmedCount: confirmedTPs.length,
        model,
      }),
    );

    try {
      const result = await runVariantAnalysis(
        confirmedTPs,
        state.context,
        {
          ...state.config,
          variantAnalysisMaxFindings: Math.min(state.config.variantAnalysisMaxFindings ?? 5, 5),
        },
        this.deps.runtime,
      );
      const normalizedVariants = await this.normalizeFindingsForVariantAnalysis(
        state,
        result.findings,
      );
      state.variantFindings = normalizedVariants.length;
      state.variantAnalysisCostUsd = result.costUsd;
      state.totalCostUsd += result.costUsd;
      await this.bus.publish(
        createEvent("run:cost", state.checkpointRunId, {
          context: state.context,
          costUsd: result.costUsd,
        }),
      );
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

    log.info(
      `[rule-sweep] Scanning with ${state.generatedRules.length} custom rules from ${customDir}`,
    );

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
        {
          findings: sweepOutput.results.map((r) => ({
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
          })),
          costUsd: 0,
        },
        state.context.repoRoot,
        state.context.repoName,
        "HEAD",
        "rule-sweep",
        state.config.variantAnalysisMaxFindings ?? 10,
      );

      // Filter out findings already in the scan — check both fingerprint and
      // location (filePath:startLine) since different tasks use incompatible
      // fingerprint schemes and a sweep finding at the same location as an
      // existing finding is a duplicate.
      const existingFps = new Set(state.scanFindings.fingerprints());
      const existingLocations = new Set<string>();
      for (const f of state.scanFindings.iterate()) {
        existingLocations.add(`${f.filePath}:${f.startLine}`);
      }
      const newFindings = sweepFindings.filter(
        (f) =>
          !existingFps.has(f.fingerprint) && !existingLocations.has(`${f.filePath}:${f.startLine}`),
      );

      if (newFindings.length > 0) {
        state.ruleSweepFindings = newFindings.length;
        state.scanFindings.addAll(newFindings);
        log.info(`[rule-sweep] Found ${newFindings.length} new findings from custom rules`);

        // Persist sweep findings to DB so they appear in reports and survive resume.
        // Tagged with needs_review verdict since they haven't been triaged.
        if (this.deps.db) {
          const { upsertFinding } = await import("../store.js");
          for (const f of newFindings) {
            upsertFinding(
              this.deps.db,
              f,
              {
                fingerprint: f.fingerprint,
                verdict: "needs_review" as const,
                confidence: 0.5,
                rationale: "Discovered by rule sweep — pending triage",
                verificationSteps: [],
                fixPatch: null,
                triageCostUsd: 0,
              },
              state.context.repoName,
              "HEAD",
            );
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
      const untouched = normalized.filter(
        (finding) => !rescoredFingerprints.has(finding.fingerprint),
      );
      const rescoreResults = await rescoreFindings(rescoreWindow, {
        model: resolveStageModel(state.config, "llm-rescore"),
        threshold: state.config.llmRescoreThreshold,
        repoRoot: state.context.scanPath ?? state.context.repoRoot,
        runtime: this.deps.runtime,
        concurrency: state.config.triageConcurrency,
      });
      normalized = [
        ...applyRescoreResults(rescoreWindow, rescoreResults).findings,
        ...untouched,
      ].sort((a, b) => getRankingScore(b) - getRankingScore(a));
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
    const hasLabelContext =
      state.taskOutputs.has("taint-analysis-label") || state.taskOutputs.has("taint-cwe-select");
    if (!hasLabelContext) {
      return false;
    }
    for (const finding of state.scanFindings.iterate()) {
      if (finding.taskId === "taint-analysis-run" || finding.taskId === "taint-iris") {
        return true;
      }
    }
    return false;
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
        findings: state.scanFindings.toArray(),
        labelOutput:
          state.taskOutputs.get("taint-analysis-label") ??
          state.taskOutputs.get("taint-cwe-select"),
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
        await this.bus.publish(
          createEvent("run:status", state.checkpointRunId, {
            context: state.context,
            status: "verifying",
          }),
        );
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
      const { remaining: afterDedup, autoAccepted: dedupAccepted } = deduplicateByPattern(
        candidates,
        state,
      );

      for (const result of dedupAccepted) {
        state.verifyGateAutoAccepted += 1;
        const candidate = candidates.find((c) => c.finding.fingerprint === result.fingerprint)!;
        await this.emitSyntheticVerification(state, runId, candidate, result.reason);
      }

      if (dedupAccepted.length > 0) {
        log.info(
          `Pattern dedup: ${dedupAccepted.length} auto-accepted, ${afterDedup.length} remaining`,
        );
      }

      if (afterDedup.length === 0) return [];

      // Step 2: LLM gate
      const gateResults = await gateVerificationCandidates(afterDedup, {
        model: resolveStageModel(state.config, "verify-gate", "verify"),
        runtime: wrapRuntimeWithActivityForwarding(
          this.deps.runtime,
          this.bus,
          "verify:gate",
          runId,
        ),
        repoRoot: state.context.scanPath ?? state.context.repoRoot,
      });

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
          state,
          runId,
          candidate,
          gate?.reason ?? "Auto-accepted by verification gate",
        );
      }

      // Step 3: Cheap single-turn verification for borderline cases
      if (toCheapVerify.length > 0) {
        log.info(`Running cheap verification on ${toCheapVerify.length} candidate(s)`);
        const cheapResults = await cheapVerifyCandidates(toCheapVerify, {
          model: resolveStageModel(state.config, "verify", "triage"),
          runtime: wrapRuntimeWithActivityForwarding(
            this.deps.runtime,
            this.bus,
            "verify:cheap",
            runId,
          ),
          repoRoot: state.context.scanPath ?? state.context.repoRoot,
        });

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
        `Verification gate: ${toVerify.length} full-verify, ${toCheapVerify.length} cheap-verify, ` +
          `${accepted.length} auto-accepted, ${skipped} skipped` +
          (dedupAccepted.length > 0 ? ` (+ ${dedupAccepted.length} pattern-deduped)` : ""),
      );

      return toVerify;
    } catch (error) {
      log.warn(
        `Verification gate failed, proceeding with all candidates: ${toErrorMessage(error)}`,
      );
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
        await this.bus.publish(
          createEvent("run:status", state.checkpointRunId, {
            context: state.context,
            status: "verifying",
          }),
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
    }

    if (!state.stageTimestamps.verifyStart) {
      state.stageTimestamps.verifyStart = new Date().toISOString();
    }

    await this.bus.publish(
      createEvent("verification:start", runId, {
        context: state.context,
        findingCount: state.verifyTotal,
        model: resolveStageModel(state.config, "verify", "triage"),
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
    const ruleGenConfidence =
      event.payload.result.compositeConfidence ?? event.payload.result.confidence;
    const findingCwes = event.payload.finding.cwe ?? [];
    const isAuthLogicCwe = findingCwes.some((c) => SKIP_RULE_GEN_CWES.has(c.replace(/^CWE-/, "")));
    if (
      state.config.autoRuleGeneration &&
      event.payload.result.exploitable &&
      typeof ruleGenConfidence === "number" &&
      ruleGenConfidence >= 0.7 &&
      !isAuthLogicCwe &&
      !state.generatingRuleFingerprints?.has(event.payload.finding.fingerprint)
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
    state.verifyQueue = [];
    state.verifyCandidates = [];

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
        fingerprints: state.scanFindings.fingerprints(),
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
    state.pocHarnessCandidates = [];
    state.pocHarnessCursor = 0;

    try {
      await this.bus.publish(
        createEvent("run:status", state.checkpointRunId, {
          context: state.context,
          status: "poc-harnessing",
        }),
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

    state.stageTimestamps.pocStart = new Date().toISOString();

    await this.bus.publish(
      createEvent("poc-harness:start", runId, {
        context: state.context,
        findingCount: state.pocHarnessTotal,
        model: resolveStageModel(state.config, "poc-harness", "verify"),
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
      state.config.pocExecute &&
      !event.payload.result.skipped &&
      event.payload.result.parsed &&
      event.payload.result.scriptPath &&
      event.payload.result.language
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
        fingerprints: state.scanFindings.fingerprints(),
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
    const fingerprints = state.scanFindings.fingerprints();
    const triageResults = getStoredTriageResults(this.deps.db, fingerprints);
    const verificationResults = getStoredVerificationResults(this.deps.db, fingerprints);

    const candidates: DynamicAnalysisCandidate[] = [];

    for (const finding of state.scanFindings.iterate()) {
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
        verificationResult &&
        (!verificationResult.exploitable || (verificationResult.confidence ?? 0) < 0.6) &&
        finding.taintPath &&
        finding.taintPath.length > 0
      ) {
        candidates.push({ finding, triageResult, verificationResult, score, proofValue });
        continue;
      }

      // Priority 2: Strong taint-analysis findings
      if (
        (finding.taskId === "taint-iris" || finding.taskId === "taint-analysis-run") &&
        score >= minScore &&
        finding.taintPath &&
        finding.taintPath.length > 0
      ) {
        candidates.push({ finding, triageResult, verificationResult, score, proofValue });
        continue;
      }

      // Priority 3: Corroborated CodeQL or agentic findings
      if (
        (finding.taskId === "codeql" || finding.taskId === "agentic") &&
        finding.corroboratingSignals &&
        finding.corroboratingSignals.length >= 1
      ) {
        candidates.push({ finding, triageResult, verificationResult, score, proofValue });
        continue;
      }

      // Priority 4: Semgrep only if corroborated or critical
      if (
        finding.taskId === "semgrep" &&
        ((finding.corroboratingSignals && finding.corroboratingSignals.length >= 1) ||
          finding.severity === "ERROR")
      ) {
        candidates.push({ finding, triageResult, verificationResult, score, proofValue });
      }
    }

    // Sort by (score + proofValue) descending, cap at maxCandidates
    candidates.sort((a, b) => b.score + b.proofValue - (a.score + a.proofValue));
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
    state.dynamicCandidates = [];
    state.dynamicCursor = 0;

    try {
      await this.bus.publish(
        createEvent("run:status", state.checkpointRunId, {
          context: state.context,
          status: "dynamic-analyzing",
        }),
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

    state.stageTimestamps.dynamicStart = new Date().toISOString();

    await this.bus.publish(
      createEvent("dynamic:start", runId, {
        context: state.context,
        findingCount: state.dynamicTotal,
        model: resolveStageModel(state.config, "dynamic-analysis", "poc-harness", "verify"),
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
    await this.bus.publish(
      createEvent("run:cost", state.checkpointRunId, { context: state.context, costUsd }),
    );

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
    await this.bus.publish(
      createEvent("run:cost", state.checkpointRunId, { context: state.context, costUsd }),
    );

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
        state.dynamicInFlight < concurrency &&
        state.dynamicCursor < state.dynamicQueue.length
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
    const processed =
      state.dynamicConfirmed +
      state.dynamicInteresting +
      state.dynamicRejected +
      state.dynamicErrors;
    return (
      state.dynamicTotal > 0 &&
      processed >= state.dynamicTotal &&
      state.dynamicInFlight === 0 &&
      !state.reportEmitted
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
        fingerprints: state.scanFindings.fingerprints(),
        exploitChains: state.exploitChains.length > 0 ? state.exploitChains : undefined,
        reportMode: state.context.reportMode,
      }),
    );

    state.reportRequested = true;
    state.reportEmitted = true;
  }

  private async publishDynamicAnalysisQueueDepth(state: RunState, runId: string): Promise<void> {
    const queued = Math.max(0, state.dynamicQueue.length - state.dynamicCursor);
    const processed =
      state.dynamicConfirmed +
      state.dynamicInteresting +
      state.dynamicRejected +
      state.dynamicErrors;

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
 * for findings from different tasks at the same code location.
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
    const key = isThreatModelScanner(f.taskId)
      ? `tm:${f.taskId}:${f.filePath}:${f.startLine}`
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
      taskId: f.taskId,
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
    if (isThreatModelScanner(f.taskId)) {
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
      taskId: detector.taskId,
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
      detector.corroboratingSignals = [
        ...(detector.corroboratingSignals ?? []),
        {
          taskId: tm.taskId,
          fingerprint: tm.fingerprint,
          ruleId: tm.ruleId,
          filePath: tm.filePath,
          startLine: tm.startLine,
          cwe: tm.cwe,
          score: tm.score ?? 0,
        },
      ];
    }
  }

  if (deduped.length < findings.length) {
    log.info(
      `[location-dedup] Merged ${findings.length} findings into ${deduped.length} (${findings.length - deduped.length} duplicates absorbed as corroborating signals)`,
    );
  }

  return deduped;
}

function isThreatModelScanner(taskId: string): boolean {
  return taskId.startsWith("threat-model-");
}

export function registerOrchestrator(
  bus: MessageBus,
  deps: OrchestratorDeps,
): PipelineOrchestrator {
  return new PipelineOrchestrator(bus, deps);
}

function buildReportStats(db: Database.Database, state: RunState): Partial<PipelineStats> {
  let extractionDegradation: PipelineStats["extractionDegradation"];
  let tiPriorDegraded: boolean | undefined;
  const preflightOutput = state.taskOutputs.get("taint-analysis-preflight");
  if (isRecord(preflightOutput)) {
    if (
      isRecord(preflightOutput["extractionDegradation"]) &&
      typeof preflightOutput["extractionDegradation"]["status"] === "string" &&
      preflightOutput["extractionDegradation"]["status"] !== "ok"
    ) {
      const deg = preflightOutput["extractionDegradation"];
      extractionDegradation = {
        status: deg["status"] as string,
        reasons: Array.isArray(deg["reasons"])
          ? (deg["reasons"] as unknown[]).filter((r): r is string => typeof r === "string")
          : [],
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

  let legacyIrisDegradation: PipelineStats["legacyIrisDegradation"];
  const legacyIrisOutput =
    state.taskOutputs.get("taint-iris:hunt") ?? state.taskOutputs.get("taint-iris");
  const legacyIrisMeta = getTaskOutputMeta(legacyIrisOutput);
  if (legacyIrisMeta?.degradation) {
    legacyIrisDegradation = {
      type: legacyIrisMeta.degradation.type,
      reason: legacyIrisMeta.degradation.reason,
      message: legacyIrisMeta.degradation.message,
    };
  } else if (
    (state.tasks.includes("taint-iris:hunt") || state.tasks.includes("taint-iris")) &&
    state.totalFindings === 0
  ) {
    legacyIrisDegradation = {
      type: "legacy-inconclusive",
      reason: "no-observable-legacy-iris-output",
      message:
        "Legacy taint-iris returned 0 findings without observable CodeQL query artifacts or degradation metadata; treat as inconclusive, not clean.",
    };
  }

  const completedAt = new Date().toISOString();
  state.stageTimestamps.pipelineEnd = completedAt;

  const runMetrics = buildRunMetrics(db, state);

  return {
    tasks: [...state.tasks],
    totalFindings: state.totalFindings,
    queuedForTriage: state.triageTotal,
    skippedAlreadyTriaged: state.skippedAlreadyTriaged,
    skippedLowConfidence: state.verifyEnabled ? state.skippedLowConfidence : undefined,
    skippedByFpFilter: state.skippedByFpFilter > 0 ? state.skippedByFpFilter : undefined,
    skippedByScoreFilter: state.skippedByScoreFilter > 0 ? state.skippedByScoreFilter : undefined,
    softSuppressedFindings:
      state.softSuppressedFindings > 0 ? state.softSuppressedFindings : undefined,
    skippedByLlmRescore: state.skippedByLlmRescore > 0 ? state.skippedByLlmRescore : undefined,
    corroboratedClusters: state.corroboratedClusters > 0 ? state.corroboratedClusters : undefined,
    triaged: state.triaged,
    triageErrors: state.triageErrors,
    totalCostUsd: state.totalCostUsd,
    verified: state.verifyEnabled ? state.verified : undefined,
    verifyErrors: state.verifyEnabled ? state.verifyErrors : undefined,
    verifyCostUsd: state.verifyEnabled ? state.verifyCostUsd : undefined,
    verifyGateAutoAccepted:
      state.verifyGateAutoAccepted > 0 ? state.verifyGateAutoAccepted : undefined,
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
    variantAnalysisCostUsd:
      state.variantAnalysisCostUsd > 0 ? state.variantAnalysisCostUsd : undefined,
    ruleSweepFindings: state.ruleSweepFindings > 0 ? state.ruleSweepFindings : undefined,
    chainCount: state.exploitChains.length > 0 ? state.exploitChains.length : undefined,
    chainAnalysisCostUsd: state.chainAnalysisCostUsd > 0 ? state.chainAnalysisCostUsd : undefined,
    budgetExceeded: state.budgetExceeded || undefined,
    failedTasks: state.failedTasks.length > 0 ? [...state.failedTasks] : undefined,
    extractionDegradation,
    stitchDegradation,
    legacyIrisDegradation,
    tiPriorDegraded,
    runMetrics,
    startedAt: state.startedAt,
    completedAt,
  };
}

function buildRunMetrics(db: Database.Database, state: RunState) {
  const triageCost =
    state.totalCostUsd -
    state.verifyCostUsd -
    state.pocHarnessCostUsd -
    state.dynamicCostUsd -
    state.variantAnalysisCostUsd -
    state.chainAnalysisCostUsd;
  const costs: StageCosts = {
    triage: Math.max(0, triageCost),
    verify: state.verifyCostUsd,
    pocHarness: state.pocHarnessCostUsd,
    dynamicAnalysis: state.dynamicCostUsd,
    variantAnalysis: state.variantAnalysisCostUsd,
  };

  let findings: Finding[] = state.scanFindings.toArray();
  try {
    const fingerprints = state.scanFindings.fingerprints();
    findings = getActionableFindings(db, state.context.repoName, {
      includeFalsePositives: true,
      fingerprints: fingerprints.length > 0 ? fingerprints : undefined,
    }) as unknown as Finding[];
  } catch (error) {
    log.warn(`Falling back to in-memory findings for run metrics: ${toErrorMessage(error)}`);
  }

  return computeRunMetrics(findings, state.stageTimestamps, costs, {
    corroboratedClusters: state.corroboratedClusters,
    verified: state.verifyEnabled ? state.verified : 0,
    verifyErrors: state.verifyEnabled ? state.verifyErrors : 0,
    pocHarnessGenerated: state.pocHarnessEnabled ? state.pocHarnessGenerated : 0,
    pocHarnessSkipped: state.pocHarnessEnabled ? state.pocHarnessSkipped : 0,
    pocHarnessErrors: state.pocHarnessEnabled ? state.pocHarnessErrors : 0,
  });
}

function resolveTaintAnalysisConfig(config: KuzushiConfig): Record<string, unknown> {
  const raw = config.taskConfig["taint-analysis"];
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
  if (
    typeof taintAnalysis["refinementModel"] === "string" &&
    taintAnalysis["refinementModel"].trim()
  ) {
    return taintAnalysis["refinementModel"].trim();
  }
  return resolveStageModel(config, "triage");
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

  const scannersValue = parsed["tasks"];
  let tasks: string[] | undefined;
  if (scannersValue != null) {
    const parsedScanners = asStringArray(scannersValue);
    if (!parsedScanners) {
      throw new Error("scan opts payload has invalid tasks");
    }
    tasks = parsedScanners;
  }

  const disabledValue = parsed["disabledTasks"];
  let disabledTasks: string[] | undefined;
  if (disabledValue != null) {
    const parsedDisabled = asStringArray(disabledValue);
    if (!parsedDisabled) {
      throw new Error("scan opts payload has invalid disabledTasks");
    }
    disabledTasks = parsedDisabled;
  }

  const taskModeValue = parsed["taskMode"];
  let taskMode: ScanOpts["taskMode"];
  if (taskModeValue !== undefined) {
    if (taskModeValue !== "auto" && taskModeValue !== "manual") {
      throw new Error("scan opts payload has invalid taskMode");
    }
    taskMode = taskModeValue;
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
    tasks,
    taskMode,
    disabledTasks,
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

  if (!isScannerVerificationEnabled(state.config, finding.taskId)) {
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
  const scannerCfg = config.taskConfig[configKey];
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

function _asLabelCountMap(value: unknown): Record<string, number> {
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

function _asString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  return value;
}

function _asNullableString(value: unknown): string | null | undefined {
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
