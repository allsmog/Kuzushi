import type Database from "better-sqlite3";
import { extractRuleFamily, updateCalibrationWeights } from "../../confidence-calibration.js";
import {
  FindingUpsertQueue,
  type PipelineRunStatus,
  saveAssertionResults,
  updatePocHarnessCost,
  updatePocHarnessResult,
  updateRunContext,
  updateRunCost,
  updateRunFindings,
  updateRunMetrics,
  updateRunStatus,
  updateVerificationCost,
  updateVerificationResult,
  upsertFinding,
} from "../../store.js";
import { updateTrajectoryCorrectness } from "../../trajectory-memory.js";
import type { KuzushiConfig } from "../../types.js";
import type {
  PocHarnessErrorEvent,
  PocHarnessResultEvent,
  RunContextCheckpointEvent,
  RunCostEvent,
  RunFindingsCheckpointEvent,
  RunMetricsEvent,
  RunStatusEvent,
  TriageAssertionsEvent,
  TriageCompleteEvent,
  TriageResultEvent,
  VerificationErrorEvent,
  VerificationResultEvent,
} from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface StoreWorkerDeps {
  db: Database.Database;
  ref?: string;
  config?: KuzushiConfig;
}

export interface StoreWorkerHandle {
  /** Flush any pending batched upserts to the database. */
  flush(): void;
}

/**
 * Store worker: persists triage results into SQLite.
 * Triage upserts are batched (flushed every 50 findings or at phase boundaries)
 * to reduce per-finding transaction overhead.
 */
export function registerStoreWorker(bus: MessageBus, deps: StoreWorkerDeps): StoreWorkerHandle {
  const upsertQueue = new FindingUpsertQueue(deps.db);

  bus.subscribe<TriageResultEvent>("triage:result", async (event) => {
    const { context, finding, result, costUsd } = event.payload;
    if (result.triageCostUsd === undefined && typeof costUsd === "number") {
      result.triageCostUsd = costUsd;
    }

    upsertQueue.enqueue(finding, result, context.repoName, deps.ref ?? "HEAD");

    await bus.publish(
      createEvent("store:upserted", event.meta.runId, {
        context,
        fingerprint: result.fingerprint,
        verdict: result.verdict,
      }),
    );
  });

  // Flush all pending upserts before the verification phase begins.
  bus.subscribe<TriageCompleteEvent>("triage:complete", () => {
    upsertQueue.flush();
  });

  bus.subscribe<TriageAssertionsEvent>("triage:assertions", (event) => {
    const { fingerprint, assertions } = event.payload;
    const runId = event.meta.runId;
    saveAssertionResults(deps.db, runId, fingerprint, assertions);
  });

  bus.subscribe<VerificationResultEvent>("verification:result", async (event) => {
    const { context, finding, result, costUsd } = event.payload;
    const triageResult = event.payload.triageResult;
    if (result.verifyCostUsd === undefined && typeof costUsd === "number") {
      result.verifyCostUsd = costUsd;
    }

    // Ensure the triage row is flushed before the UPDATE.
    upsertQueue.flush();
    updateVerificationResult(deps.db, finding.fingerprint, result);

    // Update trajectory correctness for trajectory memory
    if (deps.config?.trajectoryMemory) {
      try {
        const wasCorrect = (triageResult.verdict === "tp") === result.exploitable;
        updateTrajectoryCorrectness(deps.db, finding.fingerprint, wasCorrect);
      } catch {
        // Non-fatal
      }
    }

    // Update calibration weights for confidence calibration
    if (deps.config?.confidenceCalibration && triageResult.evidenceChain?.length) {
      try {
        const wasCorrect = (triageResult.verdict === "tp") === result.exploitable;
        const ruleFamily = extractRuleFamily(finding.ruleId);
        updateCalibrationWeights(deps.db, triageResult.evidenceChain, ruleFamily, wasCorrect);
      } catch {
        // Non-fatal
      }
    }

    await bus.publish(
      createEvent("store:upserted", event.meta.runId, {
        context,
        fingerprint: finding.fingerprint,
        verdict: triageResult.verdict,
      }),
    );
  });

  bus.subscribe<VerificationErrorEvent>("verification:error", (event) => {
    const { context, finding, triageResult, costUsd } = event.payload;
    if (typeof costUsd !== "number" || !Number.isFinite(costUsd) || costUsd < 0) {
      return;
    }

    // Flush any pending batched upserts so the row exists before the UPDATE.
    upsertQueue.flush();
    // Ensure the row exists even if persistence ordering is delayed.
    upsertFinding(deps.db, finding, triageResult, context.repoName, deps.ref ?? "HEAD");
    updateVerificationCost(deps.db, finding.fingerprint, costUsd);
  });

  bus.subscribe<PocHarnessResultEvent>("poc-harness:result", async (event) => {
    const { context, finding, triageResult, result, costUsd } = event.payload;
    if (result.costUsd === undefined && typeof costUsd === "number") {
      result.costUsd = costUsd;
    }

    // Ensure the triage row is flushed before the UPDATE.
    upsertQueue.flush();
    updatePocHarnessResult(deps.db, finding.fingerprint, result);

    await bus.publish(
      createEvent("store:upserted", event.meta.runId, {
        context,
        fingerprint: finding.fingerprint,
        verdict: triageResult.verdict,
      }),
    );
  });

  bus.subscribe<PocHarnessErrorEvent>("poc-harness:error", (event) => {
    const { context, finding, triageResult, costUsd } = event.payload;
    if (typeof costUsd !== "number" || !Number.isFinite(costUsd) || costUsd < 0) {
      return;
    }

    // Flush any pending batched upserts so the row exists before the UPDATE.
    upsertQueue.flush();
    // Ensure the row exists even if persistence ordering is delayed.
    upsertFinding(deps.db, finding, triageResult, context.repoName, deps.ref ?? "HEAD");
    updatePocHarnessCost(deps.db, finding.fingerprint, costUsd);
  });

  // ── Run lifecycle persistence (best-effort — DB failures must not kill the pipeline) ──

  bus.subscribe<RunStatusEvent>("run:status", (event) => {
    try {
      updateRunStatus(
        deps.db,
        event.meta.runId,
        event.payload.status as PipelineRunStatus,
        event.payload.extra,
      );
    } catch {
      /* best-effort */
    }
  });

  bus.subscribe<RunCostEvent>("run:cost", (event) => {
    try {
      updateRunCost(deps.db, event.meta.runId, event.payload.costUsd);
    } catch {
      /* best-effort */
    }
  });

  bus.subscribe<RunFindingsCheckpointEvent>("run:findings-checkpoint", (event) => {
    try {
      updateRunFindings(deps.db, event.meta.runId, event.payload.findings);
    } catch {
      /* best-effort */
    }
  });

  bus.subscribe<RunContextCheckpointEvent>("run:context-checkpoint", (event) => {
    try {
      updateRunContext(deps.db, event.meta.runId, event.payload.repoContext);
    } catch {
      /* best-effort */
    }
  });

  bus.subscribe<RunMetricsEvent>("run:metrics", (event) => {
    try {
      updateRunMetrics(deps.db, event.meta.runId, event.payload.metrics);
    } catch {
      /* best-effort */
    }
  });

  return { flush: () => upsertQueue.flush() };
}
