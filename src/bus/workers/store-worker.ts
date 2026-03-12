import type Database from "better-sqlite3";
import {
  updatePocHarnessCost,
  updatePocHarnessResult,
  updateVerificationCost,
  updateVerificationResult,
  upsertFinding,
} from "../../store.js";
import type {
  PocHarnessErrorEvent,
  PocHarnessResultEvent,
  TriageResultEvent,
  VerificationErrorEvent,
  VerificationResultEvent,
} from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import { updateTrajectoryCorrectness } from "../../trajectory-memory.js";
import {
  extractRuleFamily,
  updateCalibrationWeights,
} from "../../confidence-calibration.js";
import type { KuzushiConfig } from "../../types.js";

export interface StoreWorkerDeps {
  db: Database.Database;
  ref?: string;
  config?: KuzushiConfig;
}

/**
 * Store worker: persists triage results into SQLite.
 */
export function registerStoreWorker(bus: MessageBus, deps: StoreWorkerDeps): void {
  bus.subscribe<TriageResultEvent>("triage:result", async (event) => {
    const { context, finding, result, costUsd } = event.payload;
    if (result.triageCostUsd === undefined && typeof costUsd === "number") {
      result.triageCostUsd = costUsd;
    }

    upsertFinding(
      deps.db,
      finding,
      result,
      context.repoName,
      deps.ref ?? "HEAD",
    );

    await bus.publish(
      createEvent("store:upserted", event.meta.runId, {
        context,
        fingerprint: result.fingerprint,
        verdict: result.verdict,
      }),
    );
  });

  bus.subscribe<VerificationResultEvent>("verification:result", async (event) => {
    const { context, finding, result, costUsd } = event.payload;
    const triageResult = event.payload.triageResult;
    if (result.verifyCostUsd === undefined && typeof costUsd === "number") {
      result.verifyCostUsd = costUsd;
    }

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
        updateCalibrationWeights(
          deps.db,
          triageResult.evidenceChain,
          ruleFamily,
          wasCorrect,
        );
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

    // Ensure the row exists even if persistence ordering is delayed.
    upsertFinding(
      deps.db,
      finding,
      triageResult,
      context.repoName,
      deps.ref ?? "HEAD",
    );
    updateVerificationCost(deps.db, finding.fingerprint, costUsd);
  });

  bus.subscribe<PocHarnessResultEvent>("poc-harness:result", async (event) => {
    const { context, finding, triageResult, result, costUsd } = event.payload;
    if (result.costUsd === undefined && typeof costUsd === "number") {
      result.costUsd = costUsd;
    }

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

    // Ensure the row exists even if persistence ordering is delayed.
    upsertFinding(
      deps.db,
      finding,
      triageResult,
      context.repoName,
      deps.ref ?? "HEAD",
    );
    updatePocHarnessCost(deps.db, finding.fingerprint, costUsd);
  });
}
