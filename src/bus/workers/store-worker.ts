import type Database from "better-sqlite3";
import { updateVerificationCost, updateVerificationResult, upsertFinding } from "../../store.js";
import type {
  TriageResultEvent,
  VerificationErrorEvent,
  VerificationResultEvent,
} from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";

export interface StoreWorkerDeps {
  db: Database.Database;
  ref?: string;
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
    if (result.verifyCostUsd === undefined && typeof costUsd === "number") {
      result.verifyCostUsd = costUsd;
    }

    updateVerificationResult(deps.db, finding.fingerprint, result);

    await bus.publish(
      createEvent("store:upserted", event.meta.runId, {
        context,
        fingerprint: finding.fingerprint,
        verdict: event.payload.triageResult.verdict,
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
}
