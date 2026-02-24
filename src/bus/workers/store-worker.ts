import type Database from "better-sqlite3";
import { upsertFinding } from "../../store.js";
import type { TriageResultEvent } from "../events.js";
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
    const { context, finding, result } = event.payload;

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
}
