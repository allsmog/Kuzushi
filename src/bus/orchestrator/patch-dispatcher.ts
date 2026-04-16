import type Database from "better-sqlite3";
import { createLogger } from "../../logger.js";
import { getPatchResultsForFinding } from "../../store/patch-results.js";
import type {
  PatchCompleteEvent,
  PocHarnessResultEvent,
  RunContext,
  TriageResultEvent,
  VerificationResultEvent,
} from "../events.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import type { RunState } from "./types.js";

const log = createLogger({ stage: "patch-dispatcher" });

/**
 * Set up event-driven patch dispatching.
 * Subscribes to the appropriate trigger event (verification, poc, or triage)
 * and queues eligible findings for patch synthesis.
 */
export function setupPatchDispatching(
  bus: MessageBus,
  state: RunState,
  db: Database.Database,
): void {
  const trigger = state.config.autoPatchAfter ?? "verify";
  const _concurrency = state.config.patchConcurrency ?? 2;

  // Subscribe to the appropriate trigger
  if (trigger === "verify") {
    bus.subscribe<VerificationResultEvent>("verification:result", async (event) => {
      const fp = event.payload.finding.fingerprint;
      const result = event.payload.result;
      if (result.exploitable) {
        enqueuePatch(bus, state, db, fp, "verify", event.payload.context);
      }
    });
  } else if (trigger === "poc") {
    bus.subscribe<PocHarnessResultEvent>("poc-harness:result", async (event) => {
      const fp = event.payload.finding.fingerprint;
      const result = event.payload.result;
      if (result.pocExecVerdict === "PASS") {
        enqueuePatch(bus, state, db, fp, "poc", event.payload.context);
      }
    });
  } else if (trigger === "triage") {
    bus.subscribe<TriageResultEvent>("triage:result", async (event) => {
      const fp = event.payload.finding.fingerprint;
      const result = event.payload.result;
      if (result.verdict === "tp") {
        enqueuePatch(bus, state, db, fp, "triage", event.payload.context);
      }
    });
  }

  // After patch completes, dispatch re-verification if SOUND
  bus.subscribe<PatchCompleteEvent>("patch:complete", async (event) => {
    const { fingerprint, status, worktreePath, costUsd } = event.payload;
    state.patchInFlight = Math.max(0, state.patchInFlight - 1);
    state.patchCompleted++;
    state.patchCostUsd += costUsd;

    if (status === "SOUND" && worktreePath) {
      const depth = state.config.patchVerifyDepth ?? "task";
      await bus.publish(
        createEvent("patch-verify:requested", event.meta.runId, {
          context: event.payload.context,
          fingerprint,
          worktreePath,
          depth,
        }),
      );
    } else {
      state.patchFailed++;
      drainQueue(bus, state);
    }
  });

  // Track verify results
  bus.subscribe("patch-verify:complete", async (event: any) => {
    const { verified } = event.payload;
    if (verified) {
      state.patchVerified++;
    } else {
      state.patchFailed++;
    }
    drainQueue(bus, state);
  });

  bus.subscribe("patch:error", async () => {
    state.patchInFlight = Math.max(0, state.patchInFlight - 1);
    state.patchErrors++;
    drainQueue(bus, state);
  });

  bus.subscribe("patch-verify:error", async () => {
    state.patchFailed++;
    drainQueue(bus, state);
  });
}

function enqueuePatch(
  bus: MessageBus,
  state: RunState,
  db: Database.Database,
  fingerprint: string,
  trigger: "verify" | "poc" | "triage",
  context: RunContext,
): void {
  // Eligibility check
  if (state.patchCandidates.has(fingerprint)) return;

  // Check if already has a SOUND patch
  const existing = getPatchResultsForFinding(db, fingerprint);
  if (existing.some((p) => p.status === "SOUND" || p.status === "VERIFIED")) return;

  // Budget check
  if (state.budgetExceeded) return;

  state.patchCandidates.add(fingerprint);
  state.patchQueue.push(fingerprint);

  log.debug(`Queued patch for ${fingerprint.slice(0, 12)} (trigger=${trigger})`);

  // Emit queue depth
  bus.publish(
    createEvent("patch:queue-depth", state.context.runId, {
      context: state.context,
      depth: state.patchQueue.length - state.patchCompleted,
    }),
  );

  drainQueue(bus, state, trigger, context);
}

function drainQueue(
  bus: MessageBus,
  state: RunState,
  trigger?: "verify" | "poc" | "triage",
  context?: RunContext,
): void {
  const concurrency = state.config.patchConcurrency ?? 2;
  const ctx = context ?? state.context;
  const t = trigger ?? ((state.config.autoPatchAfter ?? "verify") as "verify" | "poc" | "triage");

  while (state.patchInFlight < concurrency && state.patchCursor < state.patchQueue.length) {
    const fingerprint = state.patchQueue[state.patchCursor];
    if (!fingerprint) break;

    state.patchCursor++;
    state.patchInFlight++;
    state.patchDispatching = true;

    bus.publish(
      createEvent("patch:requested", state.context.runId, {
        context: ctx,
        fingerprint,
        trigger: t,
      }),
    );
  }
}
