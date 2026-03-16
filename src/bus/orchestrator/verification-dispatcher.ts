/**
 * Verification dispatch logic extracted from PipelineOrchestrator.
 *
 * Manages the verification queue: dispatching candidates for verification,
 * handling results/errors, and tracking PoC harness candidates.
 */

import { normalizeCostUsd } from "../../utils.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import type { RunState, OrchestratorDeps, PocHarnessCandidate } from "./types.js";
import type { VerificationResultEvent, VerificationErrorEvent } from "../events.js";

export function handleVerificationResultState(
  state: RunState,
  event: VerificationResultEvent,
  deps: OrchestratorDeps,
): void {
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
    const { updateRunCost } = require("../../store.js");
    updateRunCost(deps.db, state.checkpointRunId, costUsd);
  } catch {
    // Cost persistence is best-effort.
  }
}

export function handleVerificationErrorState(
  state: RunState,
  event: VerificationErrorEvent,
  deps: OrchestratorDeps,
): void {
  state.verifyInFlight = Math.max(0, state.verifyInFlight - 1);
  state.verifyErrors += 1;
  const costUsd = normalizeCostUsd(event.payload.costUsd);
  state.totalCostUsd += costUsd;
  state.verifyCostUsd += costUsd;

  try {
    const { updateRunCost } = require("../../store.js");
    updateRunCost(deps.db, state.checkpointRunId, costUsd);
  } catch {
    // Cost persistence is best-effort.
  }
}

export function isVerificationDone(state: RunState): boolean {
  const processed = state.verified + state.verifyErrors;
  return (
    state.verifyTotal > 0
    && processed >= state.verifyTotal
    && state.verifyInFlight === 0
    && !state.reportEmitted
  );
}

export async function dispatchVerification(
  state: RunState,
  runId: string,
  bus: MessageBus,
  isBudgetExceeded: (state: RunState) => boolean,
  emitBudgetCheck: (state: RunState, runId: string) => Promise<void>,
  emitBudgetExceeded: (state: RunState, runId: string) => Promise<void>,
  publishVerificationQueueDepth: (state: RunState, runId: string) => Promise<void>,
): Promise<void> {
  if (state.verifyDispatching) return;

  state.verifyDispatching = true;
  try {
    const concurrency = normalizeConcurrency(state.config.verifyConcurrency ?? 1);
    const batchSize = Math.max(1, Math.floor(state.config.verifyBatchSize ?? 5));

    while (state.verifyInFlight < concurrency && state.verifyCursor < state.verifyQueue.length) {
      await emitBudgetCheck(state, runId);
      if (isBudgetExceeded(state)) {
        await emitBudgetExceeded(state, runId);
        break;
      }

      const batchItems: Array<{
        finding: typeof state.verifyQueue[0]["finding"];
        triageResult: typeof state.verifyQueue[0]["triageResult"];
        index: number;
        total: number;
      }> = [];
      while (batchItems.length < batchSize && state.verifyCursor < state.verifyQueue.length) {
        const item = state.verifyQueue[state.verifyCursor];
        state.verifyCursor += 1;
        batchItems.push({
          finding: item.finding,
          triageResult: item.triageResult,
          index: item.index,
          total: item.total,
        });
      }

      if (batchItems.length === 0) break;

      state.verifyInFlight += batchItems.length;

      if (batchItems.length === 1) {
        const item = batchItems[0];
        await bus.publish(
          createEvent("verification:finding-queued", runId, {
            context: state.context,
            finding: item.finding,
            triageResult: item.triageResult,
            repoContext: state.repoContext,
            enrichedContext: state.enrichedRepoContext,
            precedents: state.precedents,
            index: item.index,
            total: item.total,
          }),
        );
      } else {
        await bus.publish(
          createEvent("verification:batch-queued", runId, {
            context: state.context,
            items: batchItems,
            repoContext: state.repoContext,
            enrichedContext: state.enrichedRepoContext,
          }),
        );
      }
    }

    await publishVerificationQueueDepth(state, runId);
  } finally {
    state.verifyDispatching = false;
  }
}

export async function publishVerifyQueueDepth(
  state: RunState,
  runId: string,
  bus: MessageBus,
): Promise<void> {
  const queued = Math.max(0, state.verifyQueue.length - state.verifyCursor);
  const processed = state.verified + state.verifyErrors;

  await bus.publish(
    createEvent("verification:queue-depth", runId, {
      context: state.context,
      queued,
      inFlight: state.verifyInFlight,
      processed,
      total: state.verifyTotal,
    }),
  );
}

function normalizeConcurrency(raw: number): number {
  if (!Number.isFinite(raw) || raw < 1) return 1;
  return Math.floor(raw);
}
