/**
 * PoC harness dispatch logic extracted from PipelineOrchestrator.
 */

import { normalizeCostUsd } from "../../utils.js";
import { updateRunCost } from "../../store.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import type { PocHarnessResultEvent, PocHarnessErrorEvent } from "../events.js";
import type { RunState, OrchestratorDeps } from "./types.js";

export function handlePocHarnessResultState(
  state: RunState,
  event: PocHarnessResultEvent,
  deps: OrchestratorDeps,
): void {
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
    updateRunCost(deps.db, state.checkpointRunId, costUsd);
  } catch {
    // Cost persistence is best-effort.
  }
}

export function handlePocHarnessErrorState(
  state: RunState,
  event: PocHarnessErrorEvent,
  deps: OrchestratorDeps,
): void {
  state.pocHarnessInFlight = Math.max(0, state.pocHarnessInFlight - 1);
  state.pocHarnessErrors += 1;
  const costUsd = normalizeCostUsd(event.payload.costUsd);
  state.totalCostUsd += costUsd;
  state.pocHarnessCostUsd += costUsd;

  try {
    updateRunCost(deps.db, state.checkpointRunId, costUsd);
  } catch {
    // Cost persistence is best-effort.
  }
}

export function isPocHarnessDone(state: RunState): boolean {
  const processed = state.pocHarnessGenerated + state.pocHarnessSkipped + state.pocHarnessErrors;
  return (
    state.pocHarnessTotal > 0
    && processed >= state.pocHarnessTotal
    && state.pocHarnessInFlight === 0
    && !state.reportEmitted
  );
}

export async function dispatchPocHarness(
  state: RunState,
  runId: string,
  bus: MessageBus,
  isBudgetExceeded: (state: RunState) => boolean,
  emitBudgetCheck: (state: RunState, runId: string) => Promise<void>,
  emitBudgetExceeded: (state: RunState, runId: string) => Promise<void>,
  publishPocHarnessQueueDepth: (state: RunState, runId: string) => Promise<void>,
): Promise<void> {
  if (state.pocHarnessDispatching) return;

  state.pocHarnessDispatching = true;
  try {
    const concurrency = normalizeConcurrency(state.config.pocHarnessConcurrency ?? 1);

    while (
      state.pocHarnessInFlight < concurrency
      && state.pocHarnessCursor < state.pocHarnessQueue.length
    ) {
      await emitBudgetCheck(state, runId);
      if (isBudgetExceeded(state)) {
        await emitBudgetExceeded(state, runId);
        break;
      }
      const item = state.pocHarnessQueue[state.pocHarnessCursor];
      state.pocHarnessCursor += 1;
      state.pocHarnessInFlight += 1;

      await bus.publish(
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

    await publishPocHarnessQueueDepth(state, runId);
  } finally {
    state.pocHarnessDispatching = false;
  }
}

export async function publishPocQueueDepth(
  state: RunState,
  runId: string,
  bus: MessageBus,
): Promise<void> {
  const queued = Math.max(0, state.pocHarnessQueue.length - state.pocHarnessCursor);
  const processed = state.pocHarnessGenerated + state.pocHarnessSkipped + state.pocHarnessErrors;

  await bus.publish(
    createEvent("poc-harness:queue-depth", runId, {
      context: state.context,
      queued,
      inFlight: state.pocHarnessInFlight,
      processed,
      total: state.pocHarnessTotal,
    }),
  );
}

function normalizeConcurrency(raw: number): number {
  if (!Number.isFinite(raw) || raw < 1) return 1;
  return Math.floor(raw);
}
