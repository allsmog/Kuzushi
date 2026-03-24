/**
 * Triage dispatch logic extracted from PipelineOrchestrator.
 *
 * Manages the triage queue: dispatching findings for triage,
 * handling results/errors, and tracking dead-letter findings.
 */

import type { Finding } from "../../scanners/types.js";
import type { TriageResult } from "../../types.js";
import { normalizeCostUsd } from "../../utils.js";
import { updateRunCost } from "../../store.js";
import { createEvent } from "../helpers.js";
import type { MessageBus } from "../types.js";
import type { RunState, OrchestratorDeps } from "./types.js";

export function handleTriageResult(
  state: RunState,
  runId: string,
  finding: Finding,
  result: TriageResult,
  costUsd: number | undefined,
  shouldVerifyFinding: (state: RunState, finding: Finding, triageResult: TriageResult) => boolean,
  deps: OrchestratorDeps,
): void {
  state.inFlight = Math.max(0, state.inFlight - 1);
  state.triaged += 1;
  const cost = normalizeCostUsd(costUsd);
  state.totalCostUsd += cost;

  if (shouldVerifyFinding(state, finding, result)) {
    state.verifyCandidates.push({ finding, triageResult: result });
  }

  try {
    updateRunCost(deps.db, state.checkpointRunId, cost);
  } catch {
    // Cost persistence is best-effort.
  }
}

export function handleTriageError(
  state: RunState,
  error: string,
  finding: Finding,
  costUsd: number | undefined,
  attempts: number | undefined,
  index: number | undefined,
  total: number | undefined,
  deps: OrchestratorDeps,
): void {
  state.inFlight = Math.max(0, state.inFlight - 1);
  state.triageErrors += 1;
  const cost = normalizeCostUsd(costUsd);
  state.totalCostUsd += cost;

  const fp = finding.fingerprint;
  const maxRetries = state.config.maxTriageRetries ?? 2;
  const priorAttempts = state.triageAttempts.get(fp) ?? 0;
  const totalAttempts = Math.max(priorAttempts, attempts ?? 1);
  state.triageAttempts.set(fp, totalAttempts);

  if (totalAttempts >= maxRetries) {
    state.deadLetterFindings.push({
      fingerprint: fp,
      error,
      attempts: totalAttempts,
      lastAttempt: new Date().toISOString(),
    });
  } else {
    state.triageErrors -= 1;
    state.triageQueue.push({
      finding,
      index: index ?? 0,
      total: total ?? state.triageTotal,
    });
  }

  try {
    updateRunCost(deps.db, state.checkpointRunId, cost);
  } catch {
    // Cost persistence is best-effort.
  }
}

export function isTriageDone(state: RunState): boolean {
  const processed = state.triaged + state.triageErrors;
  return (
    state.triageTotal > 0
    && processed >= state.triageTotal
    && state.inFlight === 0
    && !state.reportRequested
  );
}

export async function dispatchTriage(
  state: RunState,
  runId: string,
  bus: MessageBus,
  isBudgetExceeded: (state: RunState) => boolean,
  emitBudgetCheck: (state: RunState, runId: string) => Promise<void>,
  emitBudgetExceeded: (state: RunState, runId: string) => Promise<void>,
  publishQueueDepth: (state: RunState, runId: string) => Promise<void>,
): Promise<void> {
  if (state.dispatching) return;

  state.dispatching = true;
  try {
    const concurrency = normalizeConcurrency(state.config.triageConcurrency);

    while (state.inFlight < concurrency && state.queueCursor < state.triageQueue.length) {
      await emitBudgetCheck(state, runId);
      if (isBudgetExceeded(state)) {
        await emitBudgetExceeded(state, runId);
        break;
      }
      const item = state.triageQueue[state.queueCursor];
      state.queueCursor += 1;
      state.inFlight += 1;

      await bus.publish(
        createEvent("triage:finding-queued", runId, {
          context: state.context,
          finding: item.finding,
          repoContext: state.repoContext,
          enrichedContext: state.enrichedRepoContext,
          precedents: state.precedents,
          index: item.index,
          total: item.total,
        }),
      );
    }

    await publishQueueDepth(state, runId);
  } finally {
    state.dispatching = false;
  }
}

export async function publishTriageQueueDepth(
  state: RunState,
  runId: string,
  bus: MessageBus,
): Promise<void> {
  const queued = Math.max(0, state.triageQueue.length - state.queueCursor);
  const processed = state.triaged + state.triageErrors;

  await bus.publish(
    createEvent("triage:queue-depth", runId, {
      context: state.context,
      queued,
      inFlight: state.inFlight,
      processed,
      total: state.triageTotal,
    }),
  );
}

function normalizeConcurrency(raw: number): number {
  if (!Number.isFinite(raw) || raw < 1) return 1;
  return Math.floor(raw);
}
