/**
 * Per-run abort wiring: chains a parent signal (operator Ctrl+C) and a
 * fatal `pipeline:error` event into a single `AbortController` that's
 * registered on the run-signals bus for downstream workers.
 *
 * Why fail-fast on `pipeline:error fatal: true`: the orchestrator's
 * fatal handler in `orchestrator.ts` deletes the run state from
 * `this.runs[runId]` but does not signal in-flight workers. Without this
 * abort hook, triage / verify dispatchers keep pulling findings off
 * their queues and burning LLM cost for ~20+ minutes after the run is
 * already dead. The dispatchers read `getRunSignal(runId)?.aborted` at
 * the top of their dispatch loops — once we abort here, they short-
 * circuit on the next iteration.
 */
import type { PipelineErrorEvent } from "./events.js";
import { registerRunSignal } from "./run-signals.js";
import type { MessageBus } from "./types.js";

export interface RunAbortHandle {
  /** The signal published on the run-signals registry. */
  readonly signal: AbortSignal;
  /** Manually abort (used by tests; production code lets the bus drive it). */
  abort(): void;
}

export function wireRunAbort(
  bus: MessageBus,
  runId: string,
  parentSignal: AbortSignal | undefined,
): RunAbortHandle {
  const controller = new AbortController();

  if (parentSignal) {
    if (parentSignal.aborted) {
      controller.abort();
    } else {
      parentSignal.addEventListener("abort", () => controller.abort(), { once: true });
    }
  }

  bus.subscribe<PipelineErrorEvent>("pipeline:error", (event) => {
    if (event.meta.runId === runId && event.payload.fatal && !controller.signal.aborted) {
      controller.abort();
    }
  });

  registerRunSignal(runId, controller.signal);

  return {
    signal: controller.signal,
    abort: () => {
      if (!controller.signal.aborted) controller.abort();
    },
  };
}
