/**
 * Shorthand helpers for emitting the shell-progress events that populate
 * `ToolRunningStatus`. These are thin wrappers over `bus.publish` so call
 * sites don't have to rebuild the envelope + meta fields each time.
 *
 * All helpers are best-effort: they swallow publish errors so a broken bus
 * listener never takes down the tool that's trying to report progress.
 */

import { createEvent } from "./helpers.js";
import type { MessageBus } from "./types.js";

/**
 * Publish a `task:activity` event — one sub-step description for the rolling
 * activity tail under the tool spinner.
 */
export function publishTaskActivity(
  bus: MessageBus,
  taskId: string,
  description: string,
  opts: { runId?: string; phase?: string; step?: number; total?: number } = {},
): void {
  const runId = opts.runId ?? "shell";
  void bus
    .publish(
      createEvent("task:activity", runId, {
        taskId,
        description,
        phase: opts.phase,
        step: opts.step,
        total: opts.total,
      }),
    )
    .catch(() => {
      /* non-fatal — progress events are best-effort */
    });
}

/**
 * Publish a `task:output` event — a raw subprocess output line for the
 * shell's ephemeral `⎿` live tail. Unlike `publishTaskActivity`, these
 * events never land in scrollback — the shell drops them when the tool
 * resolves. Use for stdout preview, sub-agent tool-use streaming, and
 * other noise that should be live-only.
 */
export function publishTaskOutput(
  bus: MessageBus,
  taskId: string,
  line: string,
  opts: { runId?: string } = {},
): void {
  const runId = opts.runId ?? "shell";
  void bus
    .publish(
      createEvent("task:output", runId, {
        taskId,
        line,
      }),
    )
    .catch(() => {
      /* non-fatal — output previews are best-effort */
    });
}

/**
 * Publish a `task:phase-progress` event — updates the "⏵ phase N/M" strip.
 */
export function publishTaskPhase(
  bus: MessageBus,
  taskId: string,
  phase: string,
  opts: { runId?: string } = {},
): void {
  const runId = opts.runId ?? "shell";
  void bus
    .publish(
      createEvent("task:phase-progress", runId, {
        taskId,
        phase,
      }),
    )
    .catch(() => {
      /* non-fatal */
    });
}
