/**
 * Shorthand helpers for emitting the shell-progress events that populate
 * `ToolRunningStatus`. These are thin wrappers over `bus.publish` so call
 * sites don't have to rebuild the envelope + meta fields each time.
 *
 * All helpers are best-effort: they swallow publish errors so a broken bus
 * listener never takes down the tool that's trying to report progress.
 */

import { randomUUID } from "node:crypto";
import type { AgentActivityKind, AgentActivityMeta } from "../modules/types.js";
import type { KuzushiEvent, TaskAgentActivityPayload } from "./events.js";
import { createEvent } from "./helpers.js";
import type { RunContext } from "./run-context.js";
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
 * Publish a `${moduleId}:agent-activity` event with the unified
 * `TaskAgentActivityPayload` shape. The topic is built dynamically from
 * `moduleId`, which means we can't use the template-literal-typed
 * `createEvent<...>` helper — instead we cast the envelope to
 * `KuzushiEvent` so `bus.publish` accepts it.
 *
 * Used by `ExecutionContext.reportAgentActivity` in `src/copilot/core.ts`
 * so every module that fans out sub-agents gets uniform bus plumbing
 * without bespoke per-topic helpers.
 *
 * The `context` field is populated from the supplied `runContext` when
 * provided (so orchestrator-invoked DagTools get a real RunContext), and
 * falls back to a synthetic shell context when invoked from shell/run mode.
 */
export function publishAgentActivity(
  bus: MessageBus,
  moduleId: string,
  fingerprint: string,
  kind: AgentActivityKind,
  meta?: AgentActivityMeta & { runContext?: RunContext },
): void {
  const runContext: RunContext = meta?.runContext ?? {
    runId: "shell",
    repoName: "shell",
    repoRoot: "",
    dbPath: "",
  };
  const payload: TaskAgentActivityPayload = {
    context: runContext,
    fingerprint,
    kind,
    moduleId,
    index: meta?.index ?? 0,
    total: meta?.total ?? 0,
    ...(meta?.toolName !== undefined ? { toolName: meta.toolName } : {}),
    ...(meta?.toolInput !== undefined ? { toolInput: meta.toolInput } : {}),
    ...(meta?.summary !== undefined ? { summary: meta.summary } : {}),
    ...(meta?.elapsedSeconds !== undefined ? { elapsedSeconds: meta.elapsedSeconds } : {}),
    ...(meta?.done !== undefined ? { done: meta.done } : {}),
  };
  const envelope = {
    type: `${moduleId}:agent-activity` as const,
    meta: {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      runId: runContext.runId,
    },
    payload,
  } as unknown as KuzushiEvent;
  void bus.publish(envelope).catch(() => {
    /* non-fatal — activity events are best-effort */
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
