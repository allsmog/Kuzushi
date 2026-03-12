import { isRecord } from "../utils.js";

/**
 * Structured task handoff protocol — enables tasks to communicate
 * qualitative insights, attention points, and confidence between tasks.
 */
export interface TaskHandoff<T = unknown> {
  /** Marker to identify this as a handoff envelope. */
  readonly __handoff: true;
  /** ID of the task that produced this handoff. */
  taskId: string;
  /** The actual task output. */
  output: T;
  /** Qualitative insights discovered during execution. */
  insights: string[];
  /** Items that downstream tasks should pay attention to. */
  attentionPoints: string[];
  /** Optional suggested actions for downstream tasks. */
  suggestedActions?: string[];
  /** Overall confidence in the output (0-1). */
  confidence: number;
}

export interface CreateHandoffOpts {
  insights?: string[];
  attentionPoints?: string[];
  suggestedActions?: string[];
  confidence?: number;
}

/**
 * Create a TaskHandoff envelope wrapping a task's output with metadata.
 */
export function createHandoff<T>(
  taskId: string,
  output: T,
  opts?: CreateHandoffOpts,
): TaskHandoff<T> {
  return {
    __handoff: true,
    taskId,
    output,
    insights: opts?.insights ?? [],
    attentionPoints: opts?.attentionPoints ?? [],
    suggestedActions: opts?.suggestedActions,
    confidence: Math.max(0, Math.min(1, opts?.confidence ?? 1)),
  };
}

/**
 * Check if a value is a TaskHandoff envelope.
 */
export function isHandoff(value: unknown): value is TaskHandoff {
  return isRecord(value) && value["__handoff"] === true;
}

/**
 * Get the raw output from an upstream task, transparently unwrapping
 * TaskHandoff if present. Returns undefined if not found.
 * Full backward compatibility — works with both raw outputs and handoffs.
 */
export function getUpstreamOutput<T>(
  upstream: Map<string, unknown>,
  taskId: string,
): T | undefined {
  const raw = upstream.get(taskId);
  if (raw === undefined) {
    return undefined;
  }

  if (isHandoff(raw)) {
    return raw.output as T;
  }

  return raw as T;
}

/**
 * Get the full TaskHandoff from an upstream task, or undefined if the
 * upstream output is not wrapped in a handoff.
 */
export function getUpstreamHandoff<T>(
  upstream: Map<string, unknown>,
  taskId: string,
): TaskHandoff<T> | undefined {
  const raw = upstream.get(taskId);
  if (isHandoff(raw)) {
    return raw as TaskHandoff<T>;
  }
  return undefined;
}

/**
 * Collect and format insights from upstream handoffs for prompt injection.
 * Only collects from tasks that used the handoff protocol.
 */
export function formatUpstreamInsights(
  upstream: Map<string, unknown>,
  depIds: string[],
): string[] {
  const lines: string[] = [];

  for (const depId of depIds) {
    const raw = upstream.get(depId);
    if (!isHandoff(raw)) {
      continue;
    }

    if (raw.insights.length > 0) {
      lines.push(`### Insights from ${depId}`);
      for (const insight of raw.insights) {
        lines.push(`- ${insight}`);
      }
    }

    if (raw.attentionPoints.length > 0) {
      lines.push(`### Attention points from ${depId}`);
      for (const point of raw.attentionPoints) {
        lines.push(`- ${point}`);
      }
    }
  }

  return lines;
}
