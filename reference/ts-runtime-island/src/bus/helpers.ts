import { randomUUID } from "node:crypto";
import type { KuzushiEvent, TaskAgentActivityPayload } from "./events.js";
import type { EventEnvelope } from "./types.js";

export function generateRunId(): string {
  return randomUUID();
}

/**
 * Per-actor activity topic overload. The template-literal
 * `${string}:agent-activity` in the `TaskAgentActivityEvent` union member
 * doesn't narrow via `Extract` for concrete strings, so we special-case the
 * convention: any topic ending in `:agent-activity` carries a
 * `TaskAgentActivityPayload`.
 */
export function createEvent<T extends `${string}:agent-activity`>(
  type: T,
  runId: string,
  payload: TaskAgentActivityPayload,
): EventEnvelope<T, TaskAgentActivityPayload>;
export function createEvent<T extends KuzushiEvent["type"]>(
  type: T,
  runId: string,
  payload: Extract<KuzushiEvent, { type: T }>["payload"],
): Extract<KuzushiEvent, { type: T }>;
export function createEvent(type: string, runId: string, payload: unknown): unknown {
  return {
    type,
    meta: {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      runId,
    },
    payload,
  };
}
