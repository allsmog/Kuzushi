import { randomUUID } from "node:crypto";
import type { KuzushiEvent } from "./events.js";

export function generateRunId(): string {
  return randomUUID();
}

export function createEvent<T extends KuzushiEvent["type"]>(
  type: T,
  runId: string,
  payload: Extract<KuzushiEvent, { type: T }>["payload"],
): Extract<KuzushiEvent, { type: T }> {
  return {
    type,
    meta: {
      id: randomUUID(),
      timestamp: new Date().toISOString(),
      runId,
    },
    payload,
  } as Extract<KuzushiEvent, { type: T }>;
}
