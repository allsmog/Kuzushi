import { kv } from "@vercel/kv";

export type RunRecord = {
  status: "pending" | "running" | "succeeded" | "failed" | "cancelled";
  stdout: string;
  stderr: string;
  exitCode: number | null;
  /**
   * Streaming chunks. Each entry is a single line (no trailing newline)
   * tagged as stdout or stderr. The `output` long-poll endpoint slices
   * `chunks[since..]` and returns it.
   */
  chunks: { stream: "stdout" | "stderr"; line: string }[];
  done: boolean;
};

const TTL_SECONDS = 60 * 60 * 24; // 24h

function key(clientId: string, runId: string): string {
  return `kuzushi:run:${clientId}:${runId}`;
}

export async function getRun(
  clientId: string,
  runId: string,
): Promise<RunRecord | null> {
  return ((await kv.get<RunRecord>(key(clientId, runId))) ?? null);
}

export async function putRun(
  clientId: string,
  runId: string,
  record: RunRecord,
): Promise<void> {
  await kv.set(key(clientId, runId), record, { ex: TTL_SECONDS });
}

/**
 * Idempotency probe: returns `true` when a record already exists under
 * the (clientId, runId) pair. Callers use this to short-circuit
 * re-launching a run that's already accepted.
 */
export async function exists(clientId: string, runId: string): Promise<boolean> {
  return (await kv.exists(key(clientId, runId))) > 0;
}
