import type { VercelRequest, VercelResponse } from "@vercel/node";

import { requireAuth } from "../../../lib/auth.js";
import { getRun } from "../../../lib/kv.js";

/**
 * `GET /v1/runs/<id>/output?since=<offset>` — long-poll streaming.
 *
 * Returns chunks accumulated since `offset` (an index into the
 * `chunks` array). `nextOffset` is the offset to pass on the next
 * call. `done` is `true` once the run is finalised.
 *
 * Kuzushi's SandboxExecutor::launch_streaming polls this endpoint at
 * ~500ms intervals, advancing through nextOffset, until `done`. When
 * the endpoint 404s (older adapters that haven't added it) the client
 * falls back to a one-shot collect, so this handler is purely
 * additive.
 */
export default async function handler(
  req: VercelRequest,
  res: VercelResponse,
): Promise<void> {
  if (req.method !== "GET") {
    res.status(405).json({ error: "method_not_allowed" });
    return;
  }
  if (!requireAuth(req, res)) return;

  const id = String(req.query.id ?? "");
  if (!id) {
    res.status(400).json({ error: "missing run id" });
    return;
  }
  const clientId = (req.headers["x-kuzushi-client-id"] as string | undefined) ?? "default";
  const since = Number.parseInt(String(req.query.since ?? "0"), 10) || 0;

  const record = await getRun(clientId, id);
  if (!record) {
    res.status(404).json({ error: "no such run", runId: id });
    return;
  }

  const chunks = record.chunks.slice(since);
  const stdout = chunks
    .filter((chunk) => chunk.stream === "stdout")
    .map((chunk) => chunk.line);
  const stderr = chunks
    .filter((chunk) => chunk.stream === "stderr")
    .map((chunk) => chunk.line);
  res.status(200).json({
    stdout,
    stderr,
    nextOffset: record.chunks.length,
    done: record.done,
  });
}
