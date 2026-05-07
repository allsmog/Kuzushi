import type { VercelRequest, VercelResponse } from "@vercel/node";

import { requireAuth } from "../../../lib/auth.js";
import { getRun } from "../../../lib/kv.js";

/**
 * `GET /v1/runs/<id>/status` — lightweight status poll. Same record
 * lookup as `[id].ts` but only returns `{status}` so a polling client
 * doesn't pay the stdout/stderr serialisation cost.
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

  const record = await getRun(clientId, id);
  if (!record) {
    res.status(404).json({ error: "no such run", runId: id });
    return;
  }

  res.status(200).json({ status: record.status });
}
