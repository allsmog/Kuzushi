import type { VercelRequest, VercelResponse } from "@vercel/node";

import { requireAuth } from "../../lib/auth.js";
import { getRun } from "../../lib/kv.js";

/**
 * `GET /v1/runs/<id>` — final result fetch.
 *
 * The kuzushi client picks the clientId out of the auth header (the
 * Bearer token is mapped 1:1 to a clientId in production; in this dev
 * adapter we accept a single global key + scan the full namespace).
 * For a real multi-tenant deployment, swap the `clientId` resolution
 * for a `req.headers["x-kuzushi-client-id"]` header check.
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

  res.status(200).json({
    status: record.status,
    stdout: record.stdout,
    stderr: record.stderr,
    exitCode: record.exitCode,
  });
}
