import type { VercelRequest, VercelResponse } from "@vercel/node";

import { requireAuth } from "../lib/auth.js";
import { exists, putRun } from "../lib/kv.js";
import { launchSandbox } from "../lib/sandbox.js";

/**
 * `POST /v1/runs` — accepts a launch request and seeds the KV record.
 *
 * Request body shape (must match what Kuzushi's SandboxExecutor sends):
 *
 * ```json
 * {
 *   "clientId": "kuzushi-91234",
 *   "runId": "semgrep-9f8e2c3a-...",
 *   "command": ["semgrep", "--json", "--config", "p/security-audit", "."],
 *   "workingDir": "/home/operator/repo",
 *   "env": {"KEY": "VAL"},
 *   "stdin": null
 * }
 * ```
 *
 * Response: `{ "runId": "<echoed>" }`. The `(clientId, runId)` pair is
 * the idempotency key — re-running the same body returns the same id
 * without re-launching.
 */
export default async function handler(
  req: VercelRequest,
  res: VercelResponse,
): Promise<void> {
  if (req.method !== "POST") {
    res.status(405).json({ error: "method_not_allowed" });
    return;
  }
  if (!requireAuth(req, res)) return;

  const body = req.body as {
    clientId?: string;
    runId?: string;
    command?: string[];
    workingDir?: string;
    env?: Record<string, string>;
    stdin?: string | null;
  };
  const clientId = (body.clientId ?? "").trim();
  const runId = (body.runId ?? "").trim();
  if (!clientId || !runId) {
    res.status(400).json({ error: "clientId and runId are required" });
    return;
  }
  if (!Array.isArray(body.command) || body.command.length === 0) {
    res.status(400).json({ error: "command must be a non-empty array" });
    return;
  }

  // Idempotent: if (clientId, runId) already exists, return its id.
  if (await exists(clientId, runId)) {
    res.status(200).json({ runId });
    return;
  }

  // Seed a pending record before launching so a follow-up GET sees something.
  await putRun(clientId, runId, {
    status: "pending",
    stdout: "",
    stderr: "",
    exitCode: null,
    chunks: [],
    done: false,
  });

  await launchSandbox({
    clientId,
    runId,
    command: body.command,
    workingDir: body.workingDir ?? "/workspace",
    env: body.env ?? {},
    stdin: body.stdin ?? null,
  });

  res.status(202).json({ runId });
}
