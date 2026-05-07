import type { VercelRequest, VercelResponse } from "@vercel/node";

/**
 * Reject the request unless `Authorization: Bearer <KUZUSHI_SANDBOX_API_KEY>`
 * matches. When the env var is unset (e.g. local `vercel dev`), allow
 * unauthenticated access — the protocol explicitly permits this for dev.
 *
 * Returns `true` when the request should be allowed to proceed; the
 * handler MUST `return` immediately when this returns `false` (the
 * function has already written a 401 to `res`).
 */
export function requireAuth(req: VercelRequest, res: VercelResponse): boolean {
  const expected = process.env.KUZUSHI_SANDBOX_API_KEY?.trim();
  if (!expected) {
    return true; // dev mode: no auth configured
  }
  const header = req.headers.authorization ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (token !== expected) {
    res.status(401).json({ error: "unauthorized" });
    return false;
  }
  return true;
}
