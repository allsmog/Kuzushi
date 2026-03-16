/**
 * ACP session persistence.
 *
 * Stores session state for multi-turn agent conversations,
 * allowing triage agents to maintain context across findings
 * without re-sending the full system prompt each time.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, unlinkSync } from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

export interface SessionRecord {
  id: string;
  runId: string;
  taskId: string;
  createdAt: string;
  updatedAt: string;
  /** Number of turns completed in this session. */
  turnCount: number;
  /** Compact session state (not full message history). */
  checkpoint?: string;
  /** Total cost accumulated in this session. */
  totalCostUsd: number;
}

const SESSIONS_DIR = ".kuzushi/sessions";
const MAX_SESSION_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

/**
 * Get the sessions directory for a repository root.
 */
function getSessionsDir(repoRoot: string): string {
  return path.join(repoRoot, SESSIONS_DIR);
}

/**
 * Create a new session record.
 */
export function createSession(repoRoot: string, runId: string, taskId: string): SessionRecord {
  const session: SessionRecord = {
    id: randomUUID(),
    runId,
    taskId,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    turnCount: 0,
    totalCostUsd: 0,
  };

  saveSession(repoRoot, session);
  return session;
}

/**
 * Save a session record to disk.
 */
export function saveSession(repoRoot: string, session: SessionRecord): void {
  const dir = getSessionsDir(repoRoot);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const filePath = path.join(dir, `${session.id}.json`);
  writeFileSync(filePath, JSON.stringify(session, null, 2), "utf-8");
}

/**
 * Load a session record by ID.
 */
export function loadSession(repoRoot: string, sessionId: string): SessionRecord | undefined {
  const filePath = path.join(getSessionsDir(repoRoot), `${sessionId}.json`);
  if (!existsSync(filePath)) {
    return undefined;
  }

  try {
    return JSON.parse(readFileSync(filePath, "utf-8")) as SessionRecord;
  } catch {
    return undefined;
  }
}

/**
 * Find active sessions for a run.
 */
export function findSessionsForRun(repoRoot: string, runId: string): SessionRecord[] {
  const dir = getSessionsDir(repoRoot);
  if (!existsSync(dir)) return [];

  const sessions: SessionRecord[] = [];
  for (const file of readdirSync(dir)) {
    if (!file.endsWith(".json")) continue;
    try {
      const session = JSON.parse(readFileSync(path.join(dir, file), "utf-8")) as SessionRecord;
      if (session.runId === runId) {
        sessions.push(session);
      }
    } catch {
      // Skip malformed session files
    }
  }

  return sessions;
}

/**
 * Update session with new turn data.
 */
export function updateSession(
  repoRoot: string,
  session: SessionRecord,
  update: { turnCount?: number; checkpoint?: string; costUsd?: number },
): SessionRecord {
  const updated: SessionRecord = {
    ...session,
    updatedAt: new Date().toISOString(),
    turnCount: update.turnCount ?? session.turnCount,
    checkpoint: update.checkpoint ?? session.checkpoint,
    totalCostUsd: session.totalCostUsd + (update.costUsd ?? 0),
  };

  saveSession(repoRoot, updated);
  return updated;
}

/**
 * Clean up expired sessions older than 24 hours.
 */
export function cleanupExpiredSessions(repoRoot: string): number {
  const dir = getSessionsDir(repoRoot);
  if (!existsSync(dir)) return 0;

  let cleaned = 0;
  const now = Date.now();

  for (const file of readdirSync(dir)) {
    if (!file.endsWith(".json")) continue;
    const filePath = path.join(dir, file);
    try {
      const session = JSON.parse(readFileSync(filePath, "utf-8")) as SessionRecord;
      const age = now - new Date(session.updatedAt).getTime();
      if (age > MAX_SESSION_AGE_MS) {
        unlinkSync(filePath);
        cleaned++;
      }
    } catch {
      // Remove malformed files
      try { unlinkSync(filePath); cleaned++; } catch { /* ignore */ }
    }
  }

  return cleaned;
}
