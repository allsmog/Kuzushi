/**
 * Thin shell-facing wrapper around `loadPersistentThreatModel` /
 * `loadThreatModelDocument` (in `src/threat-model-renderer.ts`).
 *
 * Phase C shell views call through here instead of importing directly so
 * the UI layer never has to reach into `src/agents/tasks/threat-modeling/`.
 * Also reports the source path + mtime so the shell can render a
 * "loaded from … (modified Xh ago)" hint on each threat view.
 */

import { statSync } from "node:fs";
import path from "node:path";
import type { ThreatModelDocument } from "../agents/tasks/threat-modeling/types.js";
import { loadPersistentThreatModel, loadThreatModelDocument } from "../threat-model-renderer.js";

export interface ThreatModelLoadResult {
  document: ThreatModelDocument;
  /** Absolute path the document was read from. */
  sourcePath: string;
  /** Unix ms mtime — used by the shell to render a staleness hint. */
  mtimeMs: number;
}

const PERSISTENT_PATH = ".kuzushi/threat-model.json";

function mtimeOf(abs: string): number {
  try {
    return statSync(abs).mtimeMs;
  } catch {
    return 0;
  }
}

/**
 * Load the operator-editable persistent threat model if it exists.
 * Returns null when no model has been produced yet.
 */
export function loadShellThreatModel(repoRoot: string): ThreatModelLoadResult | null {
  const doc = loadPersistentThreatModel(repoRoot);
  if (!doc) return null;
  const sourcePath = path.join(repoRoot, PERSISTENT_PATH);
  return { document: doc, sourcePath, mtimeMs: mtimeOf(sourcePath) };
}

/**
 * Load with a per-run fallback. Prefers the persistent model (operator may
 * have hand-edited it), falls back to `.kuzushi/runs/<runId>/threat-model.json`.
 */
export function loadShellThreatModelForRun(
  repoRoot: string,
  runId: string,
): ThreatModelLoadResult | null {
  const doc = loadThreatModelDocument(repoRoot, runId);
  if (!doc) return null;
  const persistent = path.join(repoRoot, PERSISTENT_PATH);
  const perRun = path.join(repoRoot, ".kuzushi", "runs", runId, "threat-model.json");
  const persistentMtime = mtimeOf(persistent);
  const sourcePath = persistentMtime > 0 ? persistent : perRun;
  return { document: doc, sourcePath, mtimeMs: mtimeOf(sourcePath) };
}

/**
 * Human-readable "loaded from … (modified Xh ago)" hint renderers compose
 * above threat views. Returns a one-line string with no leading/trailing
 * whitespace. Caller wraps in `tokens.muted()` at render time.
 */
export function formatThreatModelSource(
  result: Pick<ThreatModelLoadResult, "sourcePath" | "mtimeMs">,
): string {
  const rel = shortPath(result.sourcePath);
  if (!result.mtimeMs) return `loaded from ${rel}`;
  const deltaMs = Math.max(0, Date.now() - result.mtimeMs);
  return `loaded from ${rel} (modified ${formatAgo(deltaMs)})`;
}

function formatAgo(ms: number): string {
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

function shortPath(abs: string): string {
  const home = process.env["HOME"];
  if (home && abs.startsWith(home)) return `~${abs.slice(home.length)}`;
  return abs;
}
