/**
 * Persist + load the `ContextSnapshot` produced by `context:build` to a
 * stable on-disk location, so a fresh shell session in the same target
 * repo can auto-load prior context without requiring `--workspace`.
 *
 * Without this, `context:build` output lives in memory only; the next
 * shell session starts with `shell.contextSnapshot` empty, and
 * downstream modules (`threat-hunt`, `agentic-sast`, `taint-iris`) fail
 * the appModel/threatModel prerequisite check even though the operator
 * ran context minutes earlier.
 *
 * File shape: `<target>/.kuzushi/context-snapshot.json`. Chosen over
 * `.kuzushi/runs/<runId>/` because (a) it's predictable — a reader
 * doesn't need to pick between stale runs, (b) the run-dirs hold stage
 * artifacts (pasta-s*.json), not the aggregated snapshot shape that
 * threat-hunt/taint-iris actually consume.
 *
 * Stale handling: operators expect freshness. If the on-disk snapshot
 * is older than STALENESS_WARN_MS, `loadContextSnapshot` still returns
 * it (so modules can run) but the caller can inspect `.timestamp` to
 * render a "stale — re-run `context build`" hint.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { ContextSnapshot } from "../../ui/state.js";

const SNAPSHOT_FILENAME = "context-snapshot.json";
const SNAPSHOT_DIR = ".kuzushi";

export function contextSnapshotPath(target: string): string {
  return path.join(path.resolve(target), SNAPSHOT_DIR, SNAPSHOT_FILENAME);
}

/**
 * Write the snapshot to `<target>/.kuzushi/context-snapshot.json`.
 * Best-effort: returns false on any filesystem error, so callers don't
 * treat a write failure as a context-build failure.
 */
export function saveContextSnapshot(target: string, snapshot: ContextSnapshot): boolean {
  try {
    const snapshotPath = contextSnapshotPath(target);
    const dir = path.dirname(snapshotPath);
    if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
    writeFileSync(snapshotPath, `${JSON.stringify(snapshot, null, 2)}\n`, "utf8");
    return true;
  } catch {
    return false;
  }
}

/**
 * Read the snapshot. Returns null when the file is missing, unreadable,
 * or fails to parse — callers get a clean "no cached snapshot" signal
 * and can fall back to their usual "unmet prerequisites" flow.
 */
export function loadContextSnapshot(target: string): ContextSnapshot | null {
  try {
    const snapshotPath = contextSnapshotPath(target);
    if (!existsSync(snapshotPath)) return null;
    const raw = readFileSync(snapshotPath, "utf8");
    const parsed = JSON.parse(raw) as unknown;
    if (!isContextSnapshot(parsed)) return null;
    return parsed;
  } catch {
    return null;
  }
}

function isContextSnapshot(value: unknown): value is ContextSnapshot {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return (
    typeof record["target"] === "string" &&
    typeof record["timestamp"] === "number" &&
    typeof record["discovery"] === "string"
  );
}
