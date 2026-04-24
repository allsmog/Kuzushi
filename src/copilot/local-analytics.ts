import { appendFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import type { CommandSurfaceKind } from "./shell-commands.js";

export interface LocalUsageEvent {
  type:
    | "command"
    | "view-entered"
    | "empty-state"
    | "error-state"
    | "config-section"
    | "action-outcome";
  timestamp: string;
  surface?: CommandSurfaceKind;
  command?: string;
  view?: string;
  outcome?: "started" | "succeeded" | "failed" | "cancelled";
  category?: string;
}

const DISABLE_ENV = "KUZUSHI_DISABLE_LOCAL_ANALYTICS";
const USAGE_FILE = "usage.jsonl";

export function recordLocalUsageEvent(dataDir: string | undefined, event: LocalUsageEvent): void {
  if (!dataDir || process.env[DISABLE_ENV] === "1" || process.env[DISABLE_ENV] === "true") {
    return;
  }
  try {
    mkdirSync(dataDir, { recursive: true });
    appendFileSync(path.join(dataDir, USAGE_FILE), `${JSON.stringify(event)}\n`, "utf8");
  } catch {
    // Analytics must never interfere with a shell command.
  }
}

export function redactedCommandUsageEvent(params: {
  command: string;
  surface: CommandSurfaceKind;
  view?: string;
  outcome?: LocalUsageEvent["outcome"];
}): LocalUsageEvent {
  return {
    type: "command",
    timestamp: new Date().toISOString(),
    command: normalizeCommandName(params.command),
    surface: params.surface,
    ...(params.view ? { view: params.view } : {}),
    outcome: params.outcome ?? "started",
  };
}

function normalizeCommandName(command: string): string {
  const trimmed = command.trim();
  if (!trimmed) return "(empty)";
  const head = trimmed.replace(/^\//, "").split(/\s+/)[0] ?? trimmed;
  return head.toLowerCase();
}
