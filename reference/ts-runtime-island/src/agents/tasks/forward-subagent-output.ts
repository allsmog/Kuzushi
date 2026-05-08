/**
 * Shared helper to forward sub-agent message streams into an `onOutput`
 * callback — the live-tail feed for the `⎿` preview beneath a running
 * `⏺` tool-call header.
 *
 * Every module that spawns a Claude Code subprocess via
 * `ctx.runtime.query(...)` iterates a message stream with the same
 * shape: `assistant` (with tool_use blocks), `tool-progress`,
 * `tool-summary`, `result`. This helper collapses the common case —
 * "show the operator what the sub-agent is doing right now" — into a
 * one-liner caller sites can use without duplicating the heuristic.
 *
 * The emitted previews mirror cc-repo's ShellProgressMessage cadence:
 * one line per tool-use start, truncated to ~60 visible chars so the
 * `⎿` tail doesn't wrap.
 */

type AssistantToolUse = {
  name?: unknown;
  input?: unknown;
};

/**
 * Inspect one sub-agent message and emit a preview line to `onOutput`
 * when it matches the sub-agent-action shape we want to surface.
 * Returns `true` if it emitted, `false` otherwise (caller can use this
 * for telemetry / test assertions).
 */
export function forwardSubAgentMessage(
  message: {
    type: string;
    content?: unknown;
    toolName?: unknown;
    toolUseId?: unknown;
    isError?: unknown;
  },
  onOutput?: (line: string) => void,
): boolean {
  if (!onOutput) return false;

  if (message.type === "assistant" && Array.isArray(message.content)) {
    let emitted = false;
    for (const block of message.content as Array<Record<string, unknown>>) {
      if (block["type"] !== "tool_use") continue;
      const toolUse = block as AssistantToolUse;
      const name = typeof toolUse.name === "string" ? toolUse.name : "tool";
      const hint = summarizeSubAgentInput(toolUse.input);
      const line = hint ? `${name}(${hint})` : name;
      onOutput(line);
      emitted = true;
    }
    return emitted;
  }

  if (message.type === "tool-progress") {
    const name = typeof message.toolName === "string" ? message.toolName : "tool";
    onOutput(`${name}…`);
    return true;
  }

  // Surface tool_result failures in the live-tail too — otherwise a
  // silent retry loop reads as "the same Write over and over", with no
  // hint that each attempt failed. Successes stay quiet (we already
  // emitted the tool_use header; the user sees activity stop ticking
  // when the tool succeeds).
  if (message.type === "tool-result" && message.isError === true) {
    const raw = typeof message.content === "string" ? message.content : "";
    const firstLine =
      raw
        .split(/\r?\n/)
        .find((l) => l.trim().length > 0)
        ?.trim() ?? "tool error";
    onOutput(`tool failed: ${clamp(firstLine)}`);
    return true;
  }

  // Streaming delta events — surface a throttled "building" pulse so
  // operators see forward motion during a 20-second tool-call emission.
  // We coalesce deltas per-toolUseId with byte-count progress and throttle
  // emissions to at most one every DELTA_PULSE_THROTTLE_MS to avoid
  // flooding scrollback on fast providers.
  if (message.type === "tool-call-start") {
    const name = typeof message.toolName === "string" ? message.toolName : "tool";
    onOutput(`${name} · building`);
    return true;
  }

  if (message.type === "tool-call-delta") {
    return recordToolCallDelta(message, onOutput);
  }

  return false;
}

const DELTA_PULSE_THROTTLE_MS = 250;
interface DeltaState {
  bytes: number;
  lastPulseAt: number;
  toolName: string;
}
const deltaStateByToolUseId = new Map<string, DeltaState>();
let deltaResetScheduled = false;

function recordToolCallDelta(
  message: { toolUseId?: unknown; delta?: unknown; toolName?: unknown },
  onOutput: (line: string) => void,
): boolean {
  const toolUseId = typeof message.toolUseId === "string" ? message.toolUseId : "";
  if (!toolUseId) return false;
  const delta = typeof message.delta === "string" ? message.delta : "";
  const state = deltaStateByToolUseId.get(toolUseId) ?? {
    bytes: 0,
    lastPulseAt: 0,
    toolName: typeof message.toolName === "string" ? message.toolName : "tool",
  };
  state.bytes += delta.length;
  const now = Date.now();
  if (now - state.lastPulseAt < DELTA_PULSE_THROTTLE_MS) {
    deltaStateByToolUseId.set(toolUseId, state);
    return false;
  }
  state.lastPulseAt = now;
  deltaStateByToolUseId.set(toolUseId, state);
  // Self-cleaning: schedule a single sweep to drop stale toolUseIds so
  // long-lived runs don't leak Map entries for finished tools.
  if (!deltaResetScheduled) {
    deltaResetScheduled = true;
    setTimeout(() => {
      deltaResetScheduled = false;
      const cutoff = Date.now() - 30_000;
      for (const [id, s] of deltaStateByToolUseId.entries()) {
        if (s.lastPulseAt < cutoff) deltaStateByToolUseId.delete(id);
      }
    }, 30_000).unref?.();
  }
  onOutput(`${state.toolName} · building (${formatBytes(state.bytes)})`);
  return true;
}

/**
 * Reset internal delta-tracking state. Exported for tests; the live-tail
 * renderer relies on a module-scope Map that persists across invocations,
 * so per-test runs need a way to reset between assertions.
 */
export function __resetDeltaState(): void {
  deltaStateByToolUseId.clear();
  deltaResetScheduled = false;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  const kb = bytes / 1024;
  if (kb < 1024) return `${kb.toFixed(kb < 10 ? 1 : 0)} KB`;
  const mb = kb / 1024;
  return `${mb.toFixed(mb < 10 ? 1 : 0)} MB`;
}

/**
 * Squeeze a sub-agent's `tool_use.input` object into a ≤40-char preview
 * hint. Mirrors the shell's `summarizeInput` but simpler — sub-agents
 * call primarily Read / Bash / Grep / Edit which all have a predictable
 * primary field.
 */
function summarizeSubAgentInput(input: unknown): string | undefined {
  if (input == null) return undefined;
  if (typeof input === "string") return clamp(input);
  if (typeof input !== "object") return undefined;
  const record = input as Record<string, unknown>;
  const primary =
    record["file_path"] ??
    record["path"] ??
    record["target"] ??
    record["file"] ??
    record["command"] ??
    record["pattern"] ??
    record["query"] ??
    record["url"];
  if (typeof primary === "string" && primary.length > 0) return clamp(primary);
  return undefined;
}

function clamp(s: string): string {
  const trimmed = s.trim();
  if (trimmed.length <= 40) return trimmed;
  return `${trimmed.slice(0, 39)}…`;
}
