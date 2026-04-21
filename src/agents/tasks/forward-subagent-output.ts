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

  return false;
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
